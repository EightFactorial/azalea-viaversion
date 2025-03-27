#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use std::{io::Cursor, net::SocketAddr, path::Path, process::Stdio};

use azalea::{
    app::{App, AppExit, Plugin, PreUpdate, Startup},
    auth::sessionserver::{
        ClientSessionServerError::{ForbiddenOperation, InvalidSession},
        join_with_server_id_hash,
    },
    buf::AzaleaRead,
    ecs::prelude::*,
    packet::login::{
        IgnoreQueryIds, LoginPacketEvent, LoginSendPacketQueue, process_packet_events,
    },
    prelude::*,
    protocol::{
        ServerAddress,
        packets::login::{
            ClientboundLoginPacket, ServerboundCustomQueryAnswer, ServerboundLoginPacket,
        },
    },
    swarm::Swarm,
};
use parking_lot::Mutex;
use reqwest::Client;
use semver::Version;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::oneshot::{Receiver, error::TryRecvError},
};
use tracing::{error, info, trace};

mod java;
use java::JavaHelper;

mod proxy;
use proxy::ViaVersionHelper;

const JAVA_DOWNLOAD_URL: &str = "https://adoptium.net/installation";
const VIA_OAUTH_VERSION: Version = Version::new(1, 0, 0);
const VIA_PROXY_VERSION: Version = Version::new(3, 3, 7);

/// A [`Plugin`] that starts a `ViaProxy` instance.
pub struct ViaVersionPlugin {
    /// The receiver for the `ViaProxy` process.
    receiver: Mutex<Receiver<anyhow::Result<()>>>,
    /// The result of starting `ViaProxy`.
    task_result: Mutex<Option<anyhow::Result<()>>>,
    /// The plugin settings.
    settings: ViaVersionSettings,
}

/// The settings of the [`ViaVersionPlugin`].
#[derive(Debug, Clone, PartialEq, Eq, Resource)]
pub struct ViaVersionSettings {
    /// The Minecraft version `ViaProxy` appears to be.
    pub version: String,
    /// The address `ViaProxy` has bind to.
    pub socket: SocketAddr,
}

impl Plugin for ViaVersionPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(self.settings.clone())
            .add_systems(Startup, Self::handle_change_address)
            .add_systems(PreUpdate, Self::handle_oauth.before(process_packet_events));
    }

    fn ready(&self, _: &App) -> bool {
        self.poll_task();
        self.is_finished()
    }

    fn finish(&self, app: &mut App) {
        if self.task_result.lock().as_ref().is_none_or(Result::is_err) {
            error!("ViaProxy failed to start, exiting ...");
            app.world_mut().send_event(AppExit::error());
        } else {
            info!("ViaProxy started successfully!");
        }
    }
}

impl ViaVersionPlugin {
    /// Get the result of starting `ViaProxy`.
    ///
    /// The option is `None` if the task is still running.
    #[must_use]
    pub const fn result(&self) -> &Mutex<Option<anyhow::Result<()>>> { &self.task_result }

    /// Returns `true` if the task has finished starting.
    #[must_use]
    pub fn is_finished(&self) -> bool { self.task_result.lock().is_some() }

    /// Poll the `ViaProxy` task receiver.
    ///
    /// Returns `true` if the task has finished.
    fn poll_task(&self) {
        // Already finished, skip polling the receiver
        #[rustfmt::skip]
        if self.is_finished() { return };

        // Poll the receiver for the result
        match self.receiver.lock().try_recv() {
            // Received `Ok` or already received
            Ok(Ok(())) | Err(TryRecvError::Closed) => {
                self.task_result.lock().replace(Ok(()));
            }
            // Received an `Err`
            Ok(Err(err)) => {
                error!("Failed to start ViaProxy: {err}");
                self.task_result.lock().replace(Err(err));
            }
            // Waiting for result
            Err(TryRecvError::Empty) => {}
        }
    }
}

impl ViaVersionPlugin {
    /// Download and start a ViaProxy instance.
    ///
    /// # Errors
    /// Returns an error if java fails to parse.
    ///
    /// # Panics
    /// Panics if files fail to download or ViaProxy fails to start.
    pub async fn start(mc_version: impl ToString) -> anyhow::Result<Self> {
        match minecraft_folder_path::minecraft_dir() {
            Some(mc_path) => Self::start_using(mc_version, &mc_path).await,
            None => anyhow::bail!("Failed to find Minecraft directory, unsupported platform!"),
        }
    }

    /// Download and start a ViaProxy instance.
    ///
    /// Uses the provided directory for storing ViaProxy files.
    ///
    /// # Errors
    /// Returns an error if java fails to parse.
    ///
    /// # Panics
    /// Panics if files fail to download or ViaProxy fails to start.
    pub async fn start_using(mc_version: impl ToString, mc_path: &Path) -> anyhow::Result<Self> {
        let java_version = match JavaHelper::java_version().await {
            Ok(version) => version,
            Err(err) => {
                error!("Failed to get Java version: {err}");
                anyhow::bail!(
                    "Java installation not found! Please download Java from {JAVA_DOWNLOAD_URL} or use your system's package manager"
                );
            }
        };

        let mc_version = mc_version.to_string();

        #[rustfmt::skip]
        let via_proxy_ext = if java_version.major < 17 { "+java8.jar" } else { ".jar" };
        let via_proxy_name = format!("ViaProxy-{VIA_PROXY_VERSION}{via_proxy_ext}");
        let via_proxy_path = mc_path.join("azalea-viaversion");
        let via_proxy_url = format!(
            "https://github.com/ViaVersion/ViaProxy/releases/download/v{VIA_PROXY_VERSION}/{via_proxy_name}"
        );
        ViaVersionHelper::try_download_file(via_proxy_url, &via_proxy_path, &via_proxy_name)
            .await
            .expect("Failed to download ViaProxy");

        let via_oauth_name = format!("ViaProxyOpenAuthMod-{VIA_OAUTH_VERSION}.jar");
        let via_oauth_path = via_proxy_path.join("plugins");
        let via_oauth_url = format!(
            "https://github.com/ViaVersionAddons/ViaProxyOpenAuthMod/releases/download/v{VIA_OAUTH_VERSION}/{via_oauth_name}"
        );
        ViaVersionHelper::try_download_file(via_oauth_url, &via_oauth_path, &via_oauth_name)
            .await
            .expect("Failed to download ViaProxyOpenAuthMod");

        let bind_addr = ViaVersionHelper::try_find_free_addr().await.expect("Failed to bind");

        let (tx, rx) = tokio::sync::oneshot::channel();
        let task_version = mc_version.clone();
        tokio::spawn(async move {
            let result = Self::start_viaproxy(
                &via_proxy_name,
                &via_proxy_path,
                &bind_addr.to_string(),
                &task_version,
            )
            .await;
            match tx.send(result) {
                Ok(()) => {}
                Err(Ok(())) => error!("Failed to transmit `Ok`"),
                Err(Err(err)) => error!("Failed to transmit `Err`: \"{err}\""),
            }
        });

        Ok(Self {
            receiver: Mutex::new(rx),
            task_result: Mutex::new(None),
            settings: ViaVersionSettings { version: mc_version, socket: bind_addr },
        })
    }

    /// Start a `ViaProxy` instance.
    async fn start_viaproxy(
        proxy_name: &str,
        proxy_path: &Path,
        bind_addr: &str,
        mc_version: &str,
    ) -> anyhow::Result<()> {
        let mut child = Command::new("java")
            // Java Args
            .arg("-jar")
            .arg(proxy_path.join(proxy_name))
            // ViaProxy Args
            .arg("cli")
            .args(["--auth-method", "OPENAUTHMOD"])
            .args(["--bind-address", bind_addr])
            .args(["--target-address", "127.0.0.1:0"])
            .args(["--target-version", mc_version])
            .args(["--wildcard-domain-handling", "INTERNAL"])
            .current_dir(proxy_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdout = child.stdout.as_mut().expect("Failed to get stdout");
        let mut reader = BufReader::new(&mut stdout);
        let mut line = String::new();

        loop {
            line.clear();
            reader.read_line(&mut line).await?;

            if !line.is_empty() {
                trace!("{}", line.trim());

                if line.contains("Disabled plugin 'OpenAuthModPlugin'") {
                    return Err(anyhow::anyhow!("OpenAuthModPlugin is disabled"));
                } else if line.contains("Finished mapping loading") {
                    return Ok(());
                }
            }
        }
    }

    /// TODO: Documentation
    pub fn handle_change_address(plugin: Res<ViaVersionSettings>, swarm: Res<Swarm>) {
        let ServerAddress { host, port } = swarm.address.read().clone();

        // sadly, the first part of the resolved address is unused as viaproxy will
        // resolve it on its own more info: https://github.com/ViaVersion/ViaProxy/issues/338
        let data_after_null_byte = host.split_once('\x07').map(|(_, data)| data);

        let mut connection_host = format!("localhost\x07{host}\x07{}", plugin.version);
        if let Some(data) = data_after_null_byte {
            connection_host.push('\0');
            connection_host.push_str(data);
        }

        *swarm.address.write() = ServerAddress { port, host: connection_host };

        // Must wait to be written until after reading above
        *swarm.resolved_address.write() = plugin.socket;
    }

    /// TODO: Documentation
    pub fn handle_oauth(
        mut events: EventReader<LoginPacketEvent>,
        mut query: Query<(&mut IgnoreQueryIds, &Account, &LoginSendPacketQueue)>,
    ) {
        for event in events.read().cloned() {
            let ClientboundLoginPacket::CustomQuery(packet) = &*event.packet else {
                continue;
            };

            if packet.identifier.to_string().as_str() != "oam:join" {
                continue;
            }

            let mut buf = Cursor::new(&*packet.data);
            let Ok(hash) = String::azalea_read(&mut buf) else {
                error!("Failed to read server id hash from oam:join packet");
                continue;
            };

            let Ok((mut ignored_ids, account, queue)) = query.get_mut(event.entity) else {
                continue;
            };

            ignored_ids.insert(packet.transaction_id);

            let Some(access_token) = &account.access_token else {
                error!("Server is online-mode, but our account is offline-mode");
                continue;
            };

            let client = Client::new();
            let token = access_token.lock().clone();
            let uuid = account.uuid_or_offline();
            let account = account.clone();
            let transaction_id = packet.transaction_id;
            let tx = queue.tx.clone();

            let _handle = tokio::spawn(async move {
                let result = match join_with_server_id_hash(&client, &token, &uuid, &hash).await {
                    Ok(()) => Ok(()), // Successfully Authenticated
                    Err(InvalidSession | ForbiddenOperation) => {
                        if let Err(error) = account.refresh().await {
                            error!("Failed to refresh account: {error}");
                            return;
                        }

                        // Retry after refreshing
                        join_with_server_id_hash(&client, &token, &uuid, &hash).await
                    }
                    Err(error) => Err(error),
                };

                // Send directly instead of SendLoginPacketEvent because of lifetimes
                let _ = tx.send(ServerboundLoginPacket::CustomQueryAnswer(
                    ServerboundCustomQueryAnswer {
                        transaction_id,
                        data: Some(vec![u8::from(result.is_ok())].into()),
                    },
                ));
            });
        }
    }
}
