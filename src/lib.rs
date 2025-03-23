#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use anyhow::Result;
use azalea::app::AppExit;
use azalea::packet::login::{
    IgnoreQueryIds, LoginPacketEvent, LoginSendPacketQueue, process_packet_events,
};
use azalea::{
    app::{App, Plugin, PreUpdate, Startup},
    auth::sessionserver::{
        ClientSessionServerError::{ForbiddenOperation, InvalidSession},
        join_with_server_id_hash,
    },
    buf::AzaleaRead,
    ecs::prelude::*,
    prelude::*,
    protocol::{
        ServerAddress,
        packets::login::{
            ClientboundLoginPacket, ServerboundCustomQueryAnswer, ServerboundLoginPacket,
        },
    },
    swarm::Swarm,
};
use futures_util::StreamExt;
use kdam::{BarExt, tqdm};
use parking_lot::Mutex;
use reqwest::Client;
use reqwest::IntoUrl;
use semver::Version;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io::Cursor, net::SocketAddr, path::Path, process::Stdio};
use tokio::sync::oneshot::Receiver;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
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
    /// Whether the plugin should close the app.
    should_exit: AtomicBool,
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
        match self.receiver.lock().try_recv() {
            // Result is `Ok` or already received
            Ok(Ok(())) | Err(TryRecvError::Closed) => true,
            // Received an `Err`
            Ok(Err(err)) => {
                error!("Failed to start ViaProxy: {err}");
                self.should_exit.store(true, Ordering::Relaxed);
                true
            }
            // Waiting for result
            Err(TryRecvError::Empty) => false,
        }
    }

    fn finish(&self, app: &mut App) {
        if self.should_exit.load(Ordering::Relaxed) {
            error!("ViaProxy failed to start, exiting...");
            app.world_mut().send_event(AppExit::error());
        } else {
            info!("ViaProxy started successfully");
        }
    }
}

impl ViaVersionPlugin {
    /// Download and start a ViaProxy instance.
    ///
    /// # Panics
    /// Will panic if java fails to parse, files fail to download, or ViaProxy fails to start.
    pub async fn start(mc_version: impl ToString) -> Self {
        let Some(java_version) = JavaHelper::try_find_java_version()
            .await
            .expect("Failed to parse")
        else {
            panic!(
                "Java installation not found! Please download Java from {JAVA_DOWNLOAD_URL} or use your system's package manager."
            );
        };

        let mc_version = mc_version.to_string();
        let mc_path = minecraft_folder_path::minecraft_dir().expect("Unsupported Platform");

        #[rustfmt::skip]
        let via_proxy_ext = if java_version.major < 17 { "+java8.jar" } else { ".jar" };
        let via_proxy_name = format!("ViaProxy-{VIA_PROXY_VERSION}{via_proxy_ext}");
        let via_proxy_path = mc_path.join("azalea-viaversion");
        let via_proxy_url = format!(
            "https://github.com/ViaVersion/ViaProxy/releases/download/v{VIA_PROXY_VERSION}/{via_proxy_name}"
        );
        try_download_file(via_proxy_url, &via_proxy_path, &via_proxy_name)
            .await
            .expect("Failed to download ViaProxy");

        let via_oauth_name = format!("ViaProxyOpenAuthMod-{VIA_OAUTH_VERSION}.jar");
        let via_oauth_path = via_proxy_path.join("plugins");
        let via_oauth_url = format!(
            "https://github.com/ViaVersionAddons/ViaProxyOpenAuthMod/releases/download/v{VIA_OAUTH_VERSION}/{via_oauth_name}"
        );
        try_download_file(via_oauth_url, &via_oauth_path, &via_oauth_name)
            .await
            .expect("Failed to download ViaProxyOpenAuthMod");

        let bind_addr = ViaVersionHelper::try_find_free_addr()
            .await
            .expect("Failed to bind");
        let mut child = Command::new("java")
            /* Java Args */
            .args(["-jar", &via_proxy_name])
            /* ViaProxy Args */
            .arg("cli")
            .args(["--auth-method", "OPENAUTHMOD"])
            .args(["--bind-address", &bind_addr.to_string()])
            .args(["--target-address", "127.0.0.1:0"])
            .args(["--target-version", &mc_version])
            .args(["--wildcard-domain-handling", "INTERNAL"])
            .current_dir(via_proxy_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn");

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut stdout = child.stdout.as_mut().expect("Failed to get stdout");
            let mut reader = BufReader::new(&mut stdout);
            let mut line = String::new();

            loop {
                line.clear();
                reader.read_line(&mut line).await.expect("Failed to read");

                if !line.is_empty() {
                    trace!("{}", line.trim());

                    if line.contains("Finished mapping loading") {
                        if tx.send(Ok(())).is_err() {
                            error!("Failed to signal main thread!");
                        }
                        return;
                    }
                }
            }
        });

        Self {
            receiver: Mutex::new(rx),
            should_exit: AtomicBool::new(false),
            settings: ViaVersionSettings {
                version: mc_version,
                socket: bind_addr,
            },
        }
    }

    /// TODO: Documentation
    pub fn handle_change_address(plugin: Res<ViaVersionSettings>, swarm: Res<Swarm>) {
        let ServerAddress { host, port } = swarm.address.read().clone();

        // sadly, the first part of the resolved address is unused as viaproxy will resolve it on its own
        // more info: https://github.com/ViaVersion/ViaProxy/issues/338
        let data_after_null_byte = host.split_once('\x07').map(|(_, data)| data);

        let mut connection_host = format!("localhost\x07{host}\x07{}", plugin.version);
        if let Some(data) = data_after_null_byte {
            connection_host.push('\0');
            connection_host.push_str(data);
        }

        *swarm.address.write() = ServerAddress {
            port,
            host: connection_host,
        };

        /* Must wait to be written until after reading above */
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
                    Ok(()) => Ok(()), /* Successfully Authenticated */
                    Err(InvalidSession | ForbiddenOperation) => {
                        if let Err(error) = account.refresh().await {
                            error!("Failed to refresh account: {error}");
                            return;
                        }

                        /* Retry after refreshing */
                        join_with_server_id_hash(&client, &token, &uuid, &hash).await
                    }
                    Err(error) => Err(error),
                };

                /* Send directly instead of SendLoginPacketEvent because of lifetimes */
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

/// Try to download and save a file if it doesn't exist.
///
/// # Errors
/// Will return `Err` if the file fails to download or save.
async fn try_download_file<U, P>(url: U, dir: P, file: &str) -> Result<()>
where
    U: IntoUrl + Send + Sync,
    P: AsRef<Path> + Send + Sync,
{
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.as_ref().join(file);
    if path.exists() {
        return Ok(());
    }

    let response = reqwest::get(url).await?;
    let mut pb = tqdm!(
        total = usize::try_from(response.content_length().unwrap_or(0))?,
        unit_scale = true,
        unit_divisor = 1024,
        unit = "B",
        force_refresh = true
    );

    pb.write(format!("Downloading {file}"))?;

    let mut file = File::create(path).await?;
    let mut stream = response.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item?;
        file.write_all(&chunk).await?;
        pb.update(chunk.len())?;
    }

    pb.refresh()?;

    Ok(())
}
