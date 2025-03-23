use std::{net::SocketAddr, path::Path};

use futures_util::StreamExt;
use kdam::{BarExt, tqdm};
use reqwest::IntoUrl;
use tokio::{fs::File, io::AsyncWriteExt, net::TcpListener};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ViaVersionHelper;

impl ViaVersionHelper {
    /// Try to find a free port and return the socket address
    ///
    /// This uses `TcpListener` to ask the system for a free port.
    ///
    /// # Errors
    /// Will return `Err` if `TcpListener::bind` or `TcpListener::local_addr`
    /// fails.
    pub(crate) async fn try_find_free_addr() -> anyhow::Result<SocketAddr> {
        Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?)
    }

    /// Try to download and save a file if it doesn't exist.
    ///
    /// # Errors
    /// Will return `Err` if the file fails to download or save.
    pub(crate) async fn try_download_file<U, P>(url: U, dir: P, file: &str) -> anyhow::Result<()>
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
}
