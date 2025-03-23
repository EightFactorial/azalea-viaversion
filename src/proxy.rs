use std::net::SocketAddr;

use tokio::net::TcpListener;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ViaVersionHelper;

impl ViaVersionHelper {
    /// Try to find a free port and return the socket address
    ///
    /// This uses `TcpListener` to ask the system for a free port.
    ///
    /// # Errors
    /// Will return `Err` if `TcpListener::bind` or `TcpListener::local_addr` fails.
    pub(crate) async fn try_find_free_addr() -> anyhow::Result<SocketAddr> {
        Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?)
    }
}
