//! The mesh API: one request and one response per TCP connection, over WireGuard.
//!
//! The listener is bound to the WireGuard interface, so a request can only arrive through a
//! tunnel, and the kernel only accepts a packet from a peer's allowed address: the source
//! address *is* the caller's authenticated identity.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::proto::{ApiRequest, ApiResponse, IO_TIMEOUT, read_json, write_json};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Listens on `addr`, accepting connections that came in through `interface` only
pub fn bind(addr: SocketAddr, interface: &str) -> Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind_device(Some(interface.as_bytes())).with_context(|| format!("binding to device {interface}"))?;
    socket.bind(&addr.into()).with_context(|| format!("binding the mesh API to {addr}"))?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub async fn serve<F>(listener: TcpListener, handler: F)
where
    F: Fn(ApiRequest, IpAddr) -> ApiResponse + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("mesh API accept failed: {e}");
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let result = timeout(IO_TIMEOUT, async {
                let request: ApiRequest = read_json(&mut stream).await?;
                let response = handler(request, peer.ip());
                write_json(&mut stream, &response).await
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!("mesh API request from {peer} failed: {e:#}"),
                Err(_) => debug!("mesh API request from {peer} timed out"),
            }
        });
    }
}

pub async fn call(addr: SocketAddr, request: &ApiRequest) -> Result<ApiResponse> {
    // Over a live tunnel a connection is up in a round trip; a peer that's down shouldn't hold
    // up trying the next one for the whole request timeout
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connecting to {addr} timed out"))?
        .with_context(|| format!("connecting to {addr}"))?;
    timeout(IO_TIMEOUT, async {
        write_json(&mut stream, request).await?;
        read_json(&mut stream).await
    })
    .await
    .with_context(|| format!("request to {addr} timed out"))?
}
