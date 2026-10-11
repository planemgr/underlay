//! Messages between nodes, and their framing.
//!
//! Two channels carry them:
//!
//! - **admission** (TCP on a node's public address): a joining node isn't a WireGuard peer yet,
//!   so it can't use the mesh. One Noise handshake carries the request and the answer (see
//!   `admission`).
//! - **the mesh API** (TCP on a node's mesh address, over WireGuard): nodes exchange rosters
//!   through it. WireGuard already authenticates the sender, so the source address identifies
//!   the caller, as in innernet.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::roster::Member;
use crate::util::PubKey;

/// Requests and responses larger than this are refused (a roster of thousands of nodes fits)
const MAX_FRAME: usize = 8 << 20;
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub name: String,
    pub wg_key: PubKey,
    /// The node's own interface addresses with its WireGuard port
    pub endpoints: Vec<SocketAddr>,
    /// The address (probe, first seen) the node already holds in another partition
    pub hint: Option<(u32, u64)>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant, reason = "built once per admission")]
pub enum AdmissionResponse {
    Accepted {
        /// The node's own entry
        member: Member,
        /// The admitting node, the first peer to bring up and pull the roster from
        admitter: Member,
    },
    Refused {
        reason: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ApiRequest {
    /// Here are members (all of ours, or the ones that just changed); send yours back
    Sync { members: Vec<Member> },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ApiResponse {
    Sync {
        members: Vec<Member>,
    },
    /// The caller isn't a live member
    Unknown {
        caller: IpAddr,
    },
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_FRAME, "frame too large");
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let len = r.read_u32().await? as usize;
    ensure!(len <= max.min(MAX_FRAME), "frame of {len} bytes is too large");
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    write_frame(w, &serde_json::to_vec(value)?).await
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let bytes = read_frame(r, MAX_FRAME).await?;
    serde_json::from_slice(&bytes).context("malformed message")
}
