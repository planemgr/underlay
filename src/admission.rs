//! Admission: how a node that isn't a WireGuard peer yet becomes one.
//!
//! One Noise `NKpsk0` handshake over TCP carries the request and the answer:
//!
//! - **N**: the joining node has no identity yet beyond the WireGuard key it asks to register;
//! - **K**: it knows the admitting node's static key (its WireGuard key, from the cluster
//!   record or the roster), so it can't be answered by an impostor;
//! - **psk0**: the admission key derived from the join token, so nodes only answer token
//!   holders, and only after checking it on the first message.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::proto::{AdmissionRequest, AdmissionResponse, IO_TIMEOUT, read_frame, write_frame};
use crate::token::JoinToken;

const NOISE_PARAMS: &str = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";
const NOISE_MAX: usize = 65535;
const MAX_CONCURRENT: usize = 64;
/// Sources the rate limit keeps track of; idle ones are forgotten first
const MAX_SOURCES: usize = 4096;

fn prologue(token: &JoinToken) -> Vec<u8> {
    let mut p = b"underlay admission v2".to_vec();
    p.extend_from_slice(token.cluster_key().as_bytes());
    p
}

/// Asks the node listening at `addr` (with WireGuard key `node_key`) to admit us
pub async fn request(
    addr: SocketAddr,
    node_key: [u8; 32],
    token: &JoinToken,
    req: &AdmissionRequest,
) -> Result<AdmissionResponse> {
    timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect(addr).await.with_context(|| format!("connecting to {addr}"))?;
        let psk = token.admission_psk();
        let prologue = prologue(token);
        let mut hs = snow::Builder::new(NOISE_PARAMS.parse()?)
            .prologue(&prologue)?
            .psk(0, &psk)?
            .remote_public_key(&node_key)?
            .build_initiator()?;

        let mut buf = vec![0u8; NOISE_MAX];
        let n = hs.write_message(&serde_json::to_vec(req)?, &mut buf)?;
        write_frame(&mut stream, &buf[..n]).await?;

        let reply = read_frame(&mut stream, NOISE_MAX).await.context("the node closed the connection")?;
        let n = hs
            .read_message(&reply, &mut buf)
            .map_err(|_| anyhow!("the answer doesn't authenticate (wrong key or join token?)"))?;
        serde_json::from_slice(&buf[..n]).context("malformed admission answer")
    })
    .await
    .context("admission timed out")?
}

/// Answers admission requests on `listener` with `admit`, taking at most `per_minute`
/// connections a minute from each source (in bursts of up to as many)
pub async fn serve<F>(listener: TcpListener, private_key: [u8; 32], token: JoinToken, per_minute: u32, admit: F)
where
    F: Fn(AdmissionRequest, SocketAddr) -> AdmissionResponse + Send + Sync + 'static,
{
    let admit = Arc::new(admit);
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut rate = RateLimit::new(per_minute);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("admission accept failed: {e}");
                continue;
            }
        };
        // Before the handshake, so it holds against sources without the token too
        if !rate.allow(peer.ip(), Instant::now()) {
            debug!("dropping admission from {peer}: rate limited");
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            debug!("dropping admission from {peer}: too many in flight");
            continue;
        };
        let admit = admit.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match timeout(IO_TIMEOUT, handle(stream, peer, private_key, &token, &*admit)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!("admission from {peer} failed: {e:#}"),
                Err(_) => debug!("admission from {peer} timed out"),
            }
        });
    }
}

/// A token bucket per source address. IPv6 sources count per /64, the usual size of one
/// host's or site's allocation.
struct RateLimit {
    burst: f64,
    /// Time to earn one connection back
    interval: Duration,
    sources: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimit {
    fn new(per_minute: u32) -> Self {
        let per_minute = per_minute.max(1);
        Self { burst: per_minute as f64, interval: Duration::from_secs(60) / per_minute, sources: HashMap::new() }
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let source = match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(v6.to_bits() & !((1u128 << 64) - 1))),
            v4 => v4,
        };
        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_SOURCES {
            // Forget the sources whose bucket refilled: they are where a new one would start
            let full = self.interval.mul_f64(self.burst);
            self.sources.retain(|_, (_, last)| now.duration_since(*last) < full);
            if self.sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let (tokens, last) = self.sources.entry(source).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*last).div_duration_f64(self.interval)).min(self.burst);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

async fn handle<F>(
    mut stream: TcpStream,
    peer: SocketAddr,
    private_key: [u8; 32],
    token: &JoinToken,
    admit: &F,
) -> Result<()>
where
    F: Fn(AdmissionRequest, SocketAddr) -> AdmissionResponse,
{
    let psk = token.admission_psk();
    let prologue = prologue(token);
    let mut hs = snow::Builder::new(NOISE_PARAMS.parse()?)
        .prologue(&prologue)?
        .psk(0, &psk)?
        .local_private_key(&private_key)?
        .build_responder()?;

    let msg = read_frame(&mut stream, NOISE_MAX).await?;
    let mut buf = vec![0u8; NOISE_MAX];
    // Fails unless the sender holds the join token
    let n = hs.read_message(&msg, &mut buf).map_err(|_| anyhow!("handshake doesn't authenticate"))?;
    let req: AdmissionRequest = serde_json::from_slice(&buf[..n]).context("malformed admission request")?;

    let response = admit(req, peer);
    let n = hs.write_message(&serde_json::to_vec(&response)?, &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::AdmissionResponse;
    use crate::util::PubKey;

    fn token() -> JoinToken {
        crate::token::test_token()
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let private = crate::wg::PrivateKey::generate();
        (private.0, private.public().0)
    }

    async fn start(token: JoinToken, private: [u8; 32]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, private, token, 60, |req, _| AdmissionResponse::Refused { reason: req.name }));
        addr
    }

    fn req() -> AdmissionRequest {
        AdmissionRequest { name: "w-0".into(), wg_key: PubKey([1; 32]), endpoints: vec![], hint: None }
    }

    #[test]
    fn rate_limit() {
        let mut rate = RateLimit::new(3);
        let t = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        // A burst of three, then one every 20 seconds
        assert!((0..3).all(|_| rate.allow(a, t)));
        assert!(!rate.allow(a, t));
        assert!(!rate.allow(a, t + Duration::from_secs(19)));
        assert!(rate.allow(a, t + Duration::from_secs(20)));
        // Other sources have their own budget
        assert!(rate.allow("192.0.2.2".parse().unwrap(), t));
        // The same address over IPv6 (the dual-stack listener) shares the budget
        assert!(!rate.allow("::ffff:192.0.2.1".parse().unwrap(), t + Duration::from_secs(20)));
        // One /64 shares one budget
        assert!((0..3).all(|i| rate.allow(format!("2001:db8::{i}").parse().unwrap(), t)));
        assert!(!rate.allow("2001:db8::ffff".parse().unwrap(), t));
        assert!(rate.allow("2001:db8:0:1::".parse().unwrap(), t));
    }

    #[test]
    fn rate_limit_forgets_idle_sources() {
        let mut rate = RateLimit::new(60);
        let t = Instant::now();
        for i in 0..MAX_SOURCES as u32 {
            assert!(rate.allow(IpAddr::from(i.to_be_bytes()), t));
        }
        // Full while every source is still refilling
        assert!(!rate.allow("192.0.2.1".parse().unwrap(), t + Duration::from_secs(30)));
        assert!(rate.allow("192.0.2.1".parse().unwrap(), t + Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn round_trip() {
        let token = token();
        let (private, public) = keypair();
        let addr = start(token.clone(), private).await;
        match request(addr, public, &token, &req()).await.unwrap() {
            AdmissionResponse::Refused { reason } => assert_eq!(reason, "w-0"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_token_or_key_fails() {
        let token = token();
        let other_token = self::token();
        let (private, public) = keypair();
        let addr = start(token.clone(), private).await;
        assert!(request(addr, public, &other_token, &req()).await.is_err());
        let (_, impostor) = keypair();
        assert!(request(addr, impostor, &token, &req()).await.is_err());
    }
}
