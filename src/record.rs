//! The cluster record: a few nodes a joining node can be admitted by, on the Mainline DHT.
//!
//! It lives under the cluster key derived from the join token, so any node can write it and
//! nobody without the token can. Its content is encrypted, so the DHT only sees opaque bytes.
//! Nodes with a public address add themselves while the list is short, and keep their entry
//! fresh; whoever publishes merges into the latest version.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use pkarr::dns::Name;
use pkarr::dns::rdata::{RData, TXT};
use pkarr::{Client, ResolvePolicy, SignedPacket};
use serde::{Deserialize, Serialize};

use crate::token::JoinToken;

const RECORD_NAME: &str = "_underlay";
const RECORD_TTL: u32 = 300;
const RECORD_VERSION: u8 = 2;
/// Entry points per record: what fits in one pkarr packet with room to spare
pub const MAX_ENTRY_POINTS: usize = 6;

/// A node that admits others.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    /// WireGuard public key, also the static key of its admission handshake
    pub wg_key: [u8; 32],
    /// Its public WireGuard endpoints
    pub endpoints: Vec<SocketAddr>,
    pub admission_port: u16,
    /// Unix seconds of the entry's last refresh
    pub updated: u64,
}

impl EntryPoint {
    /// Where its admission endpoint listens, one per WireGuard endpoint
    pub fn admission_addrs(&self) -> Vec<SocketAddr> {
        self.endpoints.iter().map(|e| SocketAddr::new(e.ip(), self.admission_port)).collect()
    }

    pub fn is_fresh(&self, now: u64, ttl: Duration) -> bool {
        now.saturating_sub(self.updated) < ttl.as_secs()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RecordBody {
    version: u8,
    entry_points: Vec<EntryPoint>,
}

/// Reads and writes the cluster record.
pub struct Discovery {
    client: Client,
    token: JoinToken,
}

impl Discovery {
    /// `bootstrap` overrides the Mainline bootstrap nodes; for a private DHT (tests)
    pub fn new(token: JoinToken, bootstrap: &[String]) -> Result<Self> {
        let mut builder = Client::builder();
        if !bootstrap.is_empty() {
            builder.bootstrap(bootstrap);
        }
        let client = builder.build().context("starting the DHT client")?;
        Ok(Self { client, token })
    }

    /// The entry points in the latest record, or none if there is no record
    pub async fn resolve(&self) -> Result<Vec<EntryPoint>> {
        match self.client.resolve(&self.token.cluster_key(), ResolvePolicy::NetworkOnly).await {
            Ok(packet) => decode(&packet, &self.token),
            Err(pkarr::errors::ResolveError::NotFound) => Ok(vec![]),
            Err(e) => Err(e).context("resolving the cluster record"),
        }
    }

    pub async fn publish(&self, entry_points: &[EntryPoint]) -> Result<()> {
        let packet = encode(entry_points, &self.token)?;
        self.client.publish(&packet).await.context("publishing the cluster record")?;
        Ok(())
    }
}

fn encode(entry_points: &[EntryPoint], token: &JoinToken) -> Result<SignedPacket> {
    let body = RecordBody { version: RECORD_VERSION, entry_points: entry_points.to_vec() };
    let plain = postcard::to_stdvec(&body)?;
    let cipher = XChaCha20Poly1305::new(&token.record_key().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut sealed = nonce.to_vec();
    sealed.extend(cipher.encrypt(&nonce, plain.as_slice()).map_err(|_| anyhow::anyhow!("encrypting the record"))?);
    let text = STANDARD_NO_PAD.encode(sealed);

    let txt = TXT::try_from(text.as_str())?;
    SignedPacket::builder()
        .txt(Name::new_unchecked(RECORD_NAME), txt, RECORD_TTL)
        .sign(&token.cluster_keypair())
        .context("signing the cluster record (too many entry points for one packet?)")
}

fn decode(packet: &SignedPacket, token: &JoinToken) -> Result<Vec<EntryPoint>> {
    let Some(rr) = packet.resource_records(RECORD_NAME).next() else {
        bail!("the cluster record has no {RECORD_NAME} entry");
    };
    let RData::TXT(txt) = &rr.rdata else {
        bail!("the cluster record's {RECORD_NAME} entry is not TXT");
    };
    let text = String::try_from(txt.clone()).context("the cluster record is not text")?;
    let sealed = STANDARD_NO_PAD.decode(text).context("the cluster record is not base64")?;
    if sealed.len() < 24 {
        bail!("the cluster record is too short");
    }
    let (nonce, ciphertext) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(&token.record_key().into());
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("the cluster record doesn't decrypt with this join token"))?;
    let body: RecordBody = postcard::from_bytes(&plain).context("the cluster record is malformed")?;
    if body.version != RECORD_VERSION {
        bail!("unsupported cluster record version {}", body.version);
    }
    Ok(body.entry_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> JoinToken {
        crate::token::test_token()
    }

    fn entry_point(name: &str, key: u8) -> EntryPoint {
        EntryPoint {
            name: name.into(),
            wg_key: [key; 32],
            endpoints: vec!["203.0.113.1:51820".parse().unwrap(), "[2001:db8::1]:51820".parse().unwrap()],
            admission_port: 51821,
            updated: 1_800_000_000,
        }
    }

    #[test]
    fn round_trip() {
        let token = token();
        let entry_points = vec![entry_point("cp-0", 1), entry_point("cp-1", 2)];
        let packet = encode(&entry_points, &token).unwrap();
        assert_eq!(decode(&packet, &token).unwrap(), entry_points);
        // Another cluster's token can't read it
        assert!(decode(&packet, &self::token()).is_err());
    }

    #[test]
    fn fits_max_entry_points() {
        let token = token();
        let entry_points: Vec<_> =
            (0..MAX_ENTRY_POINTS as u8).map(|i| entry_point(&format!("staging-worker-{i}"), i)).collect();
        encode(&entry_points, &token).unwrap();
    }
}
