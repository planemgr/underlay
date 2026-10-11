//! The join token: the one secret every node of a cluster holds.
//!
//! Every node holding it is trusted, as with a k3s join token. HKDF derives three keys from it,
//! one per use:
//!
//! - the **cluster key** (ed25519): names the cluster's pkarr record on the Mainline DHT and
//!   signs it, so any node can publish itself as an entry point;
//! - the **record key**: encrypts the record, so the DHT only sees opaque bytes;
//! - the **admission key**: the pre-shared key of the admission handshake, so nodes only admit
//!   token holders.
//!
//! The token also carries the mesh's address range, so no two nodes can disagree on it. Its
//! format is `ul2:<32 random bytes, base64>:<mesh CIDR>`, which tofu can put together:
//!
//! ```hcl
//! resource "random_bytes" "underlay" { length = 32 }
//! locals { underlay_token = "ul2:${random_bytes.underlay.base64}:100.64.0.0/10" }
//! ```

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use hkdf::Hkdf;
use ipnet::IpNet;
use sha2::Sha256;

const HKDF_SALT: &[u8] = b"underlay v2";

/// Either base64 alphabet, padded or not
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let lenient = GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    [
        GeneralPurpose::new(&base64::alphabet::STANDARD, lenient),
        GeneralPurpose::new(&base64::alphabet::URL_SAFE, lenient),
    ]
    .iter()
    .find_map(|engine| engine.decode(s).ok())
}

#[derive(Clone)]
pub struct JoinToken {
    secret: [u8; 32],
    pub mesh_cidr: IpNet,
}

impl JoinToken {
    pub fn decode(token: &str) -> Result<Self> {
        let mut parts = token.trim().splitn(3, ':');
        let (Some("ul2"), Some(secret), Some(cidr)) = (parts.next(), parts.next(), parts.next()) else {
            anyhow::bail!("the join token must look like ul2:<base64 secret>:<mesh CIDR>");
        };
        let secret = decode_base64(secret).context("the join token's secret is not base64")?;
        let secret =
            <[u8; 32]>::try_from(secret.as_slice()).ok().context("the join token's secret must be 32 bytes")?;
        let mesh_cidr: IpNet = cidr.parse().context("the join token's mesh CIDR is invalid")?;
        ensure!(mesh_cidr.trunc() == mesh_cidr, "the mesh CIDR {mesh_cidr} has host bits set");
        ensure!(
            mesh_cidr.max_prefix_len() - mesh_cidr.prefix_len() >= 8,
            "the mesh CIDR {mesh_cidr} is too small; use /24 or larger"
        );
        Ok(Self { secret, mesh_cidr })
    }

    pub fn cluster_keypair(&self) -> pkarr::Keypair {
        pkarr::Keypair::from_secret_key(&self.derive(b"cluster key"))
    }

    pub fn cluster_key(&self) -> pkarr::PublicKey {
        self.cluster_keypair().public_key()
    }

    pub fn record_key(&self) -> [u8; 32] {
        self.derive(b"record")
    }

    pub fn admission_psk(&self) -> [u8; 32] {
        self.derive(b"admission")
    }

    fn derive(&self, label: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), &self.secret)
            .expand(label, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }
}

/// A fresh token, for tests
#[cfg(test)]
pub fn test_token() -> JoinToken {
    let secret: [u8; 32] = rand::random();
    JoinToken::decode(&format!("ul2:{}:100.64.0.0/10", base64::engine::general_purpose::STANDARD.encode(secret)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;

    #[test]
    fn decodes_what_tofu_writes() {
        let secret = [7u8; 32];
        let std = JoinToken::decode(&format!("ul2:{}:100.64.0.0/10", STANDARD.encode(secret))).unwrap();
        let url = JoinToken::decode(&format!("ul2:{}:100.64.0.0/10", URL_SAFE_NO_PAD.encode(secret))).unwrap();
        assert_eq!(std.cluster_key(), url.cluster_key());
        assert_eq!(std.mesh_cidr, "100.64.0.0/10".parse::<IpNet>().unwrap());
        assert_ne!(std.record_key(), std.admission_psk());
        assert_ne!(std.cluster_key(), test_token().cluster_key());
        assert!(JoinToken::decode(&format!("ul2:{}:fd00:ab::/64", STANDARD.encode(secret))).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        let secret = STANDARD.encode([7u8; 32]);
        assert!(JoinToken::decode("nope").is_err());
        assert!(JoinToken::decode(&format!("ul1:{secret}:100.64.0.0/10")).is_err());
        assert!(JoinToken::decode(&format!("ul2:{}:100.64.0.0/10", STANDARD.encode([7u8; 16]))).is_err());
        assert!(JoinToken::decode(&format!("ul2:{secret}:100.64.0.1/10")).is_err());
        assert!(JoinToken::decode(&format!("ul2:{secret}:10.0.0.0/30")).is_err());
    }
}
