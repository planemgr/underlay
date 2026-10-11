//! Cluster membership, held by every node and spread by gossip.
//!
//! The roster maps node names to members. Nodes exchange rosters and merge them; merging is
//! commutative and idempotent, so everyone converges whatever order updates arrive in:
//!
//! - a member's identity (key, address, removal) is last-writer-wins by `generation`, the clock
//!   of the node that changed it, ties broken by key;
//! - its heartbeat only grows, its endpoints are last-writer-wins.
//!
//! Removal is a tombstone that wins over the entry it replaces, so a removed node doesn't come
//! back from someone's stale copy.
//!
//! A node's mesh address is a hash of its name, so a name keeps its address across restarts,
//! new keys and even everyone losing their state. When two names hash to one address, the name
//! that joined first keeps it and the other moves itself to its next hash.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::PubKey;

/// Tombstones are forgotten after this long; until then their address stays with their name
const TOMBSTONE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub wg_key: PubKey,
    pub mesh_ip: IpAddr,
    /// Which hash of the name the address is: 0 unless it collided
    pub probe: u32,
    /// Unix milliseconds the name first joined; the older name keeps a contested address
    pub first_seen: u64,
    /// Unix milliseconds of the identity's last change (join, new key, new address, removal)
    pub generation: u64,
    pub removed: bool,
    /// Unix seconds of the node's last heartbeat
    pub heartbeat: u64,
    /// The node's own interface addresses with its WireGuard port
    pub endpoints: Vec<SocketAddr>,
    /// Unix milliseconds of the endpoints' report
    pub endpoints_at: u64,
}

impl Member {
    fn same_identity(&self, other: &Member) -> bool {
        self.wg_key == other.wg_key
            && self.mesh_ip == other.mesh_ip
            && self.probe == other.probe
            && self.removed == other.removed
    }

    fn identity_rank(&self) -> (u64, bool, PubKey) {
        (self.generation, self.removed, self.wg_key)
    }

    /// Which of two members holding one address keeps it
    fn owns_before(&self, other: &Member) -> bool {
        (self.first_seen, &self.name) < (other.first_seen, &other.name)
    }
}

/// Why an admission was refused
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The name changed keys moments ago: two live nodes are likely sharing it
    Cooldown,
    InvalidName,
    MeshFull,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::Cooldown => "the name changed keys moments ago (two nodes with the same name?)",
            Refusal::InvalidName => "names must be DNS labels",
            Refusal::MeshFull => "no free mesh address",
        })
    }
}

/// What a node asks to be admitted as
pub struct Claim<'a> {
    pub name: &'a str,
    pub wg_key: PubKey,
    pub endpoints: Vec<SocketAddr>,
    /// The address (probe, first seen) the node already has, from a partition that hasn't
    /// merged with ours yet
    pub hint: Option<(u32, u64)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    members: BTreeMap<String, Member>,
}

impl Roster {
    pub fn get(&self, name: &str) -> Option<&Member> {
        self.members.get(name)
    }

    /// Members that haven't been removed
    pub fn live(&self) -> impl Iterator<Item = &Member> {
        self.members.values().filter(|m| !m.removed)
    }

    /// Everything, tombstones included, for exchanging with other nodes
    pub fn to_vec(&self) -> Vec<Member> {
        self.members.values().cloned().collect()
    }

    pub fn by_key(&self, key: PubKey) -> Option<&Member> {
        self.live().find(|m| m.wg_key == key)
    }

    /// The live member that holds `ip`
    pub fn owner(&self, ip: IpAddr) -> Option<&Member> {
        self.live().filter(|m| m.mesh_ip == ip).reduce(|a, b| if b.owns_before(a) { b } else { a })
    }

    /// Merges one member's state. Returns whether anything changed.
    pub fn merge_member(&mut self, incoming: &Member) -> bool {
        let Some(current) = self.members.get_mut(&incoming.name) else {
            self.members.insert(incoming.name.clone(), incoming.clone());
            return true;
        };

        if !current.same_identity(incoming) {
            if incoming.identity_rank() <= current.identity_rank() {
                return false;
            }
            let (heartbeat, first_seen) = (current.heartbeat, current.first_seen);
            *current = incoming.clone();
            // A new key for the same name: the name's history carries over
            current.first_seen = first_seen.min(incoming.first_seen);
            current.heartbeat = heartbeat.max(incoming.heartbeat);
            return true;
        }

        let mut changed = false;
        if incoming.generation > current.generation {
            current.generation = incoming.generation;
            changed = true;
        }
        if incoming.first_seen < current.first_seen {
            current.first_seen = incoming.first_seen;
            changed = true;
        }
        if incoming.heartbeat > current.heartbeat {
            current.heartbeat = incoming.heartbeat;
            changed = true;
        }
        if incoming.endpoints_at > current.endpoints_at {
            current.endpoints = incoming.endpoints.clone();
            current.endpoints_at = incoming.endpoints_at;
            changed = true;
        }
        changed
    }

    pub fn merge(&mut self, members: &[Member]) -> bool {
        members.iter().fold(false, |changed, m| self.merge_member(m) | changed)
    }

    /// Admits a node, or returns its entry when it is already a member with that key.
    ///
    /// A name always gets its own address back: a restarted node rejoins with a new key and
    /// keeps its address. A name may change keys at most once per `cooldown`, so two live nodes
    /// sharing a name trade it slowly instead of thrashing.
    pub fn admit(&mut self, claim: Claim<'_>, mesh: IpNet, now_ms: u64, cooldown: Duration) -> Result<Member, Refusal> {
        if !valid_name(claim.name) {
            return Err(Refusal::InvalidName);
        }
        let existing = self.members.get(claim.name).cloned();
        if let Some(m) = existing.as_ref().filter(|m| !m.removed) {
            if m.wg_key == claim.wg_key {
                return Ok(m.clone());
            }
            if now_ms.saturating_sub(m.generation) < cooldown.as_millis() as u64 {
                return Err(Refusal::Cooldown);
            }
        }

        // A key moving to another name leaves the old one
        let moved: Vec<String> =
            self.live().filter(|m| m.wg_key == claim.wg_key && m.name != claim.name).map(|m| m.name.clone()).collect();
        for name in moved {
            self.remove(&name, now_ms);
        }

        let (probe, first_seen) = match &existing {
            Some(m) => (m.probe, m.first_seen),
            None => claim.hint.unwrap_or((0, now_ms)),
        };
        let (mesh_ip, probe) = match existing.as_ref().filter(|m| !m.removed) {
            // Taking over a live name: its address, contested or not, stays with it
            Some(m) => (m.mesh_ip, m.probe),
            None => self.free_address(mesh, claim.name, probe).ok_or(Refusal::MeshFull)?,
        };
        let generation = existing.as_ref().map_or(now_ms, |m| now_ms.max(m.generation + 1));
        let member = Member {
            name: claim.name.to_string(),
            wg_key: claim.wg_key,
            mesh_ip,
            probe,
            first_seen,
            generation,
            removed: false,
            heartbeat: now_ms / 1000,
            endpoints: claim.endpoints,
            endpoints_at: now_ms,
        };
        self.members.insert(member.name.clone(), member.clone());
        Ok(member)
    }

    /// The first address from `probe` on that no other name holds (tombstones keep theirs)
    fn free_address(&self, mesh: IpNet, name: &str, probe: u32) -> Option<(IpAddr, u32)> {
        let taken: Vec<IpAddr> = self.members.values().filter(|m| m.name != name).map(|m| m.mesh_ip).collect();
        (probe..probe.saturating_add(64)).map(|p| (address_for(mesh, name, p), p)).find(|(ip, _)| !taken.contains(ip))
    }

    /// Moves `name` to its next free address if an older name holds its current one. Returns
    /// the new address.
    pub fn resolve_conflict(&mut self, name: &str, mesh: IpNet, now_ms: u64) -> Option<IpAddr> {
        let me = self.members.get(name).filter(|m| !m.removed)?.clone();
        if self.owner(me.mesh_ip).is_none_or(|o| o.name == name) {
            return None;
        }
        let (ip, probe) = self.free_address(mesh, name, me.probe + 1)?;
        let m = self.members.get_mut(name).expect("checked above");
        m.mesh_ip = ip;
        m.probe = probe;
        m.generation = now_ms.max(m.generation + 1);
        Some(ip)
    }

    pub fn heartbeat(&mut self, name: &str, now_ms: u64) {
        if let Some(m) = self.members.get_mut(name) {
            m.heartbeat = m.heartbeat.max(now_ms / 1000);
        }
    }

    /// Sets a node's own addresses. Returns whether they changed.
    pub fn set_endpoints(&mut self, name: &str, endpoints: Vec<SocketAddr>, now_ms: u64) -> bool {
        match self.members.get_mut(name) {
            Some(m) if m.endpoints != endpoints => {
                m.endpoints = endpoints;
                m.endpoints_at = m.endpoints_at.max(now_ms);
                true
            }
            _ => false,
        }
    }

    pub fn remove(&mut self, name: &str, now_ms: u64) -> bool {
        match self.members.get_mut(name) {
            Some(m) if !m.removed => {
                m.removed = true;
                m.generation = now_ms.max(m.generation + 1);
                true
            }
            _ => false,
        }
    }

    /// Removes members without a heartbeat for `expire_after` (never `own`) and forgets old
    /// tombstones. Returns the removed names.
    pub fn expire(&mut self, own: &str, now_ms: u64, expire_after: Duration) -> Vec<String> {
        let now = now_ms / 1000;
        let expired: Vec<String> = self
            .live()
            .filter(|m| m.name != own && now.saturating_sub(m.heartbeat) >= expire_after.as_secs())
            .map(|m| m.name.clone())
            .collect();
        for name in &expired {
            self.remove(name, now_ms);
        }
        let retention = TOMBSTONE_RETENTION.as_millis() as u64;
        self.members.retain(|_, m| !m.removed || now_ms.saturating_sub(m.generation) < retention);
        expired
    }
}

/// The `probe`th candidate address of `name` in `mesh`: a hash of both, past the network address
/// (and short of the IPv4 broadcast address)
pub fn address_for(mesh: IpNet, name: &str, probe: u32) -> IpAddr {
    let digest = Sha256::new().chain_update(name.as_bytes()).chain_update(probe.to_be_bytes()).finalize();
    let hash = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
    let host_bits = u32::from(mesh.max_prefix_len() - mesh.prefix_len());
    match mesh.network() {
        IpAddr::V4(net) => {
            let usable = (1u128 << host_bits) - 2;
            let offset = 1 + (hash % usable) as u32;
            IpAddr::V4(Ipv4Addr::from(u32::from(net) + offset))
        }
        IpAddr::V6(net) => {
            let usable = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
            let offset = 1 + hash % usable;
            IpAddr::V6(Ipv6Addr::from(u128::from(net) + offset))
        }
    }
}

/// Node names are DNS labels, so they can double as host names
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOLDOWN: Duration = Duration::from_secs(60);

    fn mesh() -> IpNet {
        "100.64.0.0/10".parse().unwrap()
    }

    fn claim(name: &str, key: u8) -> Claim<'_> {
        Claim { name, wg_key: PubKey([key; 32]), endpoints: vec![], hint: None }
    }

    #[test]
    fn addresses_are_stable_and_in_range() {
        let a = address_for(mesh(), "staging-cp-0", 0);
        assert_eq!(a, address_for(mesh(), "staging-cp-0", 0));
        assert_ne!(a, address_for(mesh(), "staging-cp-0", 1));
        assert!(mesh().contains(&a));
        let small: IpNet = "10.0.0.0/24".parse().unwrap();
        for p in 0..1000 {
            let ip = address_for(small, "x", p);
            assert!(small.contains(&ip) && ip != small.network() && ip != small.broadcast(), "{ip}");
        }
        assert!("fd00::/64".parse::<IpNet>().unwrap().contains(&address_for("fd00::/64".parse().unwrap(), "x", 0)));
    }

    #[test]
    fn a_name_keeps_its_address_under_a_new_key() {
        let mut r = Roster::default();
        let first = r.admit(claim("w-0", 1), mesh(), 1_000, COOLDOWN).unwrap();
        assert_eq!(first.mesh_ip, address_for(mesh(), "w-0", 0));
        // Idempotent
        assert_eq!(r.admit(claim("w-0", 1), mesh(), 2_000, COOLDOWN).unwrap(), first);
        // A restart with a new key: refused only within the cooldown
        assert_eq!(r.admit(claim("w-0", 2), mesh(), 30_000, COOLDOWN), Err(Refusal::Cooldown));
        let again = r.admit(claim("w-0", 2), mesh(), 100_000, COOLDOWN).unwrap();
        assert_eq!(again.mesh_ip, first.mesh_ip);
        assert_eq!(again.wg_key, PubKey([2; 32]));
        assert_eq!(again.first_seen, first.first_seen);
        // And after removal
        r.remove("w-0", 200_000);
        assert_eq!(r.admit(claim("w-0", 3), mesh(), 300_000, COOLDOWN).unwrap().mesh_ip, first.mesh_ip);
    }

    #[test]
    fn collisions_go_to_the_younger_name() {
        // In a /24, some pair of names collides quickly
        let small: IpNet = "10.9.0.0/24".parse().unwrap();
        let names: Vec<String> = (0..64).map(|i| format!("n-{i}")).collect();
        let (a, b) = names
            .iter()
            .enumerate()
            .find_map(|(i, a)| {
                names[i + 1..].iter().find(|b| address_for(small, a, 0) == address_for(small, b, 0)).map(|b| (a, b))
            })
            .expect("a collision among 64 names in a /24");

        // Admitted one after the other: the second one probes past the first
        let mut r = Roster::default();
        let ma = r.admit(claim(a, 1), small, 1_000, COOLDOWN).unwrap();
        let mb = r.admit(claim(b, 2), small, 2_000, COOLDOWN).unwrap();
        assert_ne!(ma.mesh_ip, mb.mesh_ip);
        assert_eq!(mb.probe, 1);

        // Admitted in two partitions at once: after merging, the younger one moves itself
        let mut p = Roster::default();
        let mut q = Roster::default();
        p.admit(claim(a, 1), small, 1_000, COOLDOWN).unwrap();
        q.admit(claim(b, 2), small, 2_000, COOLDOWN).unwrap();
        p.merge(&q.to_vec());
        assert_eq!(p.owner(ma.mesh_ip).unwrap().name, *a);
        assert_eq!(p.resolve_conflict(a, small, 3_000), None);
        let moved = p.resolve_conflict(b, small, 3_000).unwrap();
        assert_ne!(moved, ma.mesh_ip);
        q.merge(&p.to_vec());
        assert_eq!(q.get(b).unwrap().mesh_ip, moved);
    }

    #[test]
    fn merge_converges() {
        let mut a = Roster::default();
        let mut b = Roster::default();
        a.admit(claim("w-0", 1), mesh(), 1_000, COOLDOWN).unwrap();
        b.admit(claim("w-1", 2), mesh(), 1_000, COOLDOWN).unwrap();
        b.set_endpoints("w-1", vec!["203.0.113.5:51820".parse().unwrap()], 5_000);
        b.heartbeat("w-1", 9_000);

        let mut ab = a.clone();
        ab.merge(&b.to_vec());
        let mut ba = b.clone();
        ba.merge(&a.to_vec());
        assert_eq!(ab, ba);
        assert!(!ab.clone().merge(&ba.to_vec()));

        // A removal wins over the stale copy
        ab.remove("w-0", 9_000);
        let mut stale = a.clone();
        stale.merge(&ab.to_vec());
        assert!(stale.get("w-0").unwrap().removed);
        ab.merge(&a.to_vec());
        assert!(ab.get("w-0").unwrap().removed);
    }

    #[test]
    fn a_new_key_keeps_the_names_history() {
        let mut old = Roster::default();
        old.admit(claim("w-0", 1), mesh(), 1_000, COOLDOWN).unwrap();
        let mut new = old.clone();
        new.admit(claim("w-0", 2), mesh(), 100_000, COOLDOWN).unwrap();
        old.heartbeat("w-0", 150_000);
        old.merge(&new.to_vec());
        let m = old.get("w-0").unwrap();
        assert_eq!((m.wg_key, m.first_seen, m.heartbeat), (PubKey([2; 32]), 1_000, 150));
    }

    #[test]
    fn expiry_spares_ourselves() {
        let mut r = Roster::default();
        r.admit(claim("me", 1), mesh(), 0, COOLDOWN).unwrap();
        r.admit(claim("w-0", 2), mesh(), 0, COOLDOWN).unwrap();
        let hour = Duration::from_secs(3600);
        assert_eq!(r.expire("me", 2 * 3600 * 1000, hour), vec!["w-0".to_string()]);
        assert!(!r.get("me").unwrap().removed);
    }

    #[test]
    fn names() {
        assert!(valid_name("staging-cp-0"));
        assert!(!valid_name("Staging"));
        assert!(!valid_name("-a"));
        assert!(!valid_name(""));
    }
}
