//! The kernel WireGuard interface: bringing it up and keeping its peers in line with the roster.
//!
//! Peers are changed in place, never replaced wholesale, so running sessions survive updates.
//! An endpoint WireGuard learned from a live session (roaming) is never overwritten; a peer
//! without a recent handshake is cycled through its dial order until one works.
//!
//! The device is read and written over WireGuard's generic netlink family, like `wg(8)` does.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ipnet::IpNet;
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::constants::{AF_INET, AF_INET6, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS};
use netlink_packet_wireguard::nlas::{WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs};
use netlink_packet_wireguard::{Wireguard, WireguardCmd};
use netlink_request::netlink_request_genl;
use tracing::{debug, info};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::net::InterfaceName;
use crate::roster::Member;
use crate::util::PubKey;
use crate::{endpoints, net};

/// Sessions rekey every two minutes while in use; older handshakes mean the session is gone
pub const HANDSHAKE_FRESH: Duration = Duration::from_secs(180);
/// Keeps the NAT mapping of a node behind NAT open, so peers can always reach it
const NAT_KEEPALIVE: u16 = 25;
/// Peer changes sent per netlink message. One peer is well under 200 bytes, so this stays far
/// below the kernel's 8 KiB message buffer.
const PEERS_PER_MESSAGE: usize = 16;

/// A WireGuard private key
#[derive(Clone)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::from(rand::random::<[u8; 32]>()).to_bytes())
    }

    pub fn public(&self) -> PubKey {
        PubKey(PublicKey::from(&StaticSecret::from(self.0)).to_bytes())
    }
}

/// What the kernel reports about the interface
pub struct Device {
    pub private_key: Option<PrivateKey>,
    pub peers: Vec<Peer>,
}

pub struct Peer {
    pub public_key: PubKey,
    pub endpoint: Option<SocketAddr>,
    /// Seconds, 0 when off
    pub keepalive: u16,
    pub allowed_ips: Vec<IpNet>,
    pub last_handshake: Option<SystemTime>,
}

pub struct Interface {
    name: InterfaceName,
    rotation: HashMap<PubKey, Rotation>,
    rotate_after: Duration,
}

/// Which dial candidate a peer is on, and since when
struct Rotation {
    index: usize,
    since: Instant,
}

impl Interface {
    pub fn new(name: InterfaceName, rotate_after: Duration) -> Self {
        Self { name, rotation: HashMap::new(), rotate_after }
    }

    /// Creates the interface if needed and sets its key and port
    pub fn configure(&self, private_key: &PrivateKey, listen_port: u16) -> Result<()> {
        if !net::exists(&self.name) {
            net::add_wireguard(&self.name).with_context(|| format!("creating WireGuard interface {}", self.name))?;
        }
        set_device(&self.name, vec![WgDeviceAttrs::PrivateKey(private_key.0), WgDeviceAttrs::ListenPort(listen_port)])
            .with_context(|| format!("configuring WireGuard interface {}", self.name))
    }

    /// Gives the interface `addr` as its only address and brings it up. The prefix routes the
    /// whole mesh to the interface; WireGuard picks the peer by address.
    pub fn set_address(&self, addr: IpNet, mtu: u32) -> Result<()> {
        net::set_addr(&self.name, addr).with_context(|| format!("setting {addr} on {}", self.name))?;
        // Left over from before a restart, or from an address conflict we moved away from
        for old in net::interface_addrs(&self.name)?.into_iter().filter(|a| *a != addr) {
            net::del_addr(&self.name, old).with_context(|| format!("removing {old} from {}", self.name))?;
        }
        net::set_up(&self.name, mtu).with_context(|| format!("bringing {} up", self.name))?;
        info!("interface {} up as {addr}", self.name);
        Ok(())
    }

    /// The key and peer addresses an interface left by an earlier run holds, which survive a
    /// daemon restart but not a reboot: the only state the daemon keeps
    pub fn existing(&self) -> Option<(PrivateKey, Vec<IpAddr>)> {
        let device = get_device(&self.name).ok()?;
        let key = device.private_key?;
        let peers = device.peers.iter().flat_map(|p| p.allowed_ips.iter().map(|a| a.addr())).collect();
        Some((key, peers))
    }

    pub fn device(&self) -> Result<Device> {
        get_device(&self.name).with_context(|| format!("reading WireGuard interface {}", self.name))
    }

    /// Makes the interface's peers match `members`. `self_public` says whether this node has a
    /// public address of its own; without one it keeps every peer's NAT mapping open.
    pub fn reconcile(&mut self, members: &[&Member], self_public: bool) -> Result<()> {
        let device = self.device()?;
        let current: HashMap<PubKey, &Peer> = device.peers.iter().map(|p| (p.public_key, p)).collect();
        let now = Instant::now();
        let mut changes = vec![];

        for member in members {
            let key = member.wg_key;
            let peer = current.get(&key).copied();
            let allowed = IpNet::from(member.mesh_ip);
            let keepalive = if self_public { 0 } else { NAT_KEEPALIVE };
            let endpoint = self.pick_endpoint(member, peer, self_public, now);

            let needs_update = match peer {
                None => true,
                Some(p) => {
                    p.allowed_ips != [allowed]
                        || p.keepalive != keepalive
                        || endpoint.is_some_and(|e| p.endpoint != Some(e))
                }
            };
            if !needs_update {
                continue;
            }

            let mut attrs = vec![
                WgPeerAttrs::PublicKey(key.0),
                WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
                WgPeerAttrs::AllowedIps(vec![allowed_ip(allowed)]),
                WgPeerAttrs::PersistentKeepalive(keepalive),
            ];
            attrs.extend(endpoint.map(WgPeerAttrs::Endpoint));
            if peer.is_none() {
                info!(
                    "adding peer {} ({}) at {}",
                    member.name,
                    member.mesh_ip,
                    endpoint.map_or("no endpoint".into(), |e| e.to_string())
                );
            } else {
                debug!("updating peer {} endpoint {:?}", member.name, endpoint);
            }
            changes.push(WgPeer(attrs));
        }

        let wanted: Vec<PubKey> = members.iter().map(|m| m.wg_key).collect();
        for key in current.keys().filter(|k| !wanted.contains(k)) {
            info!("removing peer {key}");
            changes.push(WgPeer(vec![WgPeerAttrs::PublicKey(key.0), WgPeerAttrs::Flags(WGPEER_F_REMOVE_ME)]));
            self.rotation.remove(key);
        }

        for chunk in changes.chunks(PEERS_PER_MESSAGE) {
            set_device(&self.name, vec![WgDeviceAttrs::Peers(chunk.to_vec())])
                .with_context(|| format!("updating peers of {}", self.name))?;
        }
        Ok(())
    }

    /// The endpoint to set for `member`, or None to leave the current one alone
    fn pick_endpoint(
        &mut self,
        member: &Member,
        peer: Option<&Peer>,
        self_public: bool,
        now: Instant,
    ) -> Option<SocketAddr> {
        let order = endpoints::dial_order(&member.endpoints, self_public);
        if order.is_empty() {
            // Nothing to dial; the peer dials us
            return None;
        }
        if peer.is_some_and(is_fresh) {
            // A live session; its endpoint may be one roaming taught us, better than ours
            self.rotation.remove(&member.wg_key);
            return None;
        }
        let current = peer.and_then(|p| p.endpoint);
        let rotation = self.rotation.entry(member.wg_key).or_insert(Rotation { index: 0, since: now });
        let position = current.and_then(|c| order.iter().position(|o| *o == c));
        match position {
            // Still on a candidate: move on once it has had its chance
            Some(i) if now.duration_since(rotation.since) < self.rotate_after => {
                rotation.index = i;
                None
            }
            Some(i) => {
                rotation.index = (i + 1) % order.len();
                rotation.since = now;
                (order.len() > 1).then(|| order[rotation.index])
            }
            // A new peer, or its current endpoint is no candidate (anymore)
            None => {
                rotation.index = 0;
                rotation.since = now;
                Some(order[0])
            }
        }
    }
}

pub fn is_fresh(peer: &Peer) -> bool {
    peer.last_handshake.and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|age| age < HANDSHAKE_FRESH)
}

fn allowed_ip(net: IpNet) -> WgAllowedIp {
    let family = if net.addr().is_ipv4() { AF_INET } else { AF_INET6 };
    WgAllowedIp(vec![
        WgAllowedIpAttrs::Family(family),
        WgAllowedIpAttrs::IpAddr(net.addr()),
        WgAllowedIpAttrs::Cidr(net.prefix_len()),
    ])
}

/// Sends `attrs` to the interface in one `WG_CMD_SET_DEVICE`; what it leaves out stays as is
fn set_device(interface: &InterfaceName, mut attrs: Vec<WgDeviceAttrs>) -> io::Result<()> {
    attrs.insert(0, WgDeviceAttrs::IfName(interface.to_string()));
    let message = GenlMessage::from_payload(Wireguard { cmd: WireguardCmd::SetDevice, nlas: attrs });
    netlink_request_genl(message, Some(NLM_F_REQUEST | NLM_F_ACK))?;
    Ok(())
}

/// Reads the interface. The kernel answers with a dump that splits large peer lists across
/// messages, and a peer with many allowed IPs across two of them (repeating its key).
fn get_device(interface: &InterfaceName) -> io::Result<Device> {
    let message = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(interface.to_string())],
    });
    let responses = netlink_request_genl(message, Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP))?;
    let mut device = Device { private_key: None, peers: vec![] };
    let attrs = responses.into_iter().filter_map(|r| match r.payload {
        NetlinkPayload::InnerMessage(message) => Some(message.payload.nlas),
        _ => None,
    });
    for attr in attrs.flatten() {
        match attr {
            WgDeviceAttrs::PrivateKey(key) if key != [0; 32] => device.private_key = Some(PrivateKey(key)),
            WgDeviceAttrs::Peers(peers) => {
                for peer in peers.into_iter().filter_map(parse_peer) {
                    match device.peers.last_mut() {
                        Some(last) if last.public_key == peer.public_key => last.allowed_ips.extend(peer.allowed_ips),
                        _ => device.peers.push(peer),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(device)
}

fn parse_peer(peer: WgPeer) -> Option<Peer> {
    let mut public_key = None;
    let mut parsed =
        Peer { public_key: PubKey([0; 32]), endpoint: None, keepalive: 0, allowed_ips: vec![], last_handshake: None };
    for attr in peer.0 {
        match attr {
            WgPeerAttrs::PublicKey(key) => public_key = Some(PubKey(key)),
            WgPeerAttrs::Endpoint(endpoint) => parsed.endpoint = Some(endpoint),
            WgPeerAttrs::PersistentKeepalive(secs) => parsed.keepalive = secs,
            // Zero when the peer never completed a handshake
            WgPeerAttrs::LastHandshake(time) if time > UNIX_EPOCH => parsed.last_handshake = Some(time),
            WgPeerAttrs::AllowedIps(ips) => parsed.allowed_ips.extend(ips.iter().filter_map(parse_allowed_ip)),
            _ => {}
        }
    }
    parsed.public_key = public_key?;
    Some(parsed)
}

fn parse_allowed_ip(ip: &WgAllowedIp) -> Option<IpNet> {
    let addr = ip.iter().find_map(|a| match a {
        WgAllowedIpAttrs::IpAddr(addr) => Some(*addr),
        _ => None,
    })?;
    let cidr = ip.iter().find_map(|a| match a {
        WgAllowedIpAttrs::Cidr(cidr) => Some(*cidr),
        _ => None,
    })?;
    IpNet::new(addr, cidr).ok()
}
