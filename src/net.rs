//! Interface addresses, link state and local address discovery over rtnetlink.
//!
//! Adapted from innernet's `shared/src/netlink.rs` (MIT, Copyright (c) 2021 tonari株式会社, 一般社団法人tonari), using
//! the same netlink crates as the WireGuard side in `wg.rs` so both speak one netlink version.

use std::ffi::c_char;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{self, AddressHeader, AddressMessage};
use netlink_packet_route::link::{self, InfoKind, LinkFlags, LinkHeader, LinkInfo, LinkMessage, State};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_request::netlink_request_rtnl;

/// A network interface name as the kernel accepts it, kept NUL-terminated for libc
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceName([u8; libc::IFNAMSIZ]);

impl InterfaceName {
    pub fn as_str(&self) -> &str {
        let len = self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len());
        // Only ever built from a &str, cut at a NUL
        std::str::from_utf8(&self.0[..len]).unwrap_or_default()
    }

    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }
}

impl FromStr for InterfaceName {
    type Err = anyhow::Error;

    /// The kernel's rules (`dev_valid_name`): up to 15 bytes, no slash, colon or whitespace
    fn from_str(name: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !name.is_empty()
                && name.len() < libc::IFNAMSIZ
                && name != "."
                && name != ".."
                && !name.bytes().any(|b| b == b'/' || b == b':' || b == 0 || b.is_ascii_whitespace()),
            "{name:?} is not a valid interface name"
        );
        let mut bytes = [0; libc::IFNAMSIZ];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self(bytes))
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

fn if_nametoindex(interface: &InterfaceName) -> io::Result<u32> {
    match unsafe { libc::if_nametoindex(interface.as_ptr()) } {
        0 => Err(io::Error::new(io::ErrorKind::NotFound, format!("couldn't find interface '{interface}'"))),
        index => Ok(index),
    }
}

pub fn exists(interface: &InterfaceName) -> bool {
    if_nametoindex(interface).is_ok()
}

/// Creates a kernel WireGuard interface called `interface`
pub fn add_wireguard(interface: &InterfaceName) -> io::Result<()> {
    let mut message = LinkMessage::default();
    message.attributes = vec![
        link::LinkAttribute::IfName(interface.to_string()),
        link::LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wireguard)]),
    ];
    match netlink_request_rtnl(RouteNetlinkMessage::NewLink(message), None) {
        // Created in the meantime
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        other => other.map(|_| ()),
    }
}

pub fn set_up(interface: &InterfaceName, mtu: u32) -> io::Result<()> {
    let mut message = LinkMessage::default();
    message.header = LinkHeader {
        index: if_nametoindex(interface)?,
        flags: LinkFlags::Up,
        change_mask: LinkFlags::Up,
        ..Default::default()
    };
    message.attributes = vec![link::LinkAttribute::Mtu(mtu)];
    netlink_request_rtnl(RouteNetlinkMessage::SetLink(message), None)?;
    Ok(())
}

fn address_message(interface: &InterfaceName, addr: IpNet) -> io::Result<AddressMessage> {
    let index = if_nametoindex(interface)?;
    let (family, attributes) = match addr {
        IpNet::V4(network) => {
            let ip = IpAddr::V4(network.addr());
            (AddressFamily::Inet, vec![address::AddressAttribute::Local(ip), address::AddressAttribute::Address(ip)])
        }
        IpNet::V6(network) => {
            (AddressFamily::Inet6, vec![address::AddressAttribute::Address(IpAddr::V6(network.addr()))])
        }
    };
    let mut message = AddressMessage::default();
    message.header = AddressHeader {
        index,
        family,
        prefix_len: addr.prefix_len(),
        scope: address::AddressScope::Universe,
        ..Default::default()
    };
    message.attributes = attributes;
    Ok(message)
}

pub fn set_addr(interface: &InterfaceName, addr: IpNet) -> io::Result<()> {
    netlink_request_rtnl(
        RouteNetlinkMessage::NewAddress(address_message(interface, addr)?),
        Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE),
    )?;
    Ok(())
}

pub fn del_addr(interface: &InterfaceName, addr: IpNet) -> io::Result<()> {
    match netlink_request_rtnl(RouteNetlinkMessage::DelAddress(address_message(interface, addr)?), None) {
        // Already gone
        Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(()),
        other => other.map(|_| ()),
    }
}

/// Names of the links that are up, except loopback and `exclude` (our own WireGuard interface)
fn up_links(exclude: &InterfaceName) -> io::Result<Vec<String>> {
    let exclude = exclude.as_str();
    let responses =
        netlink_request_rtnl(RouteNetlinkMessage::GetLink(LinkMessage::default()), Some(NLM_F_DUMP | NLM_F_REQUEST))?;
    Ok(responses
        .into_iter()
        .filter_map(|response| match response {
            NetlinkMessage { payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)), .. } => {
                Some(link)
            }
            _ => None,
        })
        .filter(|link| !link.header.flags.contains(LinkFlags::Loopback))
        .filter(|link| {
            // Container veths report "unknown", physical and virtual NICs "up"
            link.attributes.iter().any(|a| matches!(a, link::LinkAttribute::OperState(State::Up | State::Unknown)))
        })
        .filter_map(|link| {
            link.attributes.iter().find_map(|a| match a {
                link::LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            })
        })
        .filter(|name| *name != exclude)
        .collect())
}

/// Every global-scope address on the host, with its link's index
fn global_addrs() -> io::Result<Vec<(u32, IpNet)>> {
    let responses = netlink_request_rtnl(
        RouteNetlinkMessage::GetAddress(AddressMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    Ok(responses
        .into_iter()
        .filter_map(|response| match response {
            NetlinkMessage { payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)), .. } => {
                Some(addr)
            }
            _ => None,
        })
        .filter(|addr| addr.header.scope == address::AddressScope::Universe)
        .filter_map(|addr| {
            addr.attributes.iter().find_map(|a| match a {
                address::AddressAttribute::Address(ip) => {
                    IpNet::new(*ip, addr.header.prefix_len).ok().map(|net| (addr.header.index, net))
                }
                _ => None,
            })
        })
        .collect())
}

/// Global-scope addresses of the links that are up, except `exclude`
pub fn local_addrs(exclude: &InterfaceName) -> io::Result<Vec<IpAddr>> {
    let link_indices: Vec<u32> = up_links(exclude)?
        .iter()
        .filter_map(|name| name.parse::<InterfaceName>().ok())
        .filter_map(|name| if_nametoindex(&name).ok())
        .collect();
    Ok(global_addrs()?
        .into_iter()
        .filter(|(index, _)| link_indices.contains(index))
        .map(|(_, net)| net.addr())
        .collect())
}

/// The addresses on `interface`
pub fn interface_addrs(interface: &InterfaceName) -> io::Result<Vec<IpNet>> {
    let index = if_nametoindex(interface)?;
    Ok(global_addrs()?.into_iter().filter(|(i, _)| *i == index).map(|(_, net)| net).collect())
}
