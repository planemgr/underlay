//! Which addresses a node is dialed at.
//!
//! Every node reports the addresses of its own interfaces (with its WireGuard port). A node with
//! a public address of its own is only ever dialed at public addresses; its private ones (a
//! provider's private network, a container bridge) may be reachable by nobody else and may even
//! belong to an unrelated host on the dialer's own network. A node without one sits behind NAT:
//! peers behind NAT too try its private addresses (they may share its LAN), public peers wait
//! for it to dial them, which its keepalive makes sure of.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Whether an address can be reached from the internet at all. Documentation ranges
/// (198.51.100.0/24, 2001:db8::/32, ...) count as public, so test networks can use them.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(ip),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        // Shared address space (carrier-grade NAT), RFC 6598
        || (a == 100 && (64..128).contains(&b))
        // Benchmarking, RFC 2544
        || (a == 198 && (b == 18 || b == 19))
        // Reserved for future use (240/4)
        || a >= 240
        || a == 0)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // Unique local, fc00::/7
        || (first & 0xfe00) == 0xfc00
        // Link local, fe80::/10
        || (first & 0xffc0) == 0xfe80)
}

/// Whether a node with these addresses has a public one of its own (it is not behind NAT)
pub fn has_public(addrs: &[SocketAddr]) -> bool {
    addrs.iter().any(|a| is_public(a.ip()))
}

/// The endpoints to try for a peer with addresses `addrs`, in order, from a dialer that is
/// (`self_public`) or is not behind NAT. Empty means don't dial: the peer dials us.
pub fn dial_order(addrs: &[SocketAddr], self_public: bool) -> Vec<SocketAddr> {
    if has_public(addrs) {
        addrs.iter().filter(|a| is_public(a.ip())).copied().collect()
    } else if !self_public {
        // Both behind NAT: the private addresses work when we share a network
        addrs.to_vec()
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "198.51.100.7", "2a01:4f8::1", "100.128.0.1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn public_peer_is_never_dialed_privately() {
        let addrs = [sa("10.0.0.5:51820"), sa("203.0.113.10:51820")];
        assert_eq!(dial_order(&addrs, true), vec![sa("203.0.113.10:51820")]);
        assert_eq!(dial_order(&addrs, false), vec![sa("203.0.113.10:51820")]);
    }

    #[test]
    fn nat_peer() {
        let addrs = [sa("192.168.122.10:51820")];
        // A public dialer waits for it
        assert!(dial_order(&addrs, true).is_empty());
        // Another node behind NAT tries the shared network
        assert_eq!(dial_order(&addrs, false), vec![sa("192.168.122.10:51820")]);
    }
}
