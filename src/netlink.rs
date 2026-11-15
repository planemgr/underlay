//! Blocking netlink requests: send one message, collect the replies until the kernel is done.
//!
//! Adapted from innernet's `netlink-request` crate (MIT, Copyright (c) 2021 tonari株式会社, 一般社団法人tonari),
//! which stayed on an old netlink-packet release; this is the same request/reply loop over the current crates.

use std::fmt::Debug;
use std::io;

use netlink_packet_core::{
    Emitable, NLM_F_ACK, NLM_F_REQUEST, NLMSG_ALIGNTO, NetlinkDeserializable, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, NetlinkSerializable, ParseableParametrized,
};
use netlink_packet_generic::ctrl::nlas::GenlCtrlAttrs;
use netlink_packet_generic::ctrl::{GenlCtrl, GenlCtrlCmd};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::protocols::{NETLINK_GENERIC, NETLINK_ROUTE};
use netlink_sys::{Socket, SocketAddr};

/// Netlink expects requests to fit "8 KiB or a page, whichever is bigger"
/// (https://docs.kernel.org/userspace-api/netlink/intro.html#buffer-sizing)
fn max_request_len() -> usize {
    // SAFETY: sysconf only reads a configuration value
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page).unwrap_or(0).max(8 * 1024)
}

/// Sends `message` on the rtnetlink socket
pub fn route(message: RouteNetlinkMessage, flags: u16) -> io::Result<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
    request(message, flags, NETLINK_ROUTE)
}

/// Sends `message` to its generic netlink family, looking the family's id up first
pub fn generic<F>(mut message: GenlMessage<F>, flags: u16) -> io::Result<Vec<NetlinkMessage<GenlMessage<F>>>>
where
    F: GenlFamily + Emitable + ParseableParametrized<[u8], GenlHeader> + Debug,
{
    if message.family_id() == 0 {
        message.set_resolved_family_id(family_id(F::family_name())?);
    }
    request(message, flags, NETLINK_GENERIC)
}

/// The id the kernel gave the generic netlink family `name`; ENOENT when it isn't registered
/// (for WireGuard: the module isn't loaded)
fn family_id(name: &str) -> io::Result<u16> {
    let message = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(name.to_string())],
    });
    let responses = request(message, NLM_F_REQUEST | NLM_F_ACK, NETLINK_GENERIC)?;
    responses
        .into_iter()
        .find_map(|response| match response.payload {
            NetlinkPayload::InnerMessage(GenlMessage { payload: GenlCtrl { nlas, .. }, .. }) => {
                nlas.into_iter().find_map(|attr| match attr {
                    GenlCtrlAttrs::FamilyId(id) => Some(id),
                    _ => None,
                })
            }
            _ => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no generic netlink family {name:?}")))
}

/// Sends `message` with `flags` over a fresh `protocol` socket and returns every reply up to the
/// closing ACK or `NLMSG_DONE`. A NACK becomes the `io::Error` of its errno.
fn request<I>(message: I, flags: u16, protocol: isize) -> io::Result<Vec<NetlinkMessage<I>>>
where
    I: NetlinkSerializable + NetlinkDeserializable + Debug,
{
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    let mut request = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(message));
    request.finalize();
    let len = request.buffer_len();
    let max = max_request_len();
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("netlink request of {len} bytes is over the {max} byte limit"),
        ));
    }
    let mut buf = vec![0; len];
    request.serialize(&mut buf);

    let socket = Socket::new(protocol)?;
    socket.connect(&SocketAddr::new(0, 0))?;
    if socket.send(&buf, 0)? != len {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "netlink request sent partially"));
    }

    let mut responses = vec![];
    loop {
        // Dumps arrive over several datagrams; each is read whole, whatever its size
        let (datagram, _) = socket.recv_from_full()?;
        let mut offset = 0;
        while offset < datagram.len() {
            let response = NetlinkMessage::<I>::deserialize(&datagram[offset..])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let length = response.header.length as usize;
            match response.payload {
                NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.into()),
                NetlinkPayload::Done(_) | NetlinkPayload::Error(_) => return Ok(responses),
                _ => responses.push(response),
            }
            if length == 0 {
                break;
            }
            // Messages in a datagram start on 4-byte boundaries
            offset += length.next_multiple_of(usize::from(NLMSG_ALIGNTO));
        }
    }
}
