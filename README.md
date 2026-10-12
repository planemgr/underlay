# underlay

A WireGuard full mesh between nodes on any network: cloud servers with public IPs, VMs behind
NAT, nodes an autoscaler creates later. Nodes find each other through a record on the Mainline
DHT ([pkarr](https://github.com/pubky/pkarr)), so there is no DNS zone, coordination server or
account to set up: a node needs the cluster's join token and nothing else. The kernel does the
WireGuard; `underlay` only decides who peers with whom and at which address.

Linux only (kernel WireGuard over netlink). Status: draft.

## How it works

Every node runs the same code, and every node holding the join token is trusted, as with a
k3s join token. A node compromised at the OS level has the node's traffic and credentials
anyway; the design doesn't try to defend against token holders.

```
        Mainline DHT: cluster record = a few entry points (encrypted, signed)
               ▲ publish (public nodes)          │ resolve
               │                                 ▼
   ┌────────┐ gossip ┌────────┐  admission (TCP, Noise XKpsk0)  ┌──────────┐
   │ node A │◄──────►│ node B │◄────────────────────────────────│ new node │
   └────────┘  over  └────────┘                                 └──────────┘
        ▲    WireGuard   ▲   push of the new member to everyone
        └────────────────┘
```

- **One secret.** HKDF derives everything from the join token: the ed25519 key that names and
  signs the cluster record, the key that encrypts it, and the admission handshake's pre-shared
  key. The token also carries the mesh's address range, so no two nodes can disagree on it.
- **Joining.** A node asks any member to admit it: one it still knows from before, or an entry
  point from the record. The admission is a Noise `XKpsk0` handshake over TCP: the member's
  static key is its WireGuard key (from the record or the roster), so an impostor can't answer;
  the node's static key is the WireGuard key it registers, so it proves it holds it, and its
  request can't be replayed; the pre-shared key means members only answer token holders. The member adds the node to its
  roster, pushes it to every other member and answers with the node's mesh address. The node
  then pulls the whole roster from it over the tunnel.
- **Gossip.** Every interval each node exchanges rosters with one random peer over the mesh,
  which delivers whatever a push missed, and carries heartbeats and endpoint changes. The mesh
  API is bound to the WireGuard interface, so the caller's mesh address is its identity.
- **The roster** is a mergeable set: per name, the identity (key, address, removal) is
  last-writer-wins by the changing node's clock, heartbeats only grow, removals are tombstones.
  Nodes converge without a leader or consensus.
- **Mesh addresses are hashes of node names**, so a name gets the same address after a reboot,
  under a new key, and even after every node lost its state. If two names hash to one address,
  the one that joined first keeps it and the other moves itself to its next hash.
- **No state outside the kernel.** The WireGuard interface outlives the daemon, so a restarted
  daemon adopts its key and gets the roster back from one of its peers; the tunnels don't
  notice. A reboot takes the interface with it: the node rejoins under the same name with a new
  key and gets the same address. A name can change keys at most once per cooldown (a minute), so
  two live nodes accidentally sharing a name trade it slowly and log it, instead of thrashing.
- **The record** lists up to 6 entry points. Nodes with a public address add themselves while
  there's room and refresh their entry; stale ones drop out. When no member answers a joining
  node with a public address, it starts the cluster itself (seeds it). If two nodes seed at
  once, each finds the other in the record, asks it for admission and the rosters merge.
- **Expiry.** A node without a heartbeat for a day is removed. Its tombstone keeps its address,
  so it gets the same one back when it returns.

### Which addresses get dialed

Every node reports its interfaces' addresses.

- A node **with a public address** is only ever dialed at public addresses. Its private ones (a
  provider network, a container bridge) are never tried: they may belong to an unrelated host on
  the dialer's own network.
- A node **behind NAT** sends keepalives to every peer, so its NAT mapping stays open and public
  peers never need to dial it. Peers behind NAT too try its private addresses (they may share a
  LAN, like VMs on one libvirt host).
- A peer without a live session is cycled through its addresses; an endpoint WireGuard learned
  from a live session (roaming) is never overwritten.

Two nodes behind different NATs don't connect to each other yet (see below).

## Installing

Every release has static binaries and deb, rpm and apk packages (amd64, arm64). The packages
install a systemd unit (an OpenRC service on Alpine) that reads its settings from
`/etc/underlay/underlay.conf`. The service is not enabled on install; set the join token, then:

```sh
systemctl enable --now underlay                          # Debian, Ubuntu, Fedora, RHEL, SUSE
rc-update add underlay default && rc-service underlay start   # Alpine
```

The packages aren't signed yet, so Alpine needs `apk add --allow-untrusted`.

## Running

`underlay` is a daemon without a command line. Everything comes from environment variables
(cloud-init writes them to the systemd unit's `EnvironmentFile`); it needs `CAP_NET_ADMIN`.

| Variable                                               | Default               |                                                                                |
| ------------------------------------------------------ | --------------------- | ------------------------------------------------------------------------------ |
| `UNDERLAY_JOIN_TOKEN`                                  | required              | `ul2:<32 random bytes, base64>:<mesh CIDR>`                                    |
| `UNDERLAY_NAME`                                        | host name             | unique in the cluster, a DNS label                                             |
| `UNDERLAY_ADVERTISE`                                   |                       | extra addresses peers can dial (a 1:1 NAT's public IP)                         |
| `UNDERLAY_INTERFACE`                                   | `underlay0`           |                                                                                |
| `UNDERLAY_LISTEN_PORT`, `_ADMISSION_PORT`, `_API_PORT` | 51820, 51821, 51822   | the same on every node                                                         |
| `UNDERLAY_ADMISSION_PER_MINUTE`                        | 30                    | admission connections per source address (IPv6: per /64), in bursts of as many |
| `UNDERLAY_DHT_BOOTSTRAP`                               | public Mainline nodes | `host:port,...`, for a private DHT                                             |

The token is generated once per cluster, for example in Terraform or OpenTofu:

```hcl
resource "random_bytes" "underlay" { length = 32 }
locals { underlay_token = "ul2:${random_bytes.underlay.base64}:100.64.0.0/10" }
```

To see what a node is doing, look at the kernel (`wg show underlay0`, `ip addr show underlay0`)
and the daemon's log.

| Port  | Protocol | Where               | Open to                                                                   |
| ----- | -------- | ------------------- | ------------------------------------------------------------------------- |
| 51820 | UDP      | every node          | everyone (WireGuard ignores unauthenticated packets)                      |
| 51821 | TCP      | every node          | everyone (admission; answers token holders only, rate limited per source) |
| 51822 | TCP      | mesh addresses only | nothing outside the mesh                                                  |

The default mesh range is `100.64.0.0/10` (carrier-grade NAT space, as Tailscale uses): it
doesn't overlap k3s (`10.42.0.0/16`, `10.43.0.0/16`) or common provider private networks. A node
whose own network uses that range needs another one.

## Development

```sh
docker run --rm -v "$PWD":/src -w /src rust:1.97-slim-trixie cargo test
e2e/docker/test.sh   # end to end: 3 public nodes, 2 behind a NAT router, one joining late
```

The end-to-end test runs on a private DHT (`examples/dht_node.rs`) and covers the full mesh
(including NAT to NAT on a shared LAN), daemon restarts keeping keys and tunnels, reboots with new
keys keeping their addresses, joining while a node is down, and the whole cluster rebooting at
once. It uses kernel WireGuard, so it needs a Docker host whose kernel
has it.

`src/net.rs` is adapted from innernet (MIT), and netlink requests go through its
`netlink-request` crate.
