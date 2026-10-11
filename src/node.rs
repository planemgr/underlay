//! The daemon. Every node runs the same code:
//!
//! - **join**: get admitted by a node that already is a member, found in the roster we still
//!   hold or in the cluster record. When nobody answers, a node with a public address starts
//!   the cluster itself (seeds it).
//! - **admit**: answer other nodes' admission requests and push the new member to everyone.
//! - **gossip**: exchange rosters with a random peer every interval, so whatever a push missed
//!   still reaches everyone; heartbeats and endpoint changes travel this way too.
//! - **record**: keep the cluster record listing a few entry points, and ask entry points we
//!   don't know to admit us, which merges partitions (two seeds, say).
//! - **reconcile**: keep the WireGuard peers in line with the roster.
//!
//! The daemon keeps no state of its own. The WireGuard interface is left up at exit, and on
//! start the daemon adopts its key and gets the roster back from one of its peers, so a daemon
//! restart doesn't disturb the tunnels. A reboot takes the interface with it: the node rejoins
//! under the same name with a new key and gets the same mesh address back.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use rand::seq::SliceRandom;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::endpoints::{has_public, is_public};
use crate::net::InterfaceName;
use crate::proto::{AdmissionRequest, AdmissionResponse, ApiRequest, ApiResponse};
use crate::record::{Discovery, EntryPoint, MAX_ENTRY_POINTS};
use crate::roster::{Claim, Member, Roster};
use crate::token::JoinToken;
use crate::util::{PubKey, now_millis, now_secs};
use crate::wg::PrivateKey;
use crate::{admission, api, wg};

/// At most this many local addresses are reported per node
const MAX_ENDPOINTS: usize = 8;
/// Join rounds without an answer before a node with a public address seeds a new cluster,
/// when the record lists entry points (none answering may be our own network's fault)
const SEED_AFTER_ROUNDS: u32 = 3;
/// Peers tried per gossip round
const GOSSIP_TRIES: usize = 3;

pub struct Settings {
    pub name: String,
    pub interface: InterfaceName,
    pub listen_port: u16,
    pub mtu: u32,
    pub token: JoinToken,
    pub admission_port: u16,
    /// Admission connections each source address (IPv6: each /64) may open a minute
    pub admission_per_minute: u32,
    pub api_port: u16,
    pub dht_bootstrap: Vec<String>,
    /// Addresses to report besides the interfaces' own (a public IP NATed 1:1 to the node)
    pub advertise: Vec<IpAddr>,
    pub timings: Timings,
}

pub struct Timings {
    /// How often a node exchanges rosters with a random peer
    pub gossip: Duration,
    /// How often a node reads the cluster record
    pub record: Duration,
    /// Entry points not refreshed for this long are dropped from the record; each refreshes
    /// its own entry every third of it
    pub entry_ttl: Duration,
    /// How often peers and endpoints are reconciled
    pub tick: Duration,
    /// How long a peer gets on one endpoint before the next one is tried
    pub rotate: Duration,
    /// How often a name may change keys (two nodes sharing a name trade it this slowly)
    pub cooldown: Duration,
    /// How long a node may go without a heartbeat before it is removed
    pub expire_after: Duration,
}

struct Node {
    s: Settings,
    private_key: PrivateKey,
    public_key: PubKey,
    discovery: Discovery,
    inner: Mutex<Inner>,
    wake: Notify,
}

struct Inner {
    roster: Roster,
    iface: wg::Interface,
    /// The address the interface carries
    address: Option<IpNet>,
}

pub async fn run(s: Settings) -> Result<()> {
    let iface = wg::Interface::new(s.interface, s.timings.rotate);
    // An interface left by an earlier run: keep its key, so its tunnels stay up
    let (private_key, previous_peers) = match iface.existing() {
        Some((key, peers)) => {
            info!("adopting the running interface {} and its {} peers", s.interface, peers.len());
            (key, peers)
        }
        None => (PrivateKey::generate(), vec![]),
    };
    let public_key = private_key.public();
    let discovery = Discovery::new(s.token.clone(), &s.dht_bootstrap)?;
    info!("node {} with key {public_key}, mesh {}", s.name, s.token.mesh_cidr);

    // The mesh API listener binds to the interface, so it has to exist first
    iface.configure(&private_key, s.listen_port)?;
    let node = Arc::new(Node {
        private_key,
        public_key,
        discovery,
        inner: Mutex::new(Inner { roster: Roster::default(), iface, address: None }),
        wake: Notify::new(),
        s,
    });

    // Dual-stack where IPv6 is available, IPv4 only otherwise
    let listener = match TcpListener::bind(SocketAddr::new(IpAddr::from([0u8; 16]), node.s.admission_port)).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(SocketAddr::new(IpAddr::from([0u8; 4]), node.s.admission_port))
            .await
            .context("binding the admission port")?,
    };
    let admitter = node.clone();
    tokio::spawn(admission::serve(
        listener,
        node.private_key.0,
        node.s.token.clone(),
        node.s.admission_per_minute,
        move |req, from| admitter.admit(req, from),
    ));

    let any = match node.s.token.mesh_cidr {
        IpNet::V4(_) => IpAddr::from([0u8; 4]),
        IpNet::V6(_) => IpAddr::from([0u8; 16]),
    };
    let listener = api::bind(SocketAddr::new(any, node.s.api_port), node.s.interface.as_str())?;
    let handler = node.clone();
    tokio::spawn(api::serve(listener, move |req, from| handler.handle_api(req, from)));

    let n = node.clone();
    tokio::spawn(async move {
        n.recover(&previous_peers).await;
        n.membership_loop().await
    });
    let n = node.clone();
    tokio::spawn(async move { n.record_loop().await });
    let n = node.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = n.reconcile() {
                warn!("reconcile failed: {e:#}");
            }
            tokio::select! {
                _ = sleep(n.s.timings.tick) => {}
                _ = n.wake.notified() => {}
            }
        }
    });

    shutdown_signal().await;
    info!("stopping; the interface and its peers stay up");
    Ok(())
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

impl Node {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Our own live entry, if we are a member
    fn me(&self, inner: &Inner) -> Option<Member> {
        inner.roster.get(&self.s.name).filter(|m| !m.removed && m.wg_key == self.public_key).cloned()
    }

    fn is_member(&self) -> bool {
        self.me(&self.lock()).is_some()
    }

    /// This node's addresses with its WireGuard port, advertised ones first
    fn local_endpoints(&self) -> Vec<SocketAddr> {
        let mut ips = self.s.advertise.clone();
        match crate::net::local_addrs(&self.s.interface) {
            Ok(addrs) => ips.extend(addrs),
            Err(e) => warn!("listing local addresses failed: {e}"),
        }
        let mut out: Vec<SocketAddr> = Vec::new();
        for ip in ips {
            let addr = SocketAddr::new(ip, self.s.listen_port);
            if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !out.contains(&addr) {
                out.push(addr);
            }
        }
        out.truncate(MAX_ENDPOINTS);
        out
    }

    /// An entry point for the record: a node's public endpoints only
    fn entry_point(&self, name: &str, wg_key: PubKey, endpoints: &[SocketAddr], updated: u64) -> EntryPoint {
        EntryPoint {
            name: name.to_string(),
            wg_key: wg_key.0,
            endpoints: endpoints.iter().filter(|a| is_public(a.ip())).copied().collect(),
            admission_port: self.s.admission_port,
            updated,
        }
    }

    // Reconcile

    /// Keeps our entry and the interface in line with the roster
    fn reconcile(&self) -> Result<()> {
        let local = self.local_endpoints();
        let self_public = has_public(&local);
        let now = now_millis();
        let mesh = self.s.token.mesh_cidr;

        let mut inner = self.lock();
        if self.me(&inner).is_none() {
            return Ok(());
        }
        let name = self.s.name.clone();
        inner.roster.set_endpoints(&name, local, now);
        if let Some(ip) = inner.roster.resolve_conflict(&name, mesh, now) {
            warn!("an older node holds our mesh address; moving to {ip}");
        }
        let me = self.me(&inner).expect("checked above");

        let address = IpNet::new(me.mesh_ip, mesh.prefix_len())?;
        if inner.address != Some(address) {
            inner.iface.configure(&self.private_key, self.s.listen_port)?;
            inner.iface.set_address(address, self.s.mtu)?;
            inner.address = Some(address);
        }

        // Of members contesting an address, only its owner is a peer until the other one moves
        let peers: Vec<Member> = inner
            .roster
            .live()
            .filter(|m| m.name != name && m.wg_key != self.public_key)
            .filter(|m| inner.roster.owner(m.mesh_ip).is_some_and(|o| o.name == m.name))
            .cloned()
            .collect();
        let refs: Vec<&Member> = peers.iter().collect();
        if let Err(e) = inner.iface.reconcile(&refs, self_public) {
            // Set up again on the next tick, in case the interface was deleted
            inner.address = None;
            return Err(e);
        }
        Ok(())
    }

    // Admission

    fn admit(&self, req: AdmissionRequest, from: SocketAddr) -> AdmissionResponse {
        let refuse = |reason: String| {
            warn!("refused admission of {:?} from {from}: {reason}", req.name);
            AdmissionResponse::Refused { reason }
        };
        if req.wg_key == self.public_key || req.name == self.s.name {
            return refuse("that is this node".into());
        }

        let now = now_millis();
        let mut inner = self.lock();
        let Some(admitter) = self.me(&inner) else {
            drop(inner);
            return refuse("this node isn't a member yet".into());
        };
        let previous = inner.roster.get(&req.name).filter(|m| !m.removed).map(|m| m.wg_key);
        let endpoints = req.endpoints.into_iter().take(MAX_ENDPOINTS).collect();
        let claim = Claim { name: &req.name, wg_key: req.wg_key, endpoints, hint: req.hint };
        match inner.roster.admit(claim, self.s.token.mesh_cidr, now, self.s.timings.cooldown) {
            Ok(member) => {
                drop(inner);
                match previous {
                    Some(key) if key == member.wg_key => debug!("{} is already a member", member.name),
                    Some(_) => info!("{} rejoined with a new key at {} (from {from})", member.name, member.mesh_ip),
                    None => info!("admitted {} as {} (from {from})", member.name, member.mesh_ip),
                }
                self.wake.notify_one();
                self.push(vec![member.clone()]);
                AdmissionResponse::Accepted { member, admitter }
            }
            Err(r) => {
                drop(inner);
                refuse(r.to_string())
            }
        }
    }

    /// Tells every other member about `changed`, in the background
    fn push(&self, changed: Vec<Member>) {
        let targets: Vec<IpAddr> = {
            let inner = self.lock();
            inner
                .roster
                .live()
                .filter(|m| m.name != self.s.name && !changed.iter().any(|c| c.name == m.name))
                .map(|m| m.mesh_ip)
                .collect()
        };
        let port = self.s.api_port;
        for ip in targets {
            let request = ApiRequest::Sync { members: changed.clone() };
            tokio::spawn(async move {
                if let Err(e) = api::call(SocketAddr::new(ip, port), &request).await {
                    debug!("pushing to {ip} failed: {e:#}");
                }
            });
        }
    }

    fn handle_api(&self, req: ApiRequest, from: IpAddr) -> ApiResponse {
        let ApiRequest::Sync { members } = req;
        let mut inner = self.lock();
        let changed = inner.roster.merge(&members);
        // WireGuard only delivers from a peer's own address, so this is about a stale roster
        if inner.roster.owner(from).is_none() {
            return ApiResponse::Unknown { caller: from };
        }
        let members = inner.roster.to_vec();
        drop(inner);
        if changed {
            self.wake.notify_one();
        }
        ApiResponse::Sync { members }
    }

    // Membership

    /// After a daemon restart: the roster from any peer the interface still has, which makes us
    /// a member again without a new admission
    async fn recover(&self, peers: &[IpAddr]) {
        for ip in peers {
            match self.sync_with(*ip).await {
                Ok(()) if self.is_member() => {
                    info!("recovered the roster from {ip}");
                    return;
                }
                Ok(()) => {}
                Err(e) => debug!("recovering from {ip} failed: {e:#}"),
            }
        }
    }

    /// Joins when we aren't a member, gossips while we are
    async fn membership_loop(self: Arc<Self>) {
        loop {
            if !self.is_member() {
                self.join().await;
            }
            self.gossip().await;
            sleep(self.s.timings.gossip).await;
        }
    }

    /// Admission by any member that answers, retried until it succeeds; seeding the cluster
    /// when nobody answers and we can be reached
    async fn join(&self) {
        let mut backoff = Duration::from_secs(2);
        let mut round = 1;
        loop {
            match self.try_join(round).await {
                Ok(true) => return,
                Ok(false) => debug!("join round {round} failed, retrying in {backoff:?}"),
                Err(e) => warn!("joining failed, retrying in {backoff:?}: {e:#}"),
            }
            round += 1;
            sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    /// One join round. Returns whether we are a member now.
    async fn try_join(&self, round: u32) -> Result<bool> {
        let endpoints = self.local_endpoints();
        let (mut targets, hint) = {
            let inner = self.lock();
            // Members we still know of from before (a daemon restart, an eviction)
            let targets: Vec<EntryPoint> = inner
                .roster
                .live()
                .filter(|m| m.name != self.s.name && has_public(&m.endpoints))
                .map(|m| self.entry_point(&m.name, m.wg_key, &m.endpoints, 0))
                .collect();
            let hint = inner.roster.get(&self.s.name).map(|m| (m.probe, m.first_seen));
            (targets, hint)
        };
        let record = self.discovery.resolve().await;
        let record_empty = matches!(&record, Ok(entries) if entries.is_empty());
        match record {
            Ok(entries) => targets.extend(entries),
            Err(e) => warn!("reading the cluster record failed: {e:#}"),
        }
        targets.retain(|t| t.wg_key != self.public_key.0 && t.name != self.s.name);
        targets.sort_by_key(|t| t.wg_key);
        targets.dedup_by_key(|t| t.wg_key);
        targets.shuffle(&mut rand::thread_rng());

        let request = AdmissionRequest { name: self.s.name.clone(), wg_key: self.public_key, endpoints, hint };
        for target in &targets {
            match self.request_admission(target, &request).await {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) => debug!("admission at {} failed: {e:#}", target.name),
            }
        }

        let reachable = has_public(&request.endpoints);
        if reachable && (record_empty || round > SEED_AFTER_ROUNDS) {
            self.seed(request).await?;
            return Ok(true);
        }
        if targets.is_empty() && !reachable {
            debug!("no member to join yet, and without a public address this node can't start the cluster");
        }
        Ok(false)
    }

    /// Asks `target` to admit us. Returns whether it did; refusals are logged.
    async fn request_admission(&self, target: &EntryPoint, request: &AdmissionRequest) -> Result<bool> {
        let mut last_error = None;
        for addr in target.admission_addrs() {
            match admission::request(addr, target.wg_key, &self.s.token, request).await {
                Ok(AdmissionResponse::Accepted { member, admitter }) => {
                    info!("admitted by {} as {}", admitter.name, member.mesh_ip);
                    {
                        let mut inner = self.lock();
                        inner.roster.merge(&[member, admitter.clone()]);
                    }
                    self.wake.notify_one();
                    // The rest of the roster, right away
                    if let Err(e) = self.sync_with(admitter.mesh_ip).await {
                        debug!("first sync with {} failed: {e:#}", admitter.name);
                    }
                    return Ok(true);
                }
                Ok(AdmissionResponse::Refused { reason }) => {
                    warn!("{} refused to admit us: {reason}", target.name);
                    return Ok(false);
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("{} has no public endpoint", target.name)))
    }

    /// Starts the cluster: admits ourselves and lists ourselves as the only entry point (any
    /// listed ones didn't answer). If another node seeded at the same time, the record loop
    /// merges the two.
    async fn seed(&self, request: AdmissionRequest) -> Result<()> {
        let entry_point = self.entry_point(&self.s.name, self.public_key, &request.endpoints, now_secs());
        {
            let mut inner = self.lock();
            let claim =
                Claim { name: &self.s.name, wg_key: self.public_key, endpoints: request.endpoints, hint: request.hint };
            let me = inner
                .roster
                .admit(claim, self.s.token.mesh_cidr, now_millis(), Duration::ZERO)
                .map_err(|r| anyhow!("can't admit ourselves: {r}"))?;
            warn!("no member answered; starting the cluster as {}", me.mesh_ip);
        }
        self.wake.notify_one();
        self.discovery.publish(&[entry_point]).await
    }

    /// Exchanges rosters with a random peer (ones with a live session first), heartbeat
    /// included, and expires silent nodes
    async fn gossip(&self) {
        let now = now_millis();
        let peers: Vec<(String, IpAddr)> = {
            let mut inner = self.lock();
            let name = self.s.name.clone();
            inner.roster.heartbeat(&name, now);
            let expired = inner.roster.expire(&name, now, self.s.timings.expire_after);
            if !expired.is_empty() {
                info!("removed silent nodes: {}", expired.join(", "));
            }
            let fresh: Vec<PubKey> = inner
                .iface
                .device()
                .map(|d| d.peers.iter().filter(|p| wg::is_fresh(p)).map(|p| p.public_key).collect())
                .unwrap_or_default();
            let mut peers: Vec<(bool, String, IpAddr)> = inner
                .roster
                .live()
                .filter(|m| m.name != self.s.name)
                .map(|m| (fresh.contains(&m.wg_key), m.name.clone(), m.mesh_ip))
                .collect();
            peers.shuffle(&mut rand::thread_rng());
            peers.sort_by_key(|(fresh, ..)| !fresh);
            peers.into_iter().map(|(_, name, ip)| (name, ip)).collect()
        };

        for (name, ip) in peers.into_iter().take(GOSSIP_TRIES) {
            match self.sync_with(ip).await {
                Ok(()) => break,
                Err(e) => debug!("gossip with {name} failed: {e:#}"),
            }
        }

        let inner = self.lock();
        if self.me(&inner).is_none() {
            match inner.roster.get(&self.s.name) {
                Some(m) if !m.removed => warn!("another key holds our name (two nodes named {}?); rejoining", m.name),
                Some(_) => warn!("we were removed from the cluster; rejoining"),
                None => {}
            }
        }
    }

    /// One roster exchange with the node at `ip`
    async fn sync_with(&self, ip: IpAddr) -> Result<()> {
        let members = self.lock().roster.to_vec();
        match api::call(SocketAddr::new(ip, self.s.api_port), &ApiRequest::Sync { members }).await? {
            ApiResponse::Sync { members } => {
                let changed = self.lock().roster.merge(&members);
                if changed {
                    self.wake.notify_one();
                }
                Ok(())
            }
            ApiResponse::Unknown { .. } => Err(anyhow!("{ip} doesn't know us")),
        }
    }

    // Record

    /// Reads the record every interval: asks entry points we don't know to admit us (merging
    /// partitions) and lists ourselves while there is room, or refreshes our entry
    async fn record_loop(self: Arc<Self>) {
        loop {
            sleep(self.s.timings.record).await;
            if !self.is_member() {
                continue;
            }
            match self.discovery.resolve().await {
                Ok(entries) => {
                    self.merge_partitions(&entries).await;
                    if let Err(e) = self.maybe_publish(&entries).await {
                        warn!("publishing the cluster record failed: {e:#}");
                    }
                }
                Err(e) => warn!("reading the cluster record failed: {e:#}"),
            }
        }
    }

    /// Entry points our roster doesn't know are another partition (or a node that just
    /// restarted): asking them to admit us and exchanging rosters merges the two
    async fn merge_partitions(&self, entries: &[EntryPoint]) {
        let (unknown, request) = {
            let inner = self.lock();
            let Some(me) = self.me(&inner) else { return };
            let unknown: Vec<EntryPoint> = entries
                .iter()
                .filter(|e| e.wg_key != self.public_key.0 && inner.roster.by_key(PubKey(e.wg_key)).is_none())
                .cloned()
                .collect();
            let request = AdmissionRequest {
                name: self.s.name.clone(),
                wg_key: self.public_key,
                endpoints: me.endpoints.clone(),
                hint: Some((me.probe, me.first_seen)),
            };
            (unknown, request)
        };
        for entry in unknown {
            match self.request_admission(&entry, &request).await {
                Ok(true) => info!("merged with {}'s view of the cluster", entry.name),
                Ok(false) => {}
                Err(e) => debug!("entry point {} unreachable: {e:#}", entry.name),
            }
        }
    }

    /// Lists us in the record while it has room, and refreshes our entry before it goes stale.
    /// Entry points that went stale or rejoined under a new key are dropped on the way.
    async fn maybe_publish(&self, entries: &[EntryPoint]) -> Result<()> {
        let (own, live) = {
            let inner = self.lock();
            let Some(me) = self.me(&inner) else { return Ok(()) };
            let live: Vec<(String, PubKey)> = inner.roster.live().map(|m| (m.name.clone(), m.wg_key)).collect();
            (self.entry_point(&me.name, me.wg_key, &me.endpoints, now_secs()), live)
        };
        if own.endpoints.is_empty() {
            return Ok(());
        }

        let now = now_secs();
        let ttl = self.s.timings.entry_ttl;
        let mut others: Vec<EntryPoint> = entries
            .iter()
            .filter(|e| e.wg_key != own.wg_key && e.name != own.name && e.is_fresh(now, ttl))
            .filter(|e| !live.iter().any(|(name, key)| *name == e.name && key.0 != e.wg_key))
            .cloned()
            .collect();
        let listed = entries.iter().find(|e| e.wg_key == own.wg_key && e.endpoints == own.endpoints);
        let due = match listed {
            Some(e) => now.saturating_sub(e.updated) >= ttl.as_secs() / 3 || others.len() + 1 != entries.len(),
            None => others.len() < MAX_ENTRY_POINTS,
        };
        if !due {
            return Ok(());
        }
        // Prefer entry points we know to be members
        others.sort_by_key(|e| !live.iter().any(|(_, key)| key.0 == e.wg_key));
        others.truncate(MAX_ENTRY_POINTS - 1);
        others.push(own);
        others.sort_by(|a, b| a.name.cmp(&b.name));
        self.discovery.publish(&others).await?;
        debug!("published the cluster record ({} entry points)", others.len());
        Ok(())
    }
}
