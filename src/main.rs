//! underlay: a WireGuard mesh between nodes on any network, found through the Mainline DHT.
//!
//! A daemon without a command line: it is configured through environment variables (cloud-init
//! writes them to the systemd unit's environment file) and does everything else on its own.
//! See README.md for the design.

#[cfg(not(target_os = "linux"))]
compile_error!("underlay manages kernel WireGuard through netlink and only runs on Linux");

mod admission;
mod api;
mod endpoints;
mod net;
mod node;
mod proto;
mod record;
mod roster;
mod token;
mod util;
mod wg;

use std::env;
use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::node::{Settings, Timings};
use crate::token::JoinToken;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mainline=warn,pkarr=warn,netlink_packet_route=error".into()),
        )
        .init();
    tracing::info!("underlay {}", env!("CARGO_PKG_VERSION"));
    let settings = settings()?;
    tokio::runtime::Runtime::new()?.block_on(node::run(settings))
}

/// `UNDERLAY_<name>` parsed, or `default` when unset
fn var<T: FromStr>(name: &str, default: T) -> Result<T>
where
    T::Err: Display,
{
    match env::var(format!("UNDERLAY_{name}")) {
        Ok(value) => value.trim().parse().map_err(|e| anyhow::anyhow!("UNDERLAY_{name}: {e}")),
        Err(_) => Ok(default),
    }
}

fn secs(name: &str, default: u64) -> Result<Duration> {
    var(name, default).map(Duration::from_secs)
}

fn settings() -> Result<Settings> {
    let token = env::var("UNDERLAY_JOIN_TOKEN").context("UNDERLAY_JOIN_TOKEN is not set")?;
    let token = JoinToken::decode(&token)?;
    let name = match env::var("UNDERLAY_NAME") {
        Ok(name) => name,
        Err(_) => std::fs::read_to_string("/proc/sys/kernel/hostname").context("reading the host name")?,
    };
    let name = name.trim().to_lowercase();
    ensure!(roster::valid_name(&name), "node name {name:?} must be a DNS label (lowercase, digits, dashes)");

    let list = |name: &str| -> Result<Vec<String>> {
        Ok(var(name, String::new())?.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
    };
    let advertise = list("ADVERTISE")?
        .iter()
        .map(|ip| ip.parse::<IpAddr>().with_context(|| format!("UNDERLAY_ADVERTISE: {ip:?} is not an address")))
        .collect::<Result<_>>()?;

    Ok(Settings {
        name,
        interface: var("INTERFACE", "underlay0".parse()?)?,
        listen_port: var("LISTEN_PORT", 51820)?,
        mtu: var("MTU", 1420)?,
        token,
        admission_port: var("ADMISSION_PORT", 51821)?,
        admission_per_minute: var("ADMISSION_PER_MINUTE", 30)?,
        api_port: var("API_PORT", 51822)?,
        dht_bootstrap: list("DHT_BOOTSTRAP")?,
        advertise,
        timings: Timings {
            gossip: secs("GOSSIP_SECS", 30)?,
            record: secs("RECORD_SECS", 120)?,
            entry_ttl: secs("ENTRY_TTL_SECS", 3600)?,
            tick: secs("TICK_SECS", 5)?,
            rotate: secs("ROTATE_SECS", 10)?,
            cooldown: secs("COOLDOWN_SECS", 60)?,
            expire_after: secs("EXPIRE_AFTER_SECS", 2 * 3600)?,
        },
    })
}
