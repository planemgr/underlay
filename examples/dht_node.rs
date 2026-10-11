//! A standalone Mainline DHT node for the end-to-end test

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let port = 6881;
    let mut builder = pkarr::Client::builder();
    builder.no_default_network().dht(|c| {
        c.server_mode = true;
        c.port = Some(port);
        // A network of its own
        c.bootstrap = Some(vec![]);
        c
    });
    let _client = builder.build().context("starting the DHT node")?;
    tracing::info!("DHT node listening on udp/{port}");
    std::future::pending::<()>().await;
    Ok(())
}
