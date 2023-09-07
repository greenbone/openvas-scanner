mod config;
mod tests;

use config::Args;
use clap::Parser;
use crate::tests::*;
use smoketest::new_client;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy("INFO");
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = new_client(&args.api_key(), &args.cert(), &args.key());
    tracing::info!("Starting smoke test");
    tracing::info!("\n\nTEST 1: Check server connection:");
    if !test1::check_server(&cli, &args.openvasd()).await{
        tracing::info!("TEST 1: FAILED:");
        return;
    }
    tracing::info!("\n\nTEST 2: Running successful scan:");
    if !test2::run_scan(&cli, &args.openvasd(), &args.scan_config()).await{
        tracing::info!("TEST 2: FAILED");
    }
}
