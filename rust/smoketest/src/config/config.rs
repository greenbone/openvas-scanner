
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// openvasd 
    #[arg(short, long)]
    openvasd: String,

    /// Scan Config
    #[arg(short, long)]
    scan_config: String,
    /// Scan Config
    #[arg(short, long)]
    api_key: Option<String>,
}
