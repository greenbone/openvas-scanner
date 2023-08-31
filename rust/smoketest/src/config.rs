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
    /// API KEY
    #[arg(short, long)]
    api_key: Option<String>,
    /// Client certificate
    #[arg(short, long)]
    cert: Option<String>,
    /// Client private key
    #[arg(short, long)]
    key: Option<String>,
}

impl Args {
    pub fn openvasd(&self) -> &String {
        &self.openvasd
    }
    pub fn scan_config(&self) -> &String {
        &self.scan_config
    }
    pub fn api_key(&self) -> &Option<String> {
        &self.api_key
    }
    pub fn key(&self) -> &Option<String> {
        &self.key
    }
    pub fn cert(&self) -> &Option<String> {
        &self.cert
    }
}
