use std::path::{Path, PathBuf};

use scannerlib::{
    nasl::WithErrorInfo,
};
use tracing::info;

use crate::{CliError, CliErrorKind, Filename};

/// Transforms each nasl script and inc file based on the given rules.
#[derive(clap::Parser)]
pub struct TranspileArgs {
    /// Path to the feed.
    #[clap(short, long)]
    path: PathBuf,
    /// Path to the transpiler rules.
    #[clap(short, long)]
    rules: PathBuf,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Wrapper {
    cmds: Vec<ReplaceCommand>,
}

 async fn run(args: TranspileArgs) -> Result<(), CliError> {
    let rules = std::fs::read_to_string(args.rules).unwrap();
    let rules: Wrapper = toml::from_str(&rules).unwrap();
    let rules = rules.cmds;
    let base = args.path.to_str().unwrap_or_default();
    for name in FeedReplacer::new(base, &rules) {
        let name = name.unwrap();
        if let Some((name, content)) = name {
            use std::io::Write;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&name)
                .map_err(|e| {
                    CliErrorKind::Corrupt(format!("unable to open {name}: {e}"))
                        .with(Filename(Path::new(&name)))
                });
            match f.and_then(|mut f| {
                f.write_all(content.as_bytes()).map_err(|e| {
                    CliErrorKind::Corrupt(format!("unable to write to {name}: {e}"))
                        .with(Filename(Path::new(&name)))
                })
            }) {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            }

            info!("changed {name}");
        }
    }
    Ok(())
}
