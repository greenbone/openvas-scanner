use std::path::PathBuf;

use crate::error::CliError;
use scannerlib::nasl::Loader;

/// Check the syntax of the given NASL scripts and
/// report encountered errors.
#[derive(clap::Parser)]
pub struct LinterArgs {
    /// Path of the feed to lint.
    pub path: PathBuf,
    /// Optional filter, a list of `.nasl` files to run the linter on.
    #[clap(short, long)]
    pub files: Option<Vec<PathBuf>>,
}

pub(super) fn get_files_and_loader(args: &LinterArgs) -> Result<(Loader, Vec<PathBuf>), CliError> {
    let files = if let Some(ref files) = args.files {
        files.clone()
    } else {
        let mut files = vec![];
        for e in walkdir::WalkDir::new(&args.path) {
            let e = e.map_err(std::io::Error::from)?;
            if e.file_type().is_file()
                && e.path().extension().and_then(|ext| ext.to_str()) == Some("nasl")
            {
                files.push(e.path().strip_prefix(&args.path).unwrap().to_owned());
            }
        }
        files
    };
    let loader = Loader::from_feed_path(&args.path);
    Ok((loader, files))
}
