use std::path::{Path, PathBuf};

use scannerlib::nasl::Loader;

use crate::error::CliError;

#[derive(clap::Parser)]
pub struct LinterArgs {
    /// Either a single NASL file or a directory of NASL files on which to run the linter.
    pub path: PathBuf,
}

pub(super) fn get_files_and_loader(root: &Path) -> Result<(Loader, Vec<PathBuf>), CliError> {
    let mut files = vec![];
    let loader = if root.is_file() {
        files.push(root.into());
        Loader::from_feed_path(root.parent().unwrap())
    } else {
        for e in walkdir::WalkDir::new(root) {
            let e = e.map_err(std::io::Error::from)?;
            if let Some("nasl") | Some("inc") = e.path().extension().and_then(|ext| ext.to_str()) {
                files.push(e.path().strip_prefix(root).unwrap().to_owned());
            }
        }
        Loader::from_feed_path(root)
    };
    Ok((loader, files))
}
