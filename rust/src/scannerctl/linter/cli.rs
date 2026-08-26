use std::path::{Path, PathBuf};

use crate::error::CliError;
use scannerlib::nasl::Loader;

#[derive(clap::Parser)]
pub struct LinterArgs {
    /// Either a single NASL file or a feed directory. Directory scans use
    /// `.nasl` files as roots and load `.inc` files through include statements.
    pub path: PathBuf,
}

pub(super) fn get_files_and_loader(root: &Path) -> Result<(Loader, Vec<PathBuf>), CliError> {
    let mut files = vec![];
    let loader = if root.is_file() {
        files.push(Path::new(root.file_name().unwrap()).into());
        Loader::from_feed_path(root.parent().unwrap())
    } else {
        for e in walkdir::WalkDir::new(root) {
            let e = e.map_err(std::io::Error::from)?;
            if e.path().extension().and_then(|ext| ext.to_str()) == Some("nasl") {
                files.push(e.path().strip_prefix(root).unwrap().to_owned());
            }
        }
        files.sort();
        Loader::from_feed_path(root)
    };
    Ok((loader, files))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn directory_uses_only_nasl_files_as_roots() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("first.nasl"), "").unwrap();
        fs::write(directory.path().join("second.nasl"), "").unwrap();
        fs::write(directory.path().join("functions.inc"), "").unwrap();

        let (_, mut files) = get_files_and_loader(directory.path()).unwrap();
        files.sort();

        assert_eq!(
            files,
            vec![PathBuf::from("first.nasl"), PathBuf::from("second.nasl")]
        );
    }

    #[test]
    fn explicit_include_file_is_still_a_root() {
        let directory = tempfile::tempdir().unwrap();
        let include = directory.path().join("functions.inc");
        fs::write(&include, "").unwrap();

        let (_, files) = get_files_and_loader(&include).unwrap();

        assert_eq!(files, vec![PathBuf::from("functions.inc")]);
    }
}
