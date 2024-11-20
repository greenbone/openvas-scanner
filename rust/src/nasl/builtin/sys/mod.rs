use std::{
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::process::Command;

use crate::nasl::prelude::*;

#[derive(Error, Debug)]
pub enum SysError {
    #[error("Failed to spawn process. {0}")]
    SpawnProcess(io::Error),
    #[error("Unable to read file. {0}")]
    ReadFile(io::Error),
    #[error("Unable to read file metadata. {0}")]
    ReadFileMetadata(io::Error),
    #[error("Unable to find the path for the command '{0}'")]
    FindCommandPath(String),
}

pub struct Sys;

async fn find_path_of_command(cmd: &str) -> Option<PathBuf> {
    // Here, we use `which` to find out
    // what this path is.
    let mut which_cmd = Command::new("which");
    let stdout = String::from_utf8(which_cmd.arg(cmd).output().await.ok()?.stdout).ok()?;
    let path = Path::new(&stdout);
    let dir = path.parent()?.to_owned();
    Some(dir)
}

impl Sys {
    #[nasl_function(named(cd))]
    async fn pread(
        &self,
        cmd: &str,
        cd: Option<bool>,
        argv: CheckedPositionals<String>,
    ) -> Result<String, FnError> {
        let mut real_cmd = Command::new(cmd);
        if let Some(true) = cd {
            // If `cd` is true, we need to change the cwd to
            // the path in which the executable that will be
            // run resides.
            let dir = find_path_of_command(cmd)
                .await
                .ok_or_else(|| SysError::FindCommandPath(cmd.to_string()))?;
            real_cmd.current_dir(dir);
        };
        for arg in argv.iter() {
            real_cmd.arg(arg);
        }
        let out = real_cmd
            .output()
            .await
            .map_err(|e| SysError::SpawnProcess(e))?;
        let stdout = String::from_utf8(out.stdout).unwrap();
        Ok(stdout)
    }

    #[nasl_function]
    async fn fread(&self, path: &Path) -> Result<String, FnError> {
        std::fs::read_to_string(path).map_err(|e| SysError::ReadFile(e).into())
    }

    #[nasl_function]
    async fn file_stat(&self, path: &Path) -> Result<u64, FnError> {
        let metadata = std::fs::metadata(path).map_err(|e| SysError::ReadFileMetadata(e))?;
        Ok(metadata.len())
    }
}

function_set! {
    Sys,
    async_stateful,
    (
        (Sys::pread, "pread"),
        (Sys::fread, "fread"),
        (Sys::file_stat, "file_stat"),
    )
}

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;

    #[tokio::test]
    async fn pread() {
        let mut t = TestBuilder::default();
        t.ok(r#"pread("basename", "/a/b/c");"#, "c\n");
        t.async_verify().await;
    }
}
