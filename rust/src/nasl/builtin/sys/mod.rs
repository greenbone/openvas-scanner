// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    env, io,
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
    #[error("Unable to write file. {0}")]
    WriteFile(io::Error),
    #[error("Unable to remove file. {0}")]
    RemoveFile(io::Error),
    #[error("Error while trying to find the path for the command '{0}'")]
    FindCommandPath(String),
    #[error("Command '{0}' not found.")]
    CommandNotFound(String),
}

pub struct Sys;

async fn find_path_of_command(cmd: &str) -> Result<PathBuf, SysError> {
    // Here, we use `which` to find out
    // what the path of the command is.
    let make_err = || SysError::FindCommandPath(cmd.to_string());
    let mut which_cmd = Command::new("which");
    let output = which_cmd.arg(cmd).output().await.map_err(|_| make_err())?;
    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).map_err(|_| make_err())?;
        let path = Path::new(&stdout);
        let dir = path.parent().ok_or_else(make_err)?.to_owned();
        Ok(dir)
    } else {
        Err(SysError::CommandNotFound(cmd.to_string()))
    }
}

#[nasl_function(named(cd))]
async fn pread(
    cmd: &str,
    cd: Option<bool>,
    argv: CheckedPositionals<String>,
) -> Result<String, FnError> {
    let mut real_cmd = Command::new(cmd);
    if let Some(true) = cd {
        // If `cd` is true, we need to change the cwd to
        // the path in which the executable that will be
        // run resides.
        let dir = find_path_of_command(cmd).await?;
        real_cmd.current_dir(dir);
    };
    for arg in argv.iter() {
        real_cmd.arg(arg);
    }
    let out = real_cmd.output().await.map_err(SysError::SpawnProcess)?;
    let stdout = String::from_utf8(out.stdout).unwrap();
    Ok(stdout)
}

#[nasl_function]
async fn find_in_path(cmd: &str) -> Result<bool, FnError> {
    let result = find_path_of_command(cmd).await;
    match result {
        Ok(_) => Ok(true),
        Err(SysError::CommandNotFound(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[nasl_function]
async fn fread(path: &Path) -> Result<String, FnError> {
    tokio::fs::read_to_string(path)
        .await
        .map_err(|e| SysError::ReadFile(e).into())
}

#[nasl_function(named(data, file))]
async fn fwrite(data: &str, file: &Path) -> Result<usize, FnError> {
    tokio::fs::write(file, data)
        .await
        .map_err(SysError::WriteFile)?;
    let num_bytes = data.len();
    Ok(num_bytes)
}

#[nasl_function]
async fn file_stat(path: &Path) -> Result<u64, FnError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(SysError::ReadFileMetadata)?;
    Ok(metadata.len())
}

#[nasl_function]
async fn unlink(path: &Path) -> Result<(), FnError> {
    tokio::fs::remove_file(path)
        .await
        .map_err(|e| SysError::RemoveFile(e).into())
}

#[nasl_function]
async fn get_tmp_dir() -> PathBuf {
    env::temp_dir()
}

function_set! {
    Sys,
    (
        pread,
        fread,
        file_stat,
        find_in_path,
        fwrite,
        get_tmp_dir,
        unlink,
    )
}

#[cfg(test)]
mod tests {
    use crate::nasl::{builtin::sys::SysError, test_prelude::*};

    #[tokio::test]
    async fn pread() {
        let mut t = TestBuilder::default();
        t.ok(r#"pread("basename", "/a/b/c");"#, "c\n");
        t.async_verify().await;
    }

    #[tokio::test]
    async fn find_in_path() {
        let mut t = TestBuilder::default();
        t.ok(r#"find_in_path("basename");"#, true);
        // Cannot think of a way to construct a command name here
        // that is very unlikely to exist without it sounding ridiculous
        t.ok(r#"find_in_path("foobarbaz");"#, false);
        t.async_verify().await;
    }

    #[tokio::test]
    async fn write_read_to_tmpdir() {
        let mut t = TestBuilder::default();
        t.run(r#"path = get_tmp_dir();"#);
        t.run(r#"file = path + "/write_read_to_tmpdir";"#);
        t.ok(r#"fwrite(file: file, data: "foo");"#, 3);
        t.ok(r#"fread(file);"#, "foo");
        t.ok(r#"file_stat(file);"#, 3);
        t.run(r#"unlink(file);"#);
        check_err_matches!(t, r#"file_stat(file);"#, SysError::ReadFileMetadata(_));
        t.async_verify().await;
    }
}
