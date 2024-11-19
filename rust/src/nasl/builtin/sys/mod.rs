use std::io;

use thiserror::Error;
use tokio::process::Command;

use crate::nasl::prelude::*;

#[derive(Error, Debug)]
pub enum SysError {
    #[error("Failed to spawn process.")]
    SpawnProcess(io::Error),
}

pub struct Sys;

impl Sys {
    #[nasl_function(named(cd))]
    async fn pread(
        &self,
        cmd: &str,
        cd: Option<bool>,
        argv: CheckedPositionals<String>,
    ) -> Result<String, FnError> {
        let mut cmd = Command::new(cmd);
        for arg in argv.iter() {
            cmd.arg(arg);
        }
        let out = cmd.output().await.map_err(|e| SysError::SpawnProcess(e))?;
        let stdout = String::from_utf8(out.stdout).unwrap();
        Ok(stdout)
    }
}

function_set! {
    Sys,
    async_stateful,
    (
        (Sys::pread, "pread"),
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
