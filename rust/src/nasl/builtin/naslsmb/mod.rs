// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;
mod handle;
use crate::nasl::prelude::*;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

use dns_lookup::lookup_addr;

use tokio::sync::Mutex;

pub use error::SmbError;
pub use handle::SmbHandles as Smb;
use handle::{HandleId, SmbHandle};

const SMB_LIB_IMPLEMENTATION_VERSION: &str = "0.0.1";

#[nasl_function]
fn smb_versioninfo() -> String {
    SMB_LIB_IMPLEMENTATION_VERSION.to_string()
}

impl Smb {
    #[nasl_function(named(username, password, share))]
    async fn smb_connect(
        &mut self,
        ctx: &ScanCtx<'_>,
        username: String,
        password: String,
        share: String,
    ) -> Result<HandleId, FnError> {
        let server = ctx.target().ip_addr();
        let id = self.next_handle_id()?;

        let handle =
            Mutex::new(SmbHandle::new(server.to_string(), share, username, password).await?);
        self.insert(id, handle);
        Ok(id)
    }

    #[nasl_function(named(smb_handle))]
    async fn smb_close(&mut self, smb_handle: i32) -> Result<(), FnError> {
        {
            let mut handle = self.get_by_id(smb_handle).await?;
            handle.disconnect().await?;
        }
        Ok(self.remove(smb_handle)?)
    }

    #[nasl_function(named(smb_handle, filename))]
    async fn smb_file_sddl(
        &mut self,
        smb_handle: i32,
        filename: String,
    ) -> Result<String, FnError> {
        let handle = self.get_by_id(smb_handle).await?;

        Ok(handle.get_full_info(filename).await?)
    }
}

#[nasl_function(named(host, username, password, realm, kdc, cmd))]
fn nasl_win_cmd_exec(
    ctx: &ScanCtx<'_>,
    host: Option<String>,
    username: String,
    password: String,
    realm: Option<String>,
    kdc: Option<String>,
    cmd: String,
) -> Result<Option<String>, FnError> {
    let host = if let Some(host) = host {
        IpAddr::from_str(&host).map_err(|e| SmbError::InvalidHost(e.to_string()))?
    } else {
        ctx.target().ip_addr()
    };

    let host = if let Some(_krb5) = kdc.clone() {
        match lookup_addr(&host) {
            Ok(host) => host,
            Err(e) => {
                return Err(SmbError::InvalidHost(e.to_string()).into());
            }
        }
    } else {
        host.to_string()
    };

    let username = username.replacen("\\", "/", 1);
    let realm = realm.unwrap_or_default();
    let target = if let Some(_realm) = username.find("/") {
        format!("{username}:{password}@{host}")
    } else {
        format!("{realm}/{username}:{password}@{host}")
    };

    // Construct the command
    let mut output = Command::new("impacket-wmiexec");
    if let Some(krb5) = kdc.clone() {
        let first_kdc = if let Some(i) = krb5.find(",") {
            krb5[..i].to_string()
        } else {
            krb5
        };
        output
            .arg("-k")
            .arg("-dc-ip")
            .arg(first_kdc)
            .arg(target)
            .arg(cmd);
    } else {
        output.arg(target).arg(cmd);
    };

    let child = output.spawn().map_err(|e| SmbError::Smb(e.to_string()))?;

    let ret = child
        .wait_with_output()
        .map_err(|e| SmbError::Smb(e.to_string()))?;
    Ok(Some(String::from_utf8_lossy(&ret.stdout).to_string()))
}

function_set! {
    Smb,
    (
        (Smb::smb_connect, "smb_connect"),
        (Smb::smb_close, "smb_close"),
        (Smb::smb_file_sddl, "smb_file_SDDL"),
        (nasl_win_cmd_exec, "win_cmd_exec"),
        smb_versioninfo,
    )
}
