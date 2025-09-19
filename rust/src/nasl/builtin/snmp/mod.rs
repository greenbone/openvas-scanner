// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::prelude::*;
use std::{fmt, str::FromStr};
use thiserror::Error;

use snmp2::{Oid, SyncSession, Version, v3};
use std::time::Duration;

#[derive(Debug, Error)]
pub enum SnmpError {
    #[error("Unknown protocol {0}")]
    Protocol(String),
    #[error("Missing OID")]
    MissingOid,
    #[error("Snmp error: {0}")]
    Snmp(String),
    #[error("IO error during SNMP: {0}")]
    IO(String),
    #[error("SNMP Authentication Protocol unsupported")]
    AuthProtoUnsupported,
    #[error("SNMP Private Protocol unsupported")]
    PrivProtoUnsupported,
}

#[derive(Debug)]
enum L4Protocols {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Unknown,
}

impl fmt::Display for L4Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

impl From<String> for L4Protocols {
    fn from(value: String) -> Self {
        match value.as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "tcp6" => Self::Tcp6,
            "udp6" => Self::Udp6,
            _ => Self::Unknown,
        }
    }
}

impl From<&L4Protocols> for String {
    fn from(value: &L4Protocols) -> Self {
        match value {
            L4Protocols::Tcp => "tcp".to_string(),
            L4Protocols::Udp => "udp".to_string(),
            L4Protocols::Tcp6 => "tcp6".to_string(),
            L4Protocols::Udp6 => "udp6".to_string(),
            L4Protocols::Unknown => "unknown".to_string(),
        }
    }
}

impl<'a> FromNaslValue<'a> for L4Protocols {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(L4Protocols::from(s))
    }
}
#[allow(clippy::too_many_arguments)]
fn snmpv1v2c_get_shared(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    community: String,
    snmp_ver: snmp2::Version,
    is_next: bool,
) -> Result<NaslValue, FnError> {
    if let L4Protocols::Unknown = protocol {
        return Err(SnmpError::Protocol("Bad protocol version".to_string()).into());
    }

    let next_oid = script_ctx.snmp_next.clone().unwrap_or_default();
    let oid = if is_next && !next_oid.is_empty() {
        Oid::from_str(&next_oid).map_err(|_| SnmpError::MissingOid)?
    } else if let Some(oid) = oid {
        if oid.starts_with('.') {
            let oid_aux = oid.trim_start_matches('.');
            Oid::from_str(oid_aux).map_err(|_| SnmpError::MissingOid)?
        } else {
            Oid::from_str(&oid).map_err(|_| SnmpError::MissingOid)?
        }
    } else {
        return Err(SnmpError::MissingOid.into());
    };

    let peername = format!("{}:{}", config.target().ip_addr(), port);
    let timeout = Duration::from_secs(2);

    let mut sess = match snmp_ver {
        Version::V1 => SyncSession::new_v1(peername, community.as_bytes(), Some(timeout), 0)
            .map_err(|e| SnmpError::IO(e.to_string()))?,
        Version::V2C => SyncSession::new_v2c(peername, community.as_bytes(), Some(timeout), 0)
            .map_err(|e| SnmpError::IO(e.to_string()))?,
        _ => unimplemented!(),
    };

    let mut response = if is_next {
        sess.getnext(&oid)
            .map_err(|e| SnmpError::Snmp(e.to_string()))?
    } else {
        sess.get(&oid).map_err(|e| SnmpError::Snmp(e.to_string()))?
    };

    let mut res = vec![];
    if let Some((oid, val)) = response.varbinds.next() {
        let aux = format!("{:?}", val).to_string();
        if let Some((_, val)) = aux.split_once(": ") {
            script_ctx.snmp_next = Some(oid.clone().to_id_string());
            res.push(NaslValue::Number(0));
            res.push(NaslValue::String(val.to_string()));
            res.push(NaslValue::String(oid.to_id_string()));
        }
    }
    Ok(NaslValue::Array(res))
}

#[nasl_function(named(oid, port, protocol, community))]
fn snmpv1_get(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1v2c_get_shared(
        config,
        script_ctx,
        oid,
        port,
        protocol,
        community,
        snmp2::Version::V1,
        false,
    )
}

#[nasl_function(named(oid, port, protocol, community))]
fn snmpv1_getnext(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1v2c_get_shared(
        config,
        script_ctx,
        oid,
        port,
        protocol,
        community,
        snmp2::Version::V1,
        true,
    )
}

#[nasl_function(named(oid, port, protocol, community))]
fn snmpv2c_get(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1v2c_get_shared(
        config,
        script_ctx,
        oid,
        port,
        protocol,
        community,
        snmp2::Version::V2C,
        false,
    )
}

#[nasl_function(named(oid, port, protocol, community))]
fn snmpv2c_getnext(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1v2c_get_shared(
        config,
        script_ctx,
        oid,
        port,
        protocol,
        community,
        snmp2::Version::V2C,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn snmpv3_get_shared(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    username: String,
    authpass: String,
    authproto: String,
    privpass: String,
    privproto: String,
    is_next: bool,
) -> Result<NaslValue, FnError> {
    if let L4Protocols::Unknown = protocol {
        return Err(SnmpError::Protocol("Bad protocol version".to_string()).into());
    }

    let next_oid = script_ctx.snmp_next.clone().unwrap_or_default();
    let oid = if is_next && !next_oid.is_empty() {
        Oid::from_str(&next_oid).map_err(|_| SnmpError::MissingOid)?
    } else if let Some(oid) = oid {
        if oid.starts_with('.') {
            let oid_aux = oid.trim_start_matches('.');
            Oid::from_str(oid_aux).map_err(|_| SnmpError::MissingOid)?
        } else {
            Oid::from_str(&oid).map_err(|_| SnmpError::MissingOid)?
        }
    } else {
        return Err(SnmpError::MissingOid.into());
    };

    let peername = format!("{}:{}", config.target().ip_addr(), port);
    let timeout = Duration::from_secs(2);

    let auth_protcol = match authproto.as_str() {
        "sha1" => v3::AuthProtocol::Sha1,
        "md5" => v3::AuthProtocol::Md5,
        _ => return Err(SnmpError::AuthProtoUnsupported.into()),
    };

    let cipher = match privproto.as_str() {
        "aes" | "aes128" => v3::Cipher::Aes128,
        "aes192" => v3::Cipher::Aes192,
        "aes256" => v3::Cipher::Aes256,
        "des" => v3::Cipher::Des,
        _ => return Err(SnmpError::PrivProtoUnsupported.into()),
    };

    let auth = v3::Auth::AuthPriv {
        cipher,
        privacy_password: privpass.into_bytes(),
    };
    let security = v3::Security::new(&username.into_bytes(), &authpass.into_bytes())
        .with_auth_protocol(auth_protcol)
        .with_auth(auth);

    let mut sess = SyncSession::new_v3(peername, Some(timeout), 0, security)
        .map_err(|e| SnmpError::IO(e.to_string()))?;

    sess.init().map_err(|e| SnmpError::IO(e.to_string()))?;

    let mut res = vec![];
    loop {
        let mut response = if is_next {
            match sess.getnext(&oid) {
                Ok(r) => r,
                Err(snmp2::Error::AuthUpdated) => continue,
                Err(e) => return Err(SnmpError::Snmp(e.to_string()).into()),
            }
        } else {
            match sess.get(&oid) {
                Ok(r) => r,
                Err(snmp2::Error::AuthUpdated) => continue,
                Err(e) => return Err(SnmpError::Snmp(e.to_string()).into()),
            }
        };

        if let Some((oid, val)) = response.varbinds.next() {
            let aux = format!("{:?}", val).to_string();
            if let Some((_, val)) = aux.split_once(": ") {
                script_ctx.snmp_next = Some(oid.clone().to_id_string());
                res.push(NaslValue::Number(0));
                res.push(NaslValue::String(val.to_string()));
                res.push(NaslValue::String(oid.to_id_string()));
            }
        }
        break;
    }

    Ok(NaslValue::Array(res))
}

#[nasl_function(named(
    oid, port, protocol, username, authpass, authproto, privpass, privproto
))]
fn snmpv3_get(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    username: String,
    authpass: String,
    authproto: String,
    privpass: String,
    privproto: String,
) -> Result<NaslValue, FnError> {
    snmpv3_get_shared(
        config, script_ctx, oid, port, protocol, username, authpass, authproto, privpass,
        privproto, false,
    )
}

#[nasl_function(named(
    oid, port, protocol, username, authpass, authproto, privpass, privproto
))]
fn snmpv3_getnext(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: L4Protocols,
    username: String,
    authpass: String,
    authproto: String,
    privpass: String,
    privproto: String,
) -> Result<NaslValue, FnError> {
    snmpv3_get_shared(
        config, script_ctx, oid, port, protocol, username, authpass, authproto, privpass,
        privproto, true,
    )
}

/// The description builtin function
pub struct Snmp;

function_set! {
    Snmp,
    (
        snmpv1_get,
        snmpv1_getnext,
        snmpv2c_get,
        snmpv2c_getnext,
        snmpv3_get,
        snmpv3_getnext,
    )
}
