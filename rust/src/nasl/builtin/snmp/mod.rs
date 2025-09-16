// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::prelude::*;
use std::{fmt, str::FromStr};
use thiserror::Error;

use snmp2::{Oid, SyncSession, Version};
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
}

#[derive(Debug)]
enum SnmpProtocols {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Unknown,
}

impl fmt::Display for SnmpProtocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

impl From<String> for SnmpProtocols {
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

impl From<&SnmpProtocols> for String {
    fn from(value: &SnmpProtocols) -> Self {
        match value {
            SnmpProtocols::Tcp => "tcp".to_string(),
            SnmpProtocols::Udp => "udp".to_string(),
            SnmpProtocols::Tcp6 => "tcp6".to_string(),
            SnmpProtocols::Udp6 => "udp6".to_string(),
            SnmpProtocols::Unknown => "unknown".to_string(),
        }
    }
}

impl<'a> FromNaslValue<'a> for SnmpProtocols {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(SnmpProtocols::from(s))
    }
}
#[allow(clippy::too_many_arguments)]
fn snmpv1_get_shared(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: SnmpProtocols,
    community: String,
    snmp_ver: snmp2::Version,
    is_next: bool,
) -> Result<NaslValue, FnError> {
    if let SnmpProtocols::Unknown = protocol {
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
    protocol: SnmpProtocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1_get_shared(
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
    protocol: SnmpProtocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1_get_shared(
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
    protocol: SnmpProtocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1_get_shared(
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
    protocol: SnmpProtocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1_get_shared(
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

#[nasl_function(named(oid, port, protocol, community))]
fn snmpv3_get(
    config: &ScanCtx,
    script_ctx: &mut ScriptCtx,
    oid: Option<String>,
    port: i64,
    protocol: SnmpProtocols,
    community: String,
) -> Result<NaslValue, FnError> {
    snmpv1_get_shared(
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
    )
}
