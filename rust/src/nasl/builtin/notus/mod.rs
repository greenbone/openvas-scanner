// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
};

use greenbone_scanner_framework::models::FixedVersion;
use nasl_function_proc_macro::nasl_function;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{
    function_set,
    nasl::{
        ArgumentError, FnError, NaslValue, ScanCtx, builtin::http::HttpError,
        utils::scan_ctx::NotusCtx,
    },
    notus::{HashsumProductLoader, Notus},
};

#[nasl_function]
fn notus_type() -> i64 {
    1
}

#[derive(Serialize, Deserialize, Debug)]
struct NotusResult {
    oid: String,
    message: String,
}

impl NaslNotus {
    fn notus_self(
        &self,
        notus: &mut Notus<HashsumProductLoader>,
        pkg_list: &[String],
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let res = notus.scan(product, pkg_list)?;

        let mut ret = vec![];
        for (oid, vuls) in res {
            let mut dict = HashMap::new();
            let message = vuls.into_iter().map(|vul| match vul.fixed_version {
                FixedVersion::Single { version, specifier } => format!("Vulnerable package:   {}\nInstalled version:    {}-{}\nFixed version:      {:2}{}-{}", vul.name, vul.name, vul.installed_version, specifier.to_string(), vul.name, version),
                FixedVersion::Range { start, end } => format!("Vulnerable package:   {}\nInstalled version:    {}-{}\nFixed version:      < {}-{}\nFixed version:      >={}-{}", vul.name, vul.name, vul.installed_version, vul.name, start, vul.name, end),
            }).collect::<Vec<String>>().join("\n\n");
            dict.insert("oid".to_string(), NaslValue::String(oid));
            dict.insert("message".to_string(), NaslValue::String(message));
            ret.push(NaslValue::Dict(dict))
        }
        Ok(NaslValue::Array(ret))
    }

    fn notus_extern(
        &self,
        addr: &SocketAddr,
        pkg_list: &[String],
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let mut sock = TcpStream::connect(addr).map_err(|e| HttpError::IO(e.kind()))?;
        let pkg_json = serde_json::to_string(pkg_list).unwrap();

        let request = format!(
            "POST /notus/{} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            product,
            pkg_json.len(),
            pkg_json
        );
        sock.write_all(request.as_bytes())
            .map_err(|e| HttpError::IO(e.kind()))?;
        let mut response = Vec::new();
        sock.read_to_end(&mut response)
            .map_err(|e| HttpError::IO(e.kind()))?;
        let response_str = String::from_utf8(response).unwrap();

        // Split headers and body
        let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
        let body = if parts.len() > 1 {
            parts[1]
        } else {
            &response_str
        };

        // Parse JSON array of results
        let results: Vec<NotusResult> = serde_json::from_str(body).unwrap();

        // Convert to NaslValue (Dict mapping oid -> message)
        let mut ret = vec![];
        for result in results {
            let mut dict = HashMap::new();
            dict.insert("oid".to_string(), NaslValue::String(result.oid));
            dict.insert("message".to_string(), NaslValue::String(result.message));
            ret.push(NaslValue::Dict(dict));
        }

        Ok(NaslValue::Array(ret))
    }

    #[nasl_function]
    fn notus_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    #[nasl_function(named(pkg_list, product))]
    fn notus(
        &mut self,
        context: &ScanCtx,
        pkg_list: NaslValue,
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let notus = if let Some(notus) = &context.notus {
            notus
        } else {
            self.last_error = Some("Configuration Error: Notus context not found".to_string());
            return Ok(NaslValue::Null);
        };
        let pkg_list: Vec<String> = match pkg_list {
            NaslValue::String(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
            NaslValue::Array(arr) => arr.iter().map(|v| v.to_string()).collect(),
            x => {
                return Err(ArgumentError::wrong_argument(
                    "pkg_list",
                    "String as Comma Separated List or Array of Strings",
                    &format!("{:?}", x),
                )
                .into());
            }
        };
        let ret = match notus {
            NotusCtx::Direct(notus) => {
                self.notus_self(&mut notus.lock().unwrap(), &pkg_list, product)
            }
            NotusCtx::Address(addr) => self.notus_extern(addr, &pkg_list, product),
        };
        match ret {
            Err(e) => {
                self.last_error = Some(e.to_string());
                Ok(NaslValue::Null)
            }
            Ok(ret) => {
                self.last_error = None;
                Ok(ret)
            }
        }
    }
}

#[derive(Default)]
pub struct NaslNotus {
    last_error: Option<String>,
}

function_set! {
    NaslNotus,
    (
        (NaslNotus::notus_error, "notus_error"),
        (NaslNotus::notus, "notus"),
    )
}
