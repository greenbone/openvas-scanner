// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::{collections::HashMap, net::SocketAddr};

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

    async fn notus_extern(
        &self,
        addr: &SocketAddr,
        pkg_list: &[String],
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let pkg_json = serde_json::to_string(pkg_list)
            .map_err(|e| FnError::wrong_unnamed_argument("pkg_list", &e.to_string()))?;

        // TODO: Currently we only support http
        let url = format!("http://{}/notus/{}", addr, product);

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(pkg_json)
            .send()
            .await
            .map_err(|e| HttpError::Custom(e.to_string()))?;

        // Parse JSON array of results
        let results: Vec<NotusResult> = response
            .json()
            .await
            .map_err(|e| HttpError::Custom(e.to_string()))?;

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

    /// Returns the last error message from the Notus function.
    #[nasl_function]
    fn notus_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// This function takes the given information and starts a notus scan. Its arguments are:
    /// pkg_list: comma separated list or array of installed packages of the target system
    /// product: identifier for the notus scanner to get list of vulnerable packages
    ///
    /// This function returns a json like structure,
    /// so information can be adjusted and must be published using
    /// security_notus. The json like format depends
    /// one the scanner that is used.
    /// The format of the result has the following structure:
    /// ```json
    /// [
    ///   {
    ///     "oid": "[oid1]",
    ///     "message": "[message1]"
    ///   },
    ///   {
    ///     "oid": "[oid2]",
    ///     "message": "[message2]"
    ///   }
    /// ]
    /// ```
    /// It is a list of dictionaries. Each dictionary has the key `oid` and `message`.
    ///
    /// In case of an Error a NULL value is returned and an Error is set. The error can be gathered using the
    /// notus_error function, which yields the last occurred error.
    ///
    /// Internally this functions supports two modes, which is selected by the configuration of the notus context.
    /// First is the direct mode, which uses the internal notus implementation directly, the second is the external
    /// mode, which sends a request to an external notus service.
    #[nasl_function(named(pkg_list, product))]
    async fn notus(
        &mut self,
        context: &ScanCtx<'_>,
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
            NotusCtx::Address(addr) => self.notus_extern(addr, &pkg_list, product).await,
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
        notus_type
    )
}
