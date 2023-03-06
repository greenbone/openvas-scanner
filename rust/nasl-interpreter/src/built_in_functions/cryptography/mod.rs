// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{error::FunctionError, ContextType, NaslFunction, NaslValue, Register};

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod hmac;

enum Crypt {
    Encrypt,
    Decrypt,
}

pub(crate) fn lookup(function_name: &str) -> Option<NaslFunction> {
    aes_ccm::lookup(function_name)
        .or_else(|| hmac::lookup(function_name))
        .or_else(|| aes_cbc::lookup(function_name))
        .or_else(|| aes_ctr::lookup(function_name))
        .or_else(|| aes_gcm::lookup(function_name))
}

fn get_named_data<'a>(
    register: &'a Register,
    key: &'a str,
    required: bool,
    function: &str,
) -> Result<Option<&'a [u8]>, FunctionError> {
    match register.named(key) {
        Some(ContextType::Value(NaslValue::Data(x))) => Ok(Some(x.as_slice())),
        Some(ContextType::Value(NaslValue::String(x))) => Ok(Some(x.as_bytes())),
        x => {
            if required {
                Err(FunctionError::new(
                    function,
                    (key, "string or data", x).into(),
                ))
            } else {
                Ok(None)
            }
        }
    }
}

fn get_named_number(
    register: &Register,
    key: &str,
    required: bool,
    function: &str,
) -> Result<Option<i64>, FunctionError> {
    match register.named(key) {
        Some(ContextType::Value(NaslValue::Number(x))) => Ok(Some(*x)),
        x => {
            if required {
                Err(FunctionError::new(
                    function,
                    (key, "string or data", x).into(),
                ))
            } else {
                Ok(None)
            }
        }
    }
}
