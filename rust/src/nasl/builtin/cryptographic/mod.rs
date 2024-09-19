// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// use crate::nasl::utils::combine_function_sets;
use crate::nasl::utils::error::FunctionErrorKind;

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::{ContextType, IntoFunctionSet, Register, StoredFunctionSet};

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_cmac;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod aes_gmac;
pub mod des;
pub mod hash;
pub mod hmac;

#[cfg(test)]
mod tests;

enum Crypt {
    Encrypt,
    Decrypt,
}

/// Get named argument of Type Data or String from the register with appropriate error handling.
/// In case the argument is required, the returned value is either an Error or the Option is always
/// set to Some value. If it is false, no error will be returned but the Option can be either Some
/// or None.
fn get_required_named_data<'a>(
    register: &'a Register,
    key: &'a str,
) -> Result<&'a [u8], FunctionErrorKind> {
    match register.named(key) {
        Some(ContextType::Value(NaslValue::Data(x))) => Ok(x.as_slice()),
        Some(ContextType::Value(NaslValue::String(x))) => Ok(x.as_bytes()),
        Some(x) => Err(FunctionErrorKind::wrong_argument(
            key,
            "a String or Data Value",
            format!("{:?}", x).as_str(),
        )),
        _ => Err(FunctionErrorKind::missing_argument(key)),
    }
}

/// Get named argument of Type Number from the register with appropriate error handling.
/// In case the argument is required, the returned value is either an Error or the Option is always
/// set to Some value. If it is false, no error will be returned but the Option can be either Some
/// or None.
fn get_optional_named_number(
    register: &Register,
    key: &str,
) -> Result<Option<i64>, FunctionErrorKind> {
    match register.named(key) {
        Some(ContextType::Value(NaslValue::Number(x))) => Ok(Some(*x)),
        Some(x) => Err(FunctionErrorKind::wrong_argument(
            key,
            "a Number Value",
            format!("{:?}", x).as_str(),
        )),
        _ => Ok(None),
    }
}

/// Get the required key argument or error.
fn get_key(register: &Register) -> Result<&[u8], FunctionErrorKind> {
    get_required_named_data(register, "key")
}

/// Get the required data argument or error.
fn get_data(register: &Register) -> Result<&[u8], FunctionErrorKind> {
    get_required_named_data(register, "data")
}

/// Get the required iv argument or error.
fn get_iv(register: &Register) -> Result<&[u8], FunctionErrorKind> {
    get_required_named_data(register, "iv")
}

/// Get the required iv argument or error.
fn get_aad(register: &Register) -> Result<&[u8], FunctionErrorKind> {
    get_required_named_data(register, "aad")
}

/// Get the optional len argument with proper error handling.
fn get_len(register: &Register) -> Result<Option<usize>, FunctionErrorKind> {
    let buf = get_optional_named_number(register, "len")?;
    match buf {
        None => Ok(None),
        Some(x) => match x.try_into() {
            Ok(y) => Ok(Some(y)),
            Err(_) => Err(FunctionErrorKind::WrongArgument(format!(
                "System only supports numbers between {:?} and {:?} but was {:?}",
                usize::MIN,
                usize::MAX,
                x
            ))),
        },
    }
}

pub struct Cryptographic;

impl IntoFunctionSet for Cryptographic {
    type State = Cryptographic;

    fn into_function_set(self) -> StoredFunctionSet<Cryptographic> {
        let mut set = StoredFunctionSet::new(self);
        set.add_set(aes_ccm::AesCcm);
        set.add_set(hmac::HmacFns);
        set.add_set(aes_cbc::AesCbc);
        set.add_set(aes_ctr::AesCtr);
        set.add_set(aes_gcm::AesGcmFns);
        set.add_set(aes_cmac::AesCmac);
        set.add_set(aes_gmac::AesGmac);
        set.add_set(hash::Hash);
        set.add_set(des::Des);
        set
    }
}
