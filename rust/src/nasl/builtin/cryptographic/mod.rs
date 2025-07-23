// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

// use crate::nasl::utils::combine_function_sets;
use crate::nasl::prelude::*;

use crate::nasl::utils::{IntoFunctionSet, Register, StoredFunctionSet};

pub mod aes_cbc;
mod aes_ccm;
mod aes_cmac;
mod aes_ctr;
mod aes_gcm;
mod aes_gmac;
mod bf_cbc;
mod des;
mod hash;
mod hmac;
mod pem_to;
pub mod rc4;
mod rsa;

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum CryptographicError {
    #[error("Error in AesGcm: insufficient buffer size.")]
    InsufficientBufferSize,
    #[error("Error in AesCcm: unable to encrypt.")]
    AesCcmUnableToEncrypt,
    #[error("Error in AesGmac: {0}.")]
    AesGmacError(String),
    #[error("Invalid length of key in AesCmac {0}.")]
    AesCmacInvalidLength(digest::InvalidLength),
    #[error("Error in RSA: {0}.")]
    Rsa(String),
    #[error("Error in RC4: {0}.")]
    Rc4(String),
}

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
) -> Result<&'a [u8], ArgumentError> {
    match register.nasl_value(key) {
        Ok(NaslValue::Data(x)) => Ok(x.as_slice()),
        Ok(NaslValue::String(x)) => Ok(x.as_bytes()),
        Ok(x) => Err(ArgumentError::wrong_argument(
            key,
            "a String or Data Value",
            format!("{x:?}").as_str(),
        )),
        _ => Err(ArgumentError::MissingNamed(vec![key.into()])),
    }
}

/// Get named argument of Type Number from the register with appropriate error handling.
/// In case the argument is required, the returned value is either an Error or the Option is always
/// set to Some value. If it is false, no error will be returned but the Option can be either Some
/// or None.
fn get_optional_named_number(register: &Register, key: &str) -> Result<Option<i64>, ArgumentError> {
    match register.nasl_value(key) {
        Ok(NaslValue::Number(x)) => Ok(Some(*x)),
        Ok(x) => Err(ArgumentError::wrong_argument(
            key,
            "a Number Value",
            format!("{x:?}").as_str(),
        )),
        _ => Ok(None),
    }
}

/// Get the required key argument or error.
fn get_key(register: &Register) -> Result<&[u8], ArgumentError> {
    get_required_named_data(register, "key")
}

/// Get the required data argument or error.
fn get_data(register: &Register) -> Result<&[u8], ArgumentError> {
    get_required_named_data(register, "data")
}

/// Get the required iv argument or error.
fn get_iv(register: &Register) -> Result<&[u8], ArgumentError> {
    get_required_named_data(register, "iv")
}

/// Get the required iv argument or error.
fn get_aad(register: &Register) -> Result<&[u8], ArgumentError> {
    get_required_named_data(register, "aad")
}

/// Get the optional len argument with proper error handling.
fn get_len(register: &Register) -> Result<Option<usize>, ArgumentError> {
    let buf = get_optional_named_number(register, "len")?;
    match buf {
        None => Ok(None),
        Some(x) => match x.try_into() {
            Ok(y) => Ok(Some(y)),
            Err(_) => Err(ArgumentError::WrongArgument(format!(
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
        set.add_set(rsa::Rsa);
        set.add_set(bf_cbc::BfCbc);
        set.add_set(pem_to::PemTo);
        set
    }
}
