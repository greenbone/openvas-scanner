// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_builtin_utils::error::FunctionErrorKind;
use nasl_builtin_utils::{Context, NaslFunction};

use nasl_builtin_utils::{ContextType, Register};
use nasl_syntax::NaslValue;

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_cmac;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod aes_gmac;
pub mod des;
pub mod hash;
pub mod hmac;

enum Crypt {
    Encrypt,
    Decrypt,
}

/// Decodes given string as hex and returns the result as a byte array
// TODO only used in tests, move tests to its own module and define there

pub(crate) fn lookup<K>(function_name: &str) -> Option<NaslFunction<K>>
where
    K: AsRef<str>,
{
    aes_ccm::lookup(function_name)
        .or_else(|| hmac::lookup(function_name))
        .or_else(|| aes_cbc::lookup(function_name))
        .or_else(|| aes_ctr::lookup(function_name))
        .or_else(|| aes_gcm::lookup(function_name))
        .or_else(|| aes_cmac::lookup(function_name))
        .or_else(|| aes_gmac::lookup(function_name))
        .or_else(|| hash::lookup(function_name))
        .or_else(|| des::lookup(function_name))
}

pub struct Cryptographic;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Cryptographic {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<K>(name).is_some()
    }
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
        Some(x) => Err((key, "a String or Data Value", format!("{:?}", x).as_str()).into()),
        _ => Err((key).into()),
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
        Some(x) => Err((key, "a Number Value", format!("{:?}", x).as_str()).into()),
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
