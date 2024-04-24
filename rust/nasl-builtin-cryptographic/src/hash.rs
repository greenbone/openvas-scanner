// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use digest::Digest;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use nasl_builtin_utils::error::FunctionErrorKind;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::NaslFunction;
use nasl_builtin_utils::{Context, Register};
use nasl_syntax::NaslValue;

fn nasl_hash<D: Digest>(register: &Register) -> Result<NaslValue, FunctionErrorKind>
where
    D::OutputSize: std::ops::Add,
    <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8>,
{
    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    };
    let data = match &positional[0] {
        NaslValue::String(x) => x.as_bytes(),
        NaslValue::Data(x) => x,
        NaslValue::Null => return Ok(NaslValue::Null),
        x => return Err(("data", "string", x).into()),
    };

    let mut hash = D::new();
    hash.update(data);
    Ok(NaslValue::Data(hash.finalize().as_slice().to_vec()))
}

/// NASL function to get MD2 hash
pub fn hash_md2<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md2>(register)
}

/// NASL function to get MD4 hash
pub fn hash_md4<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md4>(register)
}

/// NASL function to get MD5 hash
pub fn hash_md5<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md5>(register)
}

/// NASL function to get SHA1 hash
pub fn hash_sha1<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha1>(register)
}

/// NASL function to get SHA256 hash
pub fn hash_sha256<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha256>(register)
}

/// NASL function to get SHA512 hash
pub fn hash_sha512<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha512>(register)
}

/// NASL function to get RIPemd160 hash
pub fn hash_ripemd160<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Ripemd160>(register)
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "MD2" => Some(hash_md2),
        "MD4" => Some(hash_md4),
        "MD5" => Some(hash_md5),
        "RIPEMD160" => Some(hash_ripemd160),
        "SHA1" => Some(hash_sha1),
        "SHA256" => Some(hash_sha256),
        "SHA512" => Some(hash_sha512),
        _ => None,
    }
}
