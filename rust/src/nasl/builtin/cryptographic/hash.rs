// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::function_set;
use crate::nasl::utils::error::FunctionErrorKind;
use digest::Digest;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::{Context, Register};

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
pub fn hash_md2(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md2>(register)
}

/// NASL function to get MD4 hash
pub fn hash_md4(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md4>(register)
}

/// NASL function to get MD5 hash
pub fn hash_md5(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Md5>(register)
}

/// NASL function to get SHA1 hash
pub fn hash_sha1(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha1>(register)
}

/// NASL function to get SHA256 hash
pub fn hash_sha256(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha256>(register)
}

/// NASL function to get SHA512 hash
pub fn hash_sha512(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Sha512>(register)
}

/// NASL function to get RIPemd160 hash
pub fn hash_ripemd160(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    nasl_hash::<Ripemd160>(register)
}

pub struct Hash;

function_set! {
    Hash,
    sync_stateless,
    (
        (hash_md2, "MD2"),
        (hash_md4, "MD4"),
        (hash_md5, "MD5"),
        (hash_ripemd160, "RIPEMD160"),
        (hash_sha1, "SHA1"),
        (hash_sha256, "SHA256"),
        (hash_sha512, "SHA512"),
    )
}
