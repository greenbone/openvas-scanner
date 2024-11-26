// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use digest::Digest;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::nasl::prelude::*;
use crate::nasl::utils::function::StringOrData;

fn nasl_hash<D: Digest>(data: Option<StringOrData>) -> Result<NaslValue, FnError>
where
    D::OutputSize: std::ops::Add,
    <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8>,
{
    if let Some(data) = data {
        let mut hash = D::new();
        hash.update(data.0.as_bytes());
        Ok(NaslValue::Data(hash.finalize().as_slice().to_vec()))
    } else {
        Ok(NaslValue::Null)
    }
}

/// NASL function to get MD2 hash
#[nasl_function]
pub fn hash_md2(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Md2>(data)
}

/// NASL function to get MD4 hash
#[nasl_function]
pub fn hash_md4(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Md4>(data)
}

/// NASL function to get MD5 hash
#[nasl_function]
pub fn hash_md5(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Md5>(data)
}

/// NASL function to get SHA1 hash
#[nasl_function]
pub fn hash_sha1(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Sha1>(data)
}

/// NASL function to get SHA256 hash
#[nasl_function]
pub fn hash_sha256(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Sha256>(data)
}

/// NASL function to get SHA512 hash
#[nasl_function]
pub fn hash_sha512(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Sha512>(data)
}

/// NASL function to get RIPemd160 hash
#[nasl_function]
pub fn hash_ripemd160(data: Option<StringOrData>) -> Result<NaslValue, FnError> {
    nasl_hash::<Ripemd160>(data)
}

pub struct Hash;

function_set! {
    Hash,
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
