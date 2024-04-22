// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    HashMarker, InvalidLength,
};
use hex::encode;
use hmac::{Hmac, Mac};
use md2::Md2;
use md5::Md5;
use nasl_builtin_utils::error::FunctionErrorKind;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::NaslFunction;
use nasl_builtin_utils::{Context, ContextType, Register};
use nasl_syntax::NaslValue;

fn hmac<D>(register: &Register) -> Result<NaslValue, FunctionErrorKind>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let key = match register.named("key") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        x => return Err(("key", "string", x).into()),
    };
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        x => return Err(("data", "string", x).into()),
    };
    let mut hmac = match Hmac::<D>::new_from_slice(key.as_bytes()) {
        Ok(x) => x,
        Err(InvalidLength) => return Err(("valid size key", "invalid size key").into()),
    };
    hmac.update(data.as_bytes());
    Ok(NaslValue::String(encode(
        hmac.finalize().into_bytes().as_slice(),
    )))
}

/// NASL function to get HMAC MD2 string
pub fn hmac_md2<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Md2>(register)
}

/// NASL function to get HMAC MD5 string
pub fn hmac_md5<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Md5>(register)
}

/// NASL function to get HMAC RIPEMD160 string
pub fn hmac_ripemd160<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Ripemd160>(register)
}

/// NASL function to get HMAC SHA1 string
pub fn hmac_sha1<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Sha1>(register)
}

/// NASL function to get HMAC SHA256 string
pub fn hmac_sha256<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Sha256>(register)
}

/// NASL function to get HMAC SHA384 string
pub fn hmac_sha384<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Sha384>(register)
}

/// NASL function to get HMAC SHA512 string
pub fn hmac_sha512<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    hmac::<Sha512>(register)
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "HMAC_MD2" => Some(hmac_md2),
        "HMAC_MD5" => Some(hmac_md5),
        "HMAC_RIPEMD160" => Some(hmac_ripemd160),
        "HMAC_SHA1" => Some(hmac_sha1),
        "HMAC_SHA256" => Some(hmac_sha256),
        "HMAC_SHA384" => Some(hmac_sha384),
        "HMAC_SHA512" => Some(hmac_sha512),
        _ => None,
    }
}
