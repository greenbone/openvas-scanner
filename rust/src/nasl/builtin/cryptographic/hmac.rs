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
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::nasl::prelude::*;

fn hmac<D>(key: &str, data: &str) -> Result<NaslValue, FnError>
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
    let mut hmac = match Hmac::<D>::new_from_slice(key.as_bytes()) {
        Ok(x) => x,
        Err(InvalidLength) => {
            return Err(FnError::wrong_unnamed_argument(
                "valid size key",
                "invalid size key",
            ))
        }
    };
    hmac.update(data.as_bytes());
    Ok(NaslValue::String(encode(
        hmac.finalize().into_bytes().as_slice(),
    )))
}

/// NASL function to get HMAC MD2 string
#[nasl_function(named(key, data))]
pub fn hmac_md2(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Md2>(key, data)
}

/// NASL function to get HMAC MD5 string
#[nasl_function(named(key, data))]
pub fn hmac_md5(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Md5>(key, data)
}

/// NASL function to get HMAC RIPEMD160 string
#[nasl_function(named(key, data))]
pub fn hmac_ripemd160(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Ripemd160>(key, data)
}

/// NASL function to get HMAC SHA1 string
#[nasl_function(named(key, data))]
pub fn hmac_sha1(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Sha1>(key, data)
}

/// NASL function to get HMAC SHA256 string
#[nasl_function(named(key, data))]
pub fn hmac_sha256(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Sha256>(key, data)
}

/// NASL function to get HMAC SHA384 string
#[nasl_function(named(key, data))]
pub fn hmac_sha384(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Sha384>(key, data)
}

/// NASL function to get HMAC SHA512 string
#[nasl_function(named(key, data))]
pub fn hmac_sha512(key: &str, data: &str) -> Result<NaslValue, FnError> {
    hmac::<Sha512>(key, data)
}

pub struct HmacFns;

function_set! {
    HmacFns,
    (
        (hmac_md2, "HMAC_MD2"),
        (hmac_md5, "HMAC_MD5"),
        (hmac_ripemd160, "HMAC_RIPEMD160"),
        (hmac_sha1, "HMAC_SHA1"),
        (hmac_sha256, "HMAC_SHA256"),
        (hmac_sha384, "HMAC_SHA384"),
        (hmac_sha512, "HMAC_SHA512"),
    )
}
