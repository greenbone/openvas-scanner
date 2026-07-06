// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::function_set;
use crate::nasl::{prelude::*, utils::function::StringOrData};
use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockCipher, BlockEncrypt, BlockSizeUser},
};
use aes_gcm::{
    AesGcm, Nonce,
    aead::{AeadInPlace, generic_array::ArrayLength},
};
use digest::typenum::{U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16};

use super::CryptographicError;

pub fn aes_gmac(data: &[u8], key: &[u8], iv: &[u8]) -> Result<NaslValue, FnError> {
    if key.is_empty() {
        return Err(CryptographicError::AesGmacError("Missing key".to_string()).into());
    }
    if data.is_empty() {
        return Err(CryptographicError::AesGmacError("Missing value".to_string()).into());
    }
    if iv.is_empty() {
        return Err(CryptographicError::AesGmacError("General error".to_string()).into());
    }

    match key.len() {
        16 => aes_gmac_with_key::<Aes128>(data, key, iv),
        24 => aes_gmac_with_key::<Aes192>(data, key, iv),
        32 => aes_gmac_with_key::<Aes256>(data, key, iv),
        _ => Err(CryptographicError::AesGmacError("Invalid key length".to_string()).into()),
    }
}

fn aes_gmac_with_key<D>(data: &[u8], key: &[u8], iv: &[u8]) -> Result<NaslValue, FnError>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + aes::cipher::KeyInit,
{
    match iv.len() {
        1 => aes_gmac_with_nonce::<D, U1>(data, key, iv),
        2 => aes_gmac_with_nonce::<D, U2>(data, key, iv),
        3 => aes_gmac_with_nonce::<D, U3>(data, key, iv),
        4 => aes_gmac_with_nonce::<D, U4>(data, key, iv),
        5 => aes_gmac_with_nonce::<D, U5>(data, key, iv),
        6 => aes_gmac_with_nonce::<D, U6>(data, key, iv),
        7 => aes_gmac_with_nonce::<D, U7>(data, key, iv),
        8 => aes_gmac_with_nonce::<D, U8>(data, key, iv),
        9 => aes_gmac_with_nonce::<D, U9>(data, key, iv),
        10 => aes_gmac_with_nonce::<D, U10>(data, key, iv),
        11 => aes_gmac_with_nonce::<D, U11>(data, key, iv),
        12 => aes_gmac_with_nonce::<D, U12>(data, key, iv),
        13 => aes_gmac_with_nonce::<D, U13>(data, key, iv),
        14 => aes_gmac_with_nonce::<D, U14>(data, key, iv),
        15 => aes_gmac_with_nonce::<D, U15>(data, key, iv),
        16 => aes_gmac_with_nonce::<D, U16>(data, key, iv),
        _ => Err(CryptographicError::AesGmacError("Invalid IV length".to_string()).into()),
    }
}

fn aes_gmac_with_nonce<D, N>(data: &[u8], key: &[u8], iv: &[u8]) -> Result<NaslValue, FnError>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + aes::cipher::KeyInit,
    N: ArrayLength<u8>,
{
    use aes_gcm::KeyInit;

    let cipher = AesGcm::<D, N>::new_from_slice(key)
        .map_err(|_| CryptographicError::AesGmacError("Invalid key length".to_string()))?;
    let mut empty_plaintext = [];
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<N>::from_slice(iv), data, &mut empty_plaintext)
        .map_err(|_| CryptographicError::AesGmacError("Unable to calculate GMAC".to_string()))?;

    Ok(tag.to_vec().into())
}

/// NASL function to calculate GMAC with AES128.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
#[nasl_function(named(key, iv, data))]
fn nasl_aes_gmac(
    key: StringOrData,
    iv: StringOrData,
    data: StringOrData,
) -> Result<NaslValue, FnError> {
    aes_gmac(data.data(), key.data(), iv.data())
}

pub struct AesGmac;

function_set! {
    AesGmac,
    (
        (nasl_aes_gmac, "aes_mac_gcm"),
    )
}
