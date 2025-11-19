// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use aes::{Aes128, Aes192, Aes256};
use ccm::{
    Ccm, KeyInit, NonceSize, TagSize,
    aead::{Aead, Error as aError, Payload},
    consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16},
};
use digest::generic_array::ArrayLength;

use crate::nasl::prelude::*;

use super::{Crypt, CryptographicError};

/// Core function to en- and decrypt data. Throws error in case of failure.
fn ccm_crypt<D, M, N>(
    crypt: Crypt,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, aError>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    let cipher = Ccm::<D, M, N>::new(key.into());
    let payload = Payload { msg: data, aad };
    match crypt {
        Crypt::Encrypt => cipher.encrypt(nonce.into(), payload),
        Crypt::Decrypt => cipher.decrypt(nonce.into(), payload),
    }
}

/// Base function for ccm en- and decryption. Sets the tag length to 16.
fn ccm<D>(
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    tag_size: Option<usize>,
    aad: Option<&[u8]>,
    crypt: Crypt,
) -> Result<NaslValue, FnError>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get parameters

    let tag_size = tag_size.unwrap_or(16);
    let aad = aad.unwrap_or_default();

    // Switch mode dependent on iv length
    let res = ccm_typed::<D>(tag_size, nonce.len(), crypt, key, nonce, data, aad)?;

    // Error handling
    match res {
        Ok(x) => Ok(NaslValue::Data(x)),
        Err(_) => Err(CryptographicError::AesCcmUnableToEncrypt.into()),
    }
}

/// NASL function to encrypt data with aes128 ccm.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data))]
fn aes128_ccm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ccm::<Aes128>(key, data, iv, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes128 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad))]
fn aes128_ccm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes128>(key, data, iv, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt aes128 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, len))]
fn aes128_ccm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes128>(key, data, iv, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes128 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad, len))]
fn aes128_ccm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes128>(key, data, iv, len, aad, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 ccm. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data))]
fn aes192_ccm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ccm::<Aes192>(key, data, iv, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes192 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad))]
fn aes192_ccm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes192>(key, data, iv, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt aes192 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, len))]
fn aes192_ccm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes192>(key, data, iv, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes192 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad, len))]
fn aes192_ccm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes192>(key, data, iv, len, aad, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ccm. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data))]
fn aes256_ccm_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    ccm::<Aes256>(key, data, iv, None, None, Crypt::Encrypt)
}

/// NASL function to encrypt data with aes256 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad))]
fn aes256_ccm_encrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes256>(key, data, iv, None, aad, Crypt::Encrypt)
}

/// NASL function to decrypt aes256 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, len))]
fn aes256_ccm_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes256>(key, data, iv, len, None, Crypt::Decrypt)
}

/// NASL function to decrypt data with aes256 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
#[nasl_function(named(key, iv, data, aad, len))]
fn aes256_ccm_decrypt_auth(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
    len: Option<usize>,
) -> Result<NaslValue, FnError> {
    ccm::<Aes256>(key, data, iv, len, aad, Crypt::Decrypt)
}

macro_rules! ccm_call_typed {
    ($(($t1s: expr, $t1: ty) => $(($t2s: expr, $t2: ty)),*);*) => {
        fn ccm_typed<D>(tag_size: usize, iv_size: usize, crypt: Crypt, key: &[u8], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Result<Vec<u8>, aError>, FnError>
        where D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit
        {
            match tag_size {
                $(
                    $t1s => {
                        match iv_size {
                            $(
                                $t2s => {
                                    Ok(ccm_crypt::<D, $t1, $t2>(crypt, key, nonce, data, aad))
                                }
                            ),*
                            other => Err(FnError::wrong_unnamed_argument("iv must be between 7 and 13", other.to_string().as_str()))
                        }
                    }
                ),*
                other => Err(FnError::wrong_unnamed_argument("tag_size must be 4, 6, 8, 10, 12, 14 or 16", other.to_string().as_str()))
            }
         }
     }
 }

ccm_call_typed!(
    (4, U4) => (7, U7), (8, U8), (9, U9), (10, U10), (11, U11), (12, U12), (13, U13);
    (6, U6) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13) ;
    (8, U8) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13) ;
    (10, U10) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13) ;
    (12, U12) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13) ;
    (14, U14) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13) ;
    (16, U16) => (7, U7) , (8, U8) , (9, U9) , (10, U10) , (11, U11) , (12, U12) , (13, U13)
);

pub struct AesCcm;

function_set! {
    AesCcm,
    (
        aes128_ccm_encrypt,
        aes128_ccm_encrypt_auth,
        aes128_ccm_decrypt,
        aes128_ccm_decrypt_auth,
        aes192_ccm_encrypt,
        aes192_ccm_encrypt_auth,
        aes192_ccm_decrypt,
        aes192_ccm_decrypt_auth,
        aes256_ccm_encrypt,
        aes256_ccm_encrypt_auth,
        aes256_ccm_decrypt,
        aes256_ccm_decrypt_auth,
    )
}
