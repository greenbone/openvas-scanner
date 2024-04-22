// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use aes::{Aes128, Aes192, Aes256};
use ccm::{
    aead::{Aead, Error as aError, Payload},
    consts::{U10, U11, U12, U13, U14, U16, U4, U6, U7, U8, U9},
    Ccm, KeyInit, NonceSize, TagSize,
};
use digest::generic_array::ArrayLength;
use nasl_builtin_utils::error::{FunctionErrorKind, GeneralErrorType};

use crate::NaslFunction;
use nasl_builtin_utils::{Context, Register};
use nasl_syntax::NaslValue;

use super::{get_aad, get_data, get_iv, get_key, get_len, Crypt};

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
fn ccm<D>(register: &Register, crypt: Crypt, auth: bool) -> Result<NaslValue, FunctionErrorKind>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get parameters
    let key = get_key(register)?;
    let data = get_data(register)?;
    let nonce = get_iv(register)?;
    let tag_size = get_len(register)?.unwrap_or(16);
    let aad = match auth {
        true => get_aad(register)?,
        false => b"",
    };
    // Switch mode dependent on iv length
    let res = ccm_typed::<D>(tag_size, nonce.len(), crypt, key, nonce, data, aad)?;

    // Error handling
    match res {
        Ok(x) => Ok(NaslValue::Data(x)),
        Err(_) => Err(FunctionErrorKind::GeneralError(
            GeneralErrorType::UnexpectedData("unable to en-/decrypt data".to_string()),
        )),
    }
}

/// NASL function to encrypt data with aes128 ccm.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes128_ccm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes128>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes128 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes128_ccm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes128>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt aes128 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes128_ccm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes128>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes128 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes128_ccm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes128>(register, Crypt::Decrypt, true)
}

/// NASL function to encrypt data with aes192 ccm. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes192_ccm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes192>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes192 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes192_ccm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes192>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt aes192 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes192_ccm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes192>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes192 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes192_ccm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes192>(register, Crypt::Decrypt, true)
}

/// NASL function to encrypt data with aes256 ccm. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes256_ccm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes256>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes256 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes256_ccm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes256>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt aes256 ccm encrypted data. The tag size is set to 16.
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes256_ccm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes256>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes256 ccm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 4 named arguments key, data and iv either in a string or data type.
/// Additionally the tag_size can be given as int.
/// - The length of the key should be 16 bytes long
/// - The iv must have a length of 7-13 bytes
/// - The tag_size default is 16, it can be set to either 4, 6, 8, 10, 12, 14 or 16
fn aes256_ccm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ccm::<Aes256>(register, Crypt::Decrypt, true)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_ccm_encrypt" => Some(aes128_ccm_encrypt),
        "aes128_ccm_encrypt_auth" => Some(aes128_ccm_encrypt_auth),
        "aes128_ccm_decrypt" => Some(aes128_ccm_decrypt),
        "aes128_ccm_decrypt_auth" => Some(aes128_ccm_decrypt_auth),
        "aes192_ccm_encrypt" => Some(aes192_ccm_encrypt),
        "aes192_ccm_encrypt_auth" => Some(aes192_ccm_encrypt_auth),
        "aes192_ccm_decrypt" => Some(aes192_ccm_decrypt),
        "aes192_ccm_decrypt_auth" => Some(aes192_ccm_decrypt_auth),
        "aes256_ccm_encrypt" => Some(aes256_ccm_encrypt),
        "aes256_ccm_encrypt_auth" => Some(aes256_ccm_encrypt_auth),
        "aes256_ccm_decrypt" => Some(aes256_ccm_decrypt),
        "aes256_ccm_decrypt_auth" => Some(aes256_ccm_decrypt_auth),
        _ => None,
    }
}

macro_rules! ccm_call_typed {
    ($(($t1s: expr, $t1: ty) => $(($t2s: expr, $t2: ty)),*);*) => {
        fn ccm_typed<D>(tag_size: usize, iv_size: usize, crypt: Crypt, key: &[u8], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Result<Vec<u8>, aError>, FunctionErrorKind>
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
                            other => Err(("iv must be between 7 and 13", other.to_string().as_str()).into())
                        }
                    }
                ),*
                other => Err(("tag_size must be 4, 6, 8, 10, 12, 14 or 16", other.to_string().as_str()).into())
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
