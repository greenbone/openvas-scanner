// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// FunctionErrorKind::GeneralError
use aes::{
    cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
    Aes128, Aes192, Aes256,
};
use aes_gcm::{
    aead::{Aead, Payload},
    AesGcm,
};
use digest::typenum::{U12, U16};
use nasl_builtin_utils::{Context, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;

use crate::NaslFunction;

use super::{get_aad, get_data, get_iv, get_key, get_len, Crypt};

fn gcm<D>(register: &Register, crypt: Crypt, auth: bool) -> Result<NaslValue, FunctionErrorKind>
where
    D: BlockSizeUser<BlockSize = U16>
        + aes::cipher::KeyInit
        + BlockCipher
        + BlockEncrypt
        + BlockDecrypt,
{
    // Get data
    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;
    let len = get_len(register)?;
    let aad = match auth {
        true => get_aad(register)?,
        false => b"",
    };

    let cipher = AesGcm::<D, U12>::new(key.into());

    let mut payload = Payload { msg: data, aad };

    let res = match crypt {
        Crypt::Encrypt => {
            if data.len() % 16 != 0 {
                let blocks_len = data.len() + 16 - data.len() % 16;

                let mut vec = data.to_vec();
                while vec.len() < blocks_len {
                    vec.push(0);
                }
                payload.msg = vec.as_slice();
                cipher.encrypt(iv.into(), payload)
            } else {
                cipher.encrypt(iv.into(), payload)
            }
        }
        Crypt::Decrypt => cipher.decrypt(iv.into(), payload),
    };
    match res {
        Ok(x) => match crypt {
            Crypt::Decrypt => match len {
                Some(y) => Ok(x[..y].to_vec().into()),
                None => Ok(x.into()),
            },
            Crypt::Encrypt => Ok(x.into()),
        },
        Err(_) => Err(FunctionErrorKind::WrongArgument(
            "Authentication failed".to_string(),
        )),
    }
}

/// NASL function to encrypt data with aes128 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes128_gcm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes128>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes128 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes128_gcm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes128>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt data with aes128 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes128_gcm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes128>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes128 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes128_gcm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes128>(register, Crypt::Decrypt, true)
}

/// NASL function to encrypt data with aes192 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes192_gcm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes192>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes192 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes192_gcm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes192>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt data with aes192 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes192_gcm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes192>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes192 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes192_gcm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes192>(register, Crypt::Decrypt, true)
}

/// NASL function to encrypt data with aes256 gcm.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes256_gcm_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes256>(register, Crypt::Encrypt, false)
}

/// NASL function to encrypt data with aes256 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects 4 named arguments key, data, iv and aad either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The result contains the ciphertext and the calculated tag in a single data type.
/// - The tag has a size of 16 Bytes.
fn aes256_gcm_encrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes256>(register, Crypt::Encrypt, true)
}

/// NASL function to decrypt data with aes256 gcm.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes256_gcm_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes256>(register, Crypt::Decrypt, false)
}

/// NASL function to decrypt data with aes256 gcm and authentication encryption with associated data (AEAD).
///
/// This function expects up to 5 named arguments key, data, iv and aad either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
/// - The tag is needed as a postfix in the given data in order to decrypt successfully.
fn aes256_gcm_decrypt_auth<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    gcm::<Aes256>(register, Crypt::Decrypt, true)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_gcm_encrypt" => Some(aes128_gcm_encrypt),
        "aes128_gcm_encrypt_auth" => Some(aes128_gcm_encrypt_auth),
        "aes128_gcm_decrypt" => Some(aes128_gcm_decrypt),
        "aes128_gcm_decrypt_auth" => Some(aes128_gcm_decrypt_auth),
        "aes192_gcm_encrypt" => Some(aes192_gcm_encrypt),
        "aes192_gcm_encrypt_auth" => Some(aes192_gcm_encrypt_auth),
        "aes192_gcm_decrypt" => Some(aes192_gcm_decrypt),
        "aes192_gcm_decrypt_auth" => Some(aes192_gcm_decrypt_auth),
        "aes256_gcm_encrypt" => Some(aes256_gcm_encrypt),
        "aes256_gcm_encrypt_auth" => Some(aes256_gcm_encrypt_auth),
        "aes256_gcm_decrypt" => Some(aes256_gcm_decrypt),
        "aes256_gcm_decrypt_auth" => Some(aes256_gcm_decrypt_auth),
        _ => None,
    }
}
