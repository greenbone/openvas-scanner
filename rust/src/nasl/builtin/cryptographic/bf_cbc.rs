// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use blowfish::{
    cipher::{
        block_padding::{NoPadding, ZeroPadding},
        BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
        KeyIvInit,
    },
    Blowfish,
};
use cbc::{Decryptor, Encryptor};

use crate::nasl::prelude::*;

use super::{get_data, get_iv, get_key, get_len, Crypt};

/// Base function for en- and decrypting Cipher Block Chaining (CBC) mode
fn cbc<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FnError>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get Arguments
    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            let res = Encryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(encryptor) => Ok(encryptor.encrypt_padded_vec_mut::<ZeroPadding>(data).into()),
                Err(e) => Err(ArgumentError::WrongArgument(e.to_string()).into()),
            }
        }
        Crypt::Decrypt => {
            // length for encrypted data
            let len = match get_len(register)? {
                Some(x) => x,
                None => data.len(),
            };

            // len should not be more than the length of the data
            if len > data.len() {
                return Err(ArgumentError::wrong_argument(
                    "len",
                    format!("<={:?}", data.len()).as_str(),
                    len.to_string().as_str(),
                )
                .into());
            }
            let res = Decryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(decryptor) => Ok(decryptor
                    .decrypt_padded_vec_mut::<NoPadding>(data)
                    .map_err(|e| ArgumentError::WrongArgument(e.to_string()))?[..len]
                    .to_vec()
                    .into()),
                Err(e) => Err(ArgumentError::WrongArgument(e.to_string()).into()),
            }
        }
    }
}

/// NASL function to encrypt data with blowfish cbc.
///
/// Encrypt the plaintext data using the blowfish algorithm in CBC mode
/// with the key key and the initialization vector iv.  The key must be
/// 16 bytes long.  The iv must be at least 8 bytes long. Data must be a
/// multiple of 8 bytes long.
///
/// The return value is an array a with a[0] being the encrypted data and
/// a[1] the new initialization vector to use for the next part of the
/// data.
#[nasl_function]
fn bf_cbc_encrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<Blowfish>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with blowfish cbc.
///
/// Decrypt the cipher text data using the blowfish algorithm in CBC mode
/// with the key key and the initialization vector iv.  The key must be
/// 16 bytes long.  The iv must be at least 8 bytes long.  data must be a
/// multiple of 8 bytes long.
///
/// The return value is an array a with a[0] being the plaintext data
/// and a[1] the new initialization vector to use for the next part of
/// the data.
#[nasl_function]
fn bf_cbc_decrypt(register: &Register) -> Result<NaslValue, FnError> {
    cbc::<Blowfish>(register, Crypt::Decrypt)
}

pub struct BfCbc;

function_set! {
    BfCbc,
    (
        bf_cbc_encrypt,
        bf_cbc_decrypt,
    )
}
