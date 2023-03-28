// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use ::aes::{Aes128, Aes192, Aes256};
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use ccm::{
    aead::{Aead, Error as aError},
    consts::{U10, U11, U12, U13, U14, U16, U4, U6, U7, U8, U9},
    Ccm, KeyInit, NonceSize, TagSize,
};
use digest::generic_array::ArrayLength;

use crate::{error::FunctionErrorKind, Context, NaslFunction, NaslValue, Register};

use super::{get_data, get_iv, get_key, get_len, Crypt};

/// Core function to en- and decrypt data. Throws error in case of failure.
fn ccm_crypt<D, M, N>(
    crypt: Crypt,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, aError>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    let cipher = Ccm::<D, M, N>::new(key.into());
    match crypt {
        Crypt::Encrypt => cipher.encrypt(nonce.into(), data),
        Crypt::Decrypt => cipher.decrypt(nonce.into(), data),
    }
}

/// Base function for ccm en- and decryption. Sets the tag length to 16.
fn ccm<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FunctionErrorKind>
where
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get parameters
    let key = get_key(register)?;
    let data = get_data(register)?;
    let nonce = get_iv(register)?;
    let tag_size = get_len(register)?.unwrap_or(16);
    // Switch mode dependent on iv length
    let res = ccm_typed::<D>(tag_size, nonce.len(), crypt, key, nonce, data)?;

    // Error handling
    match res {
        Ok(x) => Ok(NaslValue::Data(x)),
        Err(_) => Err(crate::error::FunctionErrorKind::GeneralError(
            "unable to en-/decrypt data".to_string(),
        )),
    }
}

/// NASL function to encrypt data with aes256 ccm. The tag size is set to 16.
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
    ccm::<Aes128>(register, Crypt::Encrypt)
}

/// NASL function to decrypt aes256 ccm encrypted data. The tag size is set to 16.
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
    ccm::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ccm. The tag size is set to 16.
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
    ccm::<Aes192>(register, Crypt::Encrypt)
}

/// NASL function to decrypt aes256 ccm encrypted data. The tag size is set to 16.
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
    ccm::<Aes192>(register, Crypt::Decrypt)
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
    ccm::<Aes256>(register, Crypt::Encrypt)
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
    ccm::<Aes256>(register, Crypt::Decrypt)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_ccm_encrypt" => Some(aes128_ccm_encrypt),
        "aes128_ccm_decrypt" => Some(aes128_ccm_decrypt),
        "aes192_ccm_encrypt" => Some(aes192_ccm_encrypt),
        "aes192_ccm_decrypt" => Some(aes192_ccm_decrypt),
        "aes256_ccm_encrypt" => Some(aes256_ccm_encrypt),
        "aes256_ccm_decrypt" => Some(aes256_ccm_decrypt),
        _ => None,
    }
}

macro_rules! ccm_call_typed {
    ($(($t1s: expr, $t1: ty) => $(($t2s: expr, $t2: ty)),*);*) => {
        fn ccm_typed<D>(tag_size: usize, iv_size: usize, crypt: Crypt, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Result<Vec<u8>, aError>, FunctionErrorKind>
        where D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit
        {
            match tag_size {
                $(
                    $t1s => {
                        match iv_size {
                            $(
                                $t2s => {
                                    Ok(ccm_crypt::<D, $t1, $t2>(crypt, key, nonce, data))
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

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;

    use crate::{helper::decode_hex, DefaultContext, Interpreter, Register};

    #[test]
    fn aes128_ccm_crypt() {
        let code = r###"
        key = hexstr_to_data("d24a3d3dde8c84830280cb87abad0bb3");
        data = hexstr_to_data("7c86135ed9c2a515aaae0e9a208133897269220f30870006");
        iv = hexstr_to_data("f1100035bb24a8d26004e0e24b");
        crypt = aes128_ccm_encrypt(key: key, data: data, iv: iv);
        aes128_ccm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("1faeb0ee2ca2cd52f0aa3966578344f24e69b742c4ab37ab1123301219c70599b7c373ad4b3ad67b").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("7c86135ed9c2a515aaae0e9a208133897269220f30870006").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_ccm_crypt() {
        let code = r###"
        key = hexstr_to_data("26511fb51fcfa75cb4b44da75a6e5a0eb8d9c8f3b906f886");
        data = hexstr_to_data("39f08a2af1d8da6212550639b91fb2573e39a8eb5d801de8");
        iv = hexstr_to_data("15b369889699b6de1fa3ee73e5");
        crypt = aes192_ccm_encrypt(key: key, data: data, iv: iv);
        aes192_ccm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("6342b8700edec97a960eb16e7cb1eb4412fb4e263ddd2206b090155d34a76c8324e5550c3ef426ed").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("39f08a2af1d8da6212550639b91fb2573e39a8eb5d801de8").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_ccm_crypt() {
        let code = r###"
        key = hexstr_to_data("26511fb51fcfa75cb4b44da75a6e5a0eb8d9c8f3b906f886df3ba3e6da3a1389");
        data = hexstr_to_data("30d56ff2a25b83fee791110fcaea48e41db7c7f098a81000");
        iv = hexstr_to_data("72a60f345a1978fb40f28a2fa4");
        crypt = aes256_ccm_encrypt(key: key, data: data, iv: iv);
        aes256_ccm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("55f068c0bbba8b598013dd1841fd740fda2902322148ab5e935753e601b79db4ae730b6ae3500731").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("30d56ff2a25b83fee791110fcaea48e41db7c7f098a81000").unwrap()
            )))
        );
    }
}
