// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use aes::{Aes128, Aes192, Aes256};
use ccm::{
    aead::{Aead, Error as aError, Payload},
    consts::{U10, U11, U12, U13, U14, U16, U4, U6, U7, U8, U9},
    Ccm, KeyInit, NonceSize, TagSize,
};
use digest::generic_array::ArrayLength;

use crate::{error::FunctionErrorKind, Context, NaslFunction, NaslValue, Register};

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
        Err(_) => Err(crate::error::FunctionErrorKind::GeneralError(
            "unable to en-/decrypt data".to_string(),
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
    fn aes128_ccm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("5a33980e71e7d67fd6cf171454dc96e5");
        data = hexstr_to_data("a34dfa24847c365291ce1b54bcf8d9a75d861e5133cc3a74");
        iv = hexstr_to_data("33ae68ebb8010c6b3da6b9cb29");
        aad = hexstr_to_data("eca622a37570df619e10ebb18bebadb2f2b49c4d2b2ff715873bb672e30fc0ff");
        crypt = aes128_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes128_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("7a60fa7ee8859e283cce378fb6b95522ab8b70efcdb0265f7c4b4fa597666b86dd1353e400f28864").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("a34dfa24847c365291ce1b54bcf8d9a75d861e5133cc3a74").unwrap()
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
    fn aes192_ccm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("50925853a84a33ff392154e4e737efc18dcfc98f4d5235a9");
        data = hexstr_to_data("718f061e8b972a3adcf465d66c5b28e8661f080127f6722f");
        iv = hexstr_to_data("809343e986f6ff47f54d4cac22");
        aad = hexstr_to_data("d70aef3532bdc5293a3ebb11589ac1f801c9f93ea0d656e1d04068facf9f768b");
        crypt = aes192_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes192_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("bad3b0e6772e9c4c9c631c095e259d99692292932efb72b8966e91a19617bb748f3495aa433585bb").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("718f061e8b972a3adcf465d66c5b28e8661f080127f6722f").unwrap()
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

    #[test]
    fn aes256_ccm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("2e6e34070caf1b8820ed39edfa83459abe1c15a1827f1c39f7ac316c4c27910f");
        data = hexstr_to_data("771a7baa9cf83aa253349f6475d5e74dba4525307b022ba7");
        iv = hexstr_to_data("c49ccef869bb86d21932cb443b");
        aad = hexstr_to_data("d37e35d7cdccd9824a1ae4c787819735e4af798a3beb49d4705336d6496853ad");
        crypt = aes256_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes256_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("eebac2475004970071dfa2cfb855c4e78b1add8dcbccfc0bd6b14027324b657a56263df148665393").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("771a7baa9cf83aa253349f6475d5e74dba4525307b022ba7").unwrap()
            )))
        );
    }
}
