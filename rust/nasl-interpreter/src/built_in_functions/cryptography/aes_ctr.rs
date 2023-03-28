// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{error::FunctionErrorKind, Context};
use aes::{
    cipher::{
        BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyIvInit, StreamCipher,
        StreamCipherSeek,
    },
    Aes128, Aes192, Aes256,
};
use digest::typenum::U16;

use crate::{NaslFunction, NaslValue, Register};

use super::{get_data, get_iv, get_key, get_len, Crypt};

fn ctr<D>(register: &Register, crypt: Crypt) -> Result<NaslValue, FunctionErrorKind>
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
    let data_len = data.len();
    let iv = get_iv(register)?;
    let len = match get_len(register)? {
        Some(x) => x,
        None => data_len,
    };

    let mut cipher = ctr::Ctr64BE::<D>::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            cipher.apply_keystream(&mut buf);
            Ok(buf.to_vec().into())
        }
        Crypt::Decrypt => {
            cipher.seek(0u32);
            cipher.apply_keystream(&mut buf);
            Ok(buf[..len].to_vec().into())
        }
    }
}

/// NASL function to encrypt data with aes128 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes128_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes128>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes128 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes128_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes128>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes192 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes192_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes192>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes192 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes192_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes192>(register, Crypt::Decrypt)
}

/// NASL function to encrypt data with aes256 ctr.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes256_ctr_encrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes256>(register, Crypt::Encrypt)
}

/// NASL function to decrypt data with aes256 ctr.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes. It is used as the initial counter.
fn aes256_ctr_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    ctr::<Aes256>(register, Crypt::Decrypt)
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_ctr_encrypt" => Some(aes128_ctr_encrypt),
        "aes128_ctr_decrypt" => Some(aes128_ctr_decrypt),
        "aes192_ctr_encrypt" => Some(aes192_ctr_encrypt),
        "aes192_ctr_decrypt" => Some(aes192_ctr_decrypt),
        "aes256_ctr_encrypt" => Some(aes256_ctr_encrypt),
        "aes256_ctr_decrypt" => Some(aes256_ctr_decrypt),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use nasl_syntax::parse;

    use crate::{helper::decode_hex, DefaultContext, Interpreter, Register};

    #[test]
    fn aes128_ctr_crypt() {
        let code = r###"
        key = hexstr_to_data("2b7e151628aed2a6abf7158809cf4f3c");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes128_ctr_encrypt(key: key, data: data, iv: iv);
        aes128_ctr_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("874d6191b620e3261bef6864990db6ce").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_ctr_crypt() {
        let code = r###"
        key = hexstr_to_data("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes192_ctr_encrypt(key: key, data: data, iv: iv);
        aes192_ctr_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("1abc932417521ca24f2b0459fe7e6e0b").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_ctr_crypt() {
        let code = r###"
        key = hexstr_to_data("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes256_ctr_encrypt(key: key, data: data, iv: iv);
        aes256_ctr_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("601ec313775789a5b7a7f504bbf3d228").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }
}
