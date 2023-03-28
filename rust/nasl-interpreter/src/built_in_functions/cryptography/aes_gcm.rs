// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::{FunctionErrorKind, FunctionErrorKind::GeneralError},
    Context,
};
use aes::{
    cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
    Aes128, Aes192, Aes256,
};
use aes_gcm::{
    aead::{Aead, Payload},
    AesGcm,
};
use digest::typenum::{U12, U16};

use crate::{NaslFunction, NaslValue, Register};

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
        Err(_) => Err(GeneralError("Authentication failed".to_string())),
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

#[cfg(test)]
mod tests {

    use nasl_syntax::parse;

    use crate::{helper::decode_hex, DefaultContext, Interpreter, Register};

    #[test]
    fn aes128_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
        data = hexstr_to_data("d5de42b461646c255c87bd2962d3b9a2");
        iv = hexstr_to_data("ee283a3fc75575e33efd4887");
        crypt = aes128_gcm_encrypt(key: key, data: data, iv: iv);
        aes128_gcm_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("d5de42b461646c255c87bd2962d3b9a2").unwrap()
            )))
        );
    }

    #[test]
    fn aes128_gcm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("c939cc13397c1d37de6ae0e1cb7c423c");
        data = hexstr_to_data("c3b3c41f113a31b73d9a5cd432103069");
        iv = hexstr_to_data("b3d8cc017cbb89b39e0f67e2");
        aad = hexstr_to_data("24825602bd12a984e0092d3e448eda5f");
        crypt = aes128_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes128_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
                decode_hex("93fe7d9e9bfd10348a5606e5cafa73540032a1dc85f1c9786925a2e71d8272dd")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("c3b3c41f113a31b73d9a5cd432103069").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f");
        data = hexstr_to_data("d2ae38c4375954835d75b8e4c2f9bbb4");
        iv = hexstr_to_data("5f4b43e811da9c470d6a9b01");
        crypt = aes192_gcm_encrypt(key: key, data: data, iv: iv);
        aes192_gcm_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("69482957e6be5c54882d00314e0259cf191e9f29bef63a26860c1e020a21137e")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("d2ae38c4375954835d75b8e4c2f9bbb4").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_gcm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("6f44f52c2f62dae4e8684bd2bc7d16ee7c557330305a790d");
        data = hexstr_to_data("37222d30895eb95884bbbbaee4d9cae1");
        iv = hexstr_to_data("9ae35825d7c7edc9a39a0732");
        aad = hexstr_to_data("1b4236b846fc2a0f782881ba48a067e9");
        crypt = aes192_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes192_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
                decode_hex("a54b5da33fc1196a8ef31a5321bfcaeb1c198086450ae1834dd6c2636796bce2")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("37222d30895eb95884bbbbaee4d9cae1").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22");
        data = hexstr_to_data("2db5168e932556f8089a0622981d017d");
        iv = hexstr_to_data("0d18e06c7c725ac9e362e1ce");
        crypt = aes256_gcm_encrypt(key: key, data: data, iv: iv);
        aes256_gcm_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("2db5168e932556f8089a0622981d017d").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_gcm_crypt_auth() {
        let code = r###"
        key = hexstr_to_data("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");
        data = hexstr_to_data("2d71bcfa914e4ac045b2aa60955fad24");
        iv = hexstr_to_data("ac93a1a6145299bde902f21a");
        aad = hexstr_to_data("1e0889016f67601c8ebea4943bc23ad6");
        crypt = aes256_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes256_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
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
                decode_hex("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab")
                    .unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("2d71bcfa914e4ac045b2aa60955fad24").unwrap()
            )))
        );
    }

    #[test]
    fn padding() {
        let code = r###"
        key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
        data1 = hexstr_to_data("d5de42b461646c255c87bd29");
        data2 = hexstr_to_data("d5de42b461646c255c87bd2900000000");
        iv = hexstr_to_data("ee283a3fc75575e33efd4887");
        aes128_gcm_encrypt(key: key, data: data1, iv: iv);
        aes128_gcm_encrypt(key: key, data: data2, iv: iv);
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
        let crypt1 = parser.next();
        let crypt2 = parser.next();
        assert_eq!(crypt1, crypt2);
    }
}
