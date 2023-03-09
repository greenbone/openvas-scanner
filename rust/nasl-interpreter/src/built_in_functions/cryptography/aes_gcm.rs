// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::FunctionErrorKind::GeneralError;
use aes::{
    cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
    Aes128, Aes192, Aes256,
};
use aes_gcm::{aead::Aead, AesGcm};
use digest::typenum::{U12, U16};
use sink::Sink;

use crate::{error::FunctionError, NaslFunction, NaslValue, Register};

use super::{get_named_data, get_named_number, Crypt};

fn gcm<D>(register: &Register, crypt: Crypt, function: &str) -> Result<NaslValue, FunctionError>
where
    D: BlockSizeUser<BlockSize = U16>
        + aes::cipher::KeyInit
        + BlockCipher
        + BlockEncrypt
        + BlockDecrypt,
{
    // Get data
    let key = get_named_data(register, "key", true, function)?.unwrap();
    let data = get_named_data(register, "data", true, function)?.unwrap();
    let iv = get_named_data(register, "iv", true, function)?.unwrap();
    let len = match get_named_number(register, "len", false, function)? {
        Some(x) => match usize::try_from(x) {
            Ok(x) => Some(x),
            Err(_) => {
                return Err(FunctionError::new(
                    function,
                    GeneralError(format!(
                        "System only supports numbers between {:?} and {:?}",
                        usize::MIN,
                        usize::MAX
                    )),
                ))
            }
        },
        None => None,
    };

    let cipher = AesGcm::<D, U12>::new(key.into());

    let res = match crypt {
        Crypt::Encrypt => {
            if data.len() % 16 != 0 {
                let blocks_len = data.len() + 16 - data.len() % 16;
                let mut vec = data.to_vec();
                while vec.len() < blocks_len {
                    vec.push(0);
                }
                cipher.encrypt(iv.into(), vec.as_slice())
            } else {
                cipher.encrypt(iv.into(), data)
            }
        }
        Crypt::Decrypt => cipher.decrypt(iv.into(), data),
    };
    match res {
        Ok(x) => match crypt {
            Crypt::Decrypt => match len {
                Some(y) => Ok(x[..y].to_vec().into()),
                None => Ok(x.into()),
            },
            Crypt::Encrypt => Ok(x.into()),
        },
        Err(_) => Err(FunctionError::new(
            function,
            GeneralError("Authentication failed".to_string()),
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
fn aes128_gcm_encrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes128>(register, Crypt::Encrypt, "aes128_gcm_encrypt")
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
fn aes128_gcm_decrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes128>(register, Crypt::Decrypt, "aes128_gcm_decrypt")
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
fn aes192_gcm_encrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes192>(register, Crypt::Encrypt, "aes192_gcm_encrypt")
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
fn aes192_gcm_decrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes192>(register, Crypt::Decrypt, "aes192_gcm_decrypt")
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
fn aes256_gcm_encrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes256>(register, Crypt::Encrypt, "aes256_gcm_encrypt")
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
fn aes256_gcm_decrypt(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    gcm::<Aes256>(register, Crypt::Decrypt, "aes256_gcm_decrypt")
}

pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "aes128_gcm_encrypt" => Some(aes128_gcm_encrypt),
        "aes128_gcm_decrypt" => Some(aes128_gcm_decrypt),
        "aes192_gcm_encrypt" => Some(aes192_gcm_encrypt),
        "aes192_gcm_decrypt" => Some(aes192_gcm_decrypt),
        "aes256_gcm_encrypt" => Some(aes256_gcm_encrypt),
        "aes256_gcm_decrypt" => Some(aes256_gcm_decrypt),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{helper::decode_hex, Interpreter, NoOpLoader, Register};

    #[test]
    fn aes128_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
        data = hexstr_to_data("d5de42b461646c255c87bd2962d3b9a2");
        iv = hexstr_to_data("ee283a3fc75575e33efd4887");
        crypt = aes128_gcm_encrypt(key: key, data: data, iv: iv);
        aes128_gcm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
    fn aes192_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f");
        data = hexstr_to_data("d2ae38c4375954835d75b8e4c2f9bbb4");
        iv = hexstr_to_data("5f4b43e811da9c470d6a9b01");
        crypt = aes192_gcm_encrypt(key: key, data: data, iv: iv);
        aes192_gcm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
    fn aes256_gcm_crypt() {
        let code = r###"
        key = hexstr_to_data("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22");
        data = hexstr_to_data("2db5168e932556f8089a0622981d017d");
        iv = hexstr_to_data("0d18e06c7c725ac9e362e1ce");
        crypt = aes256_gcm_encrypt(key: key, data: data, iv: iv);
        aes256_gcm_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
    fn padding() {
        let code = r###"
        key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
        data1 = hexstr_to_data("d5de42b461646c255c87bd29");
        data2 = hexstr_to_data("d5de42b461646c255c87bd2900000000");
        iv = hexstr_to_data("ee283a3fc75575e33efd4887");
        aes128_gcm_encrypt(key: key, data: data1, iv: iv);
        aes128_gcm_encrypt(key: key, data: data2, iv: iv);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
