// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;

#[cfg(test)]
mod tests {

    use crate::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn aes128_ctr_crypt() {
        let code = r#"
        key = hexstr_to_data("2b7e151628aed2a6abf7158809cf4f3c");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes128_ctr_encrypt(key: key, data: data, iv: iv);
        aes128_ctr_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("874d6191b620e3261bef6864990db6ce").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_ctr_crypt() {
        let code = r#"
        key = hexstr_to_data("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes192_ctr_encrypt(key: key, data: data, iv: iv);
        aes192_ctr_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("1abc932417521ca24f2b0459fe7e6e0b").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_ctr_crypt() {
        let code = r#"
        key = hexstr_to_data("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        data = hexstr_to_data("6bc1bee22e409f96e93d7e117393172a");
        iv = hexstr_to_data("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        crypt = aes256_ctr_encrypt(key: key, data: data, iv: iv);
        aes256_ctr_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("601ec313775789a5b7a7f504bbf3d228").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
            )))
        );
    }
}
