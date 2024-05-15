// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;
#[cfg(test)]
mod tests {

    use super::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn aes128_cbc_crypt() {
        let code = r#"
        key = hexstr_to_data("00000000000000000000000000000000");
        data = hexstr_to_data("80000000000000000000000000000000");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes128_cbc_encrypt(key: key, data: data, iv: iv);
        aes128_cbc_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("3ad78e726c1ec02b7ebfe92b23d9ec34").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("80000000000000000000000000000000").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_cbc_crypt() {
        let code = r#"
        key = hexstr_to_data("000000000000000000000000000000000000000000000000");
        data = hexstr_to_data("1b077a6af4b7f98229de786d7516b639");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes192_cbc_encrypt(key: key, data: data, iv: iv);
        aes192_cbc_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("275cfc0413d8ccb70513c3859b1d0f72").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("1b077a6af4b7f98229de786d7516b639").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_cbc_crypt() {
        let code = r#"
        key = hexstr_to_data("0000000000000000000000000000000000000000000000000000000000000000");
        data = hexstr_to_data("014730f80ac625fe84f026c60bfd547d");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes256_cbc_encrypt(key: key, data: data, iv: iv);
        aes256_cbc_decrypt(key: key, data: crypt, iv: iv);
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
                decode_hex("5c9d844ed46f9885085e5d6a4f94c7d7").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("014730f80ac625fe84f026c60bfd547d").unwrap()
            )))
        );
    }

    #[test]
    fn padding() {
        let code = r#"
        key = hexstr_to_data("00000000000000000000000000000000");
        data1 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f2");
        data2 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f20000");
        iv = hexstr_to_data("00000000000000000000000000000000");
        aes128_cbc_encrypt(key: key, data: data1, iv: iv);
        aes128_cbc_encrypt(key: key, data: data2, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        let crypt1 = parser.next();
        let crypt2 = parser.next();
        assert_eq!(crypt1, crypt2);
    }
}
