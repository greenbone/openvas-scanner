// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;
#[cfg(test)]
mod tests {
    use super::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn aes_mac_cbc() {
        let code = r#"
        key = hexstr_to_data("e3ceb929b52a6eec02b99b13bf30721b");
        data = hexstr_to_data("d2e8a3e86ae0b9edc7cc3116d929a16f13ee3643");
        crypt = aes_mac_cbc(key: key, data: data);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("10f3d29e89e4039b85e16438b2b2a470").unwrap()
            )))
        );
    }
}
