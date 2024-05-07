// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;
    #[test]
    fn hmac_md2() {
        let code = r#"
        HMAC_MD2(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("9558b32badac84072d54422d05bd601a".into()))
        );
    }

    #[test]
    fn hmac_md5() {
        let code = r#"
        HMAC_MD5(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("815292959633f0e63666d90d6f47cb79".into()))
        );
    }

    #[test]
    fn hmac_ripemd160() {
        let code = r#"
        HMAC_RIPEMD160(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("e337eca2ca86bd2d4678462b491d72f03dbc70c8".into()))
        );
    }

    #[test]
    fn hmac_sha1() {
        let code = r#"
        HMAC_SHA1(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("3815da2d914cdddd3fe2ca620dd1f1a2ba5f17bc".into()))
        );
    }

    #[test]
    fn hmac_sha256() {
        let code = r#"
        HMAC_SHA256(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(
                "08e56e5751d78aaeb49f16142a8b5fb6636a88f7fbf6ee7a93bbfa9be18c4ea6".into()
            ))
        );
    }

    #[test]
    fn hmac_sha384() {
        let code = r#"
        HMAC_SHA384(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("fce1f12094a52a4654c4a0f7086a470e74096fa200187a79f770384e33dd9f1a224b7bd86f6ced2dd1be6d922f8418b2".into()))
        );
    }

    #[test]
    fn hmac_sha512() {
        let code = r#"
        HMAC_SHA512(key: "my_shared?key", data: "so much wow");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok("7e251167d67f7f29fc978048d338f6ebe0d8bb5213f5ccacca50359b3435df19e60fa709241b98b0ed9e1aeb994df6f900c5fa87201c3fc971b0120968c96cb3".into()))
        );
    }
}
