// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;

    #[test]
    fn hash_md5() {
        let code = r#"
        a = MD5("hola mundo");
        a = MD5('hola mundo');
        a = MD5();
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [10, 208, 102, 165, 210, 159, 63, 42, 42, 28, 124, 23, 221, 8, 42, 121].to_vec()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [10, 208, 102, 165, 210, 159, 63, 42, 42, 28, 124, 23, 221, 8, 42, 121].to_vec()
            )))
        );
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }

    #[test]
    fn hash_md4() {
        let code = r#"
        MD4("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [150, 189, 216, 54, 225, 218, 147, 16, 141, 155, 247, 14, 153, 134, 239, 236]
                    .to_vec()
            )))
        );
    }

    #[test]
    fn hash_md2() {
        let code = r#"
        MD2("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [45, 30, 74, 180, 247, 157, 181, 203, 252, 239, 123, 54, 5, 214, 55, 45].to_vec()
            )))
        );
    }

    #[test]
    fn hash_sha1() {
        let code = r#"
        SHA1("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [
                    69, 149, 103, 211, 189, 228, 65, 139, 127, 227, 2, 255, 152, 9, 196, 176, 190,
                    250, 247, 221
                ]
                .to_vec()
            )))
        );
    }
    #[test]

    fn hash_sha256() {
        let code = r#"
        SHA256("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [
                    11, 137, 65, 102, 211, 51, 100, 53, 200, 0, 190, 163, 111, 242, 27, 41, 234,
                    168, 1, 165, 47, 88, 76, 0, 108, 73, 40, 154, 13, 207, 110, 47
                ]
                .to_vec()
            )))
        );
    }

    #[test]
    fn hash_sha512() {
        let code = r#"
        SHA512("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [
                    227, 97, 236, 195, 31, 42, 172, 32, 102, 163, 16, 61, 59, 20, 220, 99, 181,
                    152, 75, 2, 143, 159, 45, 9, 222, 230, 116, 96, 206, 39, 2, 188, 129, 103, 58,
                    207, 88, 16, 155, 85, 51, 36, 133, 44, 98, 162, 39, 217, 167, 93, 76, 47, 104,
                    101, 128, 39, 15, 225, 67, 4, 143, 71, 195, 60
                ]
                .to_vec()
            )))
        );
    }

    #[test]
    fn hash_ripemd160() {
        let code = r#"
        RIPEMD160("hola mundo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [
                    224, 38, 197, 40, 255, 116, 162, 102, 178, 240, 158, 34, 193, 190, 227, 99, 44,
                    6, 233, 21
                ]
                .to_vec()
            )))
        );
    }
}
