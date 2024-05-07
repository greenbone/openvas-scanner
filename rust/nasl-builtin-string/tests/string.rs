// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
#[cfg(test)]
mod tests {
    use nasl_interpreter::*;

    #[test]
    fn hexstr() {
        let code = r#"
        a = 'foo';
        hexstr('foo');
        hexstr('foo', "I will be ignored");
        hexstr(6);
        hexstr();
        hexstr(raw_string(10, 208, 102, 165, 210, 159, 63, 42, 42, 28, 124, 23, 221, 8, 42, 121));
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok("666f6f".into())));
        assert_eq!(parser.next(), Some(Ok("666f6f".into())));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String(
                "0ad066a5d29f3f2a2a1c7c17dd082a79".to_string()
            )))
        );
    }
    #[test]
    fn raw_string() {
        let code = r#"
        raw_string(0x7B);
        raw_string(0x7B, 1);
        raw_string(0x7B, 1, "Hallo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(vec![123].into())));
        assert_eq!(parser.next(), Some(Ok(vec![123, 1].into())));
        assert_eq!(
            parser.next(),
            Some(Ok(vec![123, 1, 72, 97, 108, 108, 111].into()))
        );
    }
    #[test]
    fn tolower() {
        let code = r###"
        tolower(0x7B);
        tolower('HALLO');
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok("hallo".into())));
    }
    #[test]
    fn toupper() {
        let code = r###"
        toupper(0x7B);
        toupper('hallo');
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok("HALLO".into())));
    }
    #[test]
    fn strlen() {
        let code = r###"
        strlen(0x7B);
        strlen('hallo');
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(0i64.into())));
        assert_eq!(parser.next(), Some(Ok(5i64.into())));
    }
    #[test]
    fn string() {
        let code = r#"
        string(0x7B);
        string(0x7B, 1);
        string(0x7B, 1, "Hallo");
        string(0x7B, 1, NULL, "Hallo");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok("123".into())));
        assert_eq!(parser.next(), Some(Ok("1231".into())));
        assert_eq!(parser.next(), Some(Ok("1231Hallo".into())));
        assert_eq!(parser.next(), Some(Ok("1231Hallo".into())));
    }

    #[test]
    fn substr() {
        let code = r#"
        substr("hello", 1);
        substr("hello", 0, 4);
        substr("hello", 6);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok("ello".into())));
        assert_eq!(parser.next(), Some(Ok("hell".into())));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }

    #[test]
    fn crap() {
        let code = r#"
        crap(5);
        crap(length: 5);
        crap(data: "ab", length: 5);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok("XXXXX".into())));
        assert_eq!(parser.next(), Some(Ok("XXXXX".into())));
        assert_eq!(parser.next(), Some(Ok("ababababab".into())));
    }

    #[test]
    fn chomp() {
        let code = r#"
        chomp("abc");
        chomp("abc\n");
        chomp("abc  ");
        chomp("abc\n\t\r ");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
    }

    #[test]
    fn stridx() {
        let code = r#"
        stridx("abc", "bcd");
        stridx("abc", "bc");
        stridx("abc", "abc");
        stridx("blahabc", "abc", 4);
        stridx("blahabc", "abc", 3);
        stridx("blahbc", "abc", 2);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok((-1_i64).into())));
        assert_eq!(parser.next(), Some(Ok(1_i64.into())));
        assert_eq!(parser.next(), Some(Ok(0_i64.into())));
        assert_eq!(parser.next(), Some(Ok(0_i64.into())));
        assert_eq!(parser.next(), Some(Ok(1_i64.into())));
        assert_eq!(parser.next(), Some(Ok((-1_i64).into())));
    }

    #[test]
    fn display() {
        let code = r#"
        display("abc");
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }

    #[test]
    fn hexstr_to_data() {
        let code = r#"
        a = hexstr_to_data("4bb3c4a4f893ad8c9bdc833c325d62b3");
        data_to_hexstr(a);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(vec![
                75, 179, 196, 164, 248, 147, 173, 140, 155, 220, 131, 60, 50, 93, 98, 179
            ])))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String(
                "4bb3c4a4f893ad8c9bdc833c325d62b3".to_string()
            )))
        );
    }
}
