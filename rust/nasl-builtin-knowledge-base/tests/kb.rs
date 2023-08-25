// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;

    #[test]
    fn set_kb_item() {
        let code = r#"
        set_kb_item(name: "test", value: 1);
        set_kb_item(name: "test");
        set_kb_item(value: 1);
        "#;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert!(matches!(parser.next(), Some(Err(_))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
    #[test]
    fn get_kb_item() {
        let code = r#"
        set_kb_item(name: "test", value: 1);
        get_kb_item("test");
        get_kb_item("test", 1);
        "#;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(1))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
}
