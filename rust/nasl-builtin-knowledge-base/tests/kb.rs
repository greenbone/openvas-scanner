// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

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
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
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
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(1))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
}
