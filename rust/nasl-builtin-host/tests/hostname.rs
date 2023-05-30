// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;
    #[test]
    fn get_host_name() {
        let code = r###"
        get_host_name();
        get_host_names();
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::String(_)))));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Array(_)))));
    }
}
