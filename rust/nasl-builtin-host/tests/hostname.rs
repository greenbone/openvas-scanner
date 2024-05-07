// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;
    #[test]
    fn get_host_name() {
        let code = r###"
        get_host_name();
        get_host_names();
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert!(matches!(parser.next(), Some(Ok(NaslValue::String(_)))));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Array(_)))));
    }
}
