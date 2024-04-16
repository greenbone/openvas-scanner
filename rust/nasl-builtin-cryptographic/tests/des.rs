// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod helper;
#[cfg(test)]
mod tests {

    use super::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn des_encrypt() {
        let code = r#"
        key = hexstr_to_data("0101010101010101");
        data = hexstr_to_data("95f8a5e5dd31d900");
        DES(data,key);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(decode_hex("8000000000000000").unwrap())))
        );
    }
}
