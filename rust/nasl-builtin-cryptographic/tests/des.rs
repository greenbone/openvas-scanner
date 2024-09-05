// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod helper;
#[cfg(test)]
mod tests {
    use super::helper::decode_hex;
    use nasl_interpreter::test_utils::TestBuilder;

    #[test]
    fn des_encrypt() {
        let mut t = TestBuilder::default();
        t.run(r#"key = hexstr_to_data("0101010101010101");"#);
        t.run(r#"data = hexstr_to_data("95f8a5e5dd31d900");"#);
        t.ok(r#"DES(data,key);"#, decode_hex("8000000000000000").unwrap());
    }
}
