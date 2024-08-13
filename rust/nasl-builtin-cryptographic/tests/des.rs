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
        nasl_test! {
            r#"key = hexstr_to_data("0101010101010101");"#,
            r#"data = hexstr_to_data("95f8a5e5dd31d900");"#,
            r#"DES(data,key);"#
                == decode_hex("8000000000000000").unwrap(),
        }
    }
}
