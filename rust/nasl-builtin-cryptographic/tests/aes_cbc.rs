// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;
#[cfg(test)]
mod tests {

    use super::helper::decode_hex;
    use nasl_interpreter::{test_utils::run, *};

    #[test]
    fn aes128_cbc_crypt() {
        nasl_test! {
            r#"key = hexstr_to_data("00000000000000000000000000000000");"#,
            r#"data = hexstr_to_data("80000000000000000000000000000000");"#,
            r#"iv = hexstr_to_data("00000000000000000000000000000000");"#,
            r#"crypt = aes128_cbc_encrypt(key: key, data: data, iv: iv);"#
                == decode_hex("3ad78e726c1ec02b7ebfe92b23d9ec34").unwrap(),
            r#"aes128_cbc_decrypt(key: key, data: crypt, iv: iv);"#
                == decode_hex("80000000000000000000000000000000").unwrap(),
        }
    }

    #[test]
    fn aes192_cbc_crypt() {
        nasl_test! {
            r#"key = hexstr_to_data("000000000000000000000000000000000000000000000000");"#,
            r#"data = hexstr_to_data("1b077a6af4b7f98229de786d7516b639");"#,
            r#"iv = hexstr_to_data("00000000000000000000000000000000");"#,
            r#"crypt = aes192_cbc_encrypt(key: key, data: data, iv: iv);"#
                == decode_hex("275cfc0413d8ccb70513c3859b1d0f72").unwrap(),
            r#"aes192_cbc_decrypt(key: key, data: crypt, iv: iv);"#
                == decode_hex("1b077a6af4b7f98229de786d7516b639").unwrap(),
        }
    }

    #[test]
    fn aes256_cbc_crypt() {
        nasl_test! {
            r#"key = hexstr_to_data("0000000000000000000000000000000000000000000000000000000000000000");"#,
            r#"data = hexstr_to_data("014730f80ac625fe84f026c60bfd547d");"#,
            r#"iv = hexstr_to_data("00000000000000000000000000000000");"#,
            r#"crypt = aes256_cbc_encrypt(key: key, data: data, iv: iv);"#
                == decode_hex("5c9d844ed46f9885085e5d6a4f94c7d7").unwrap(),
            r#"aes256_cbc_decrypt(key: key, data: crypt, iv: iv);"#
                == decode_hex("014730f80ac625fe84f026c60bfd547d").unwrap(),
        }
    }

    #[test]
    fn padding() {
        let results = run(r#"
            key = hexstr_to_data("00000000000000000000000000000000");
            data1 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f2");
            data2 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f20000");
            iv = hexstr_to_data("00000000000000000000000000000000");
            aes128_cbc_encrypt(key: key, data: data1, iv: iv);
            aes128_cbc_encrypt(key: key, data: data2, iv: iv);
        "#);
        assert_eq!(results[results.len() - 2], results[results.len() - 1]);
    }
}
