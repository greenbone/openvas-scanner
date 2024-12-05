// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::test_prelude::*;

use super::helper::decode_hex;

#[test]
fn aes128_cbc_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("00000000000000000000000000000000");"#);
    t.run(r#"data = hexstr_to_data("80000000000000000000000000000000");"#);
    t.run(r#"iv = hexstr_to_data("00000000000000000000000000000000");"#);
    t.ok(
        r#"crypt = aes128_cbc_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("3ad78e726c1ec02b7ebfe92b23d9ec34").unwrap(),
    );
    t.ok(
        r#"aes128_cbc_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("80000000000000000000000000000000").unwrap(),
    );
}

#[test]
fn aes192_cbc_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("000000000000000000000000000000000000000000000000");"#);
    t.run(r#"data = hexstr_to_data("1b077a6af4b7f98229de786d7516b639");"#);
    t.run(r#"iv = hexstr_to_data("00000000000000000000000000000000");"#);
    t.ok(
        r#"crypt = aes192_cbc_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("275cfc0413d8ccb70513c3859b1d0f72").unwrap(),
    );
    t.ok(
        r#"aes192_cbc_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("1b077a6af4b7f98229de786d7516b639").unwrap(),
    );
}

#[test]
fn aes256_cbc_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("0000000000000000000000000000000000000000000000000000000000000000");"#);
    t.run(r#"data = hexstr_to_data("014730f80ac625fe84f026c60bfd547d");"#);
    t.run(r#"iv = hexstr_to_data("00000000000000000000000000000000");"#);
    t.ok(
        r#"crypt = aes256_cbc_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("5c9d844ed46f9885085e5d6a4f94c7d7").unwrap(),
    );
    t.ok(
        r#"aes256_cbc_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("014730f80ac625fe84f026c60bfd547d").unwrap(),
    );
}

#[test]
fn padding() {
    let mut t = TestBuilder::default();
    t.run_all(
        r#"
            key = hexstr_to_data("00000000000000000000000000000000");
            data1 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f2");
            data2 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f20000");
            iv = hexstr_to_data("00000000000000000000000000000000");
            aes128_cbc_encrypt(key: key, data: data1, iv: iv);
            aes128_cbc_encrypt(key: key, data: data2, iv: iv);
        "#,
    );
    let results = t.results();
    assert_eq!(
        results[results.len() - 2].as_ref().unwrap(),
        results[results.len() - 1].as_ref().unwrap()
    );
}
