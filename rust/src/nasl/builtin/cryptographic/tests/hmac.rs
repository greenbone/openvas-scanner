// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::test_utils::check_code_result;

#[test]
fn hmac_md2() {
    check_code_result(
        r#"HMAC_MD2(key: "my_shared?key", data: "so much wow");"#,
        "9558b32badac84072d54422d05bd601a",
    );
}

#[test]
fn hmac_md5() {
    check_code_result(
        r#"HMAC_MD5(key: "my_shared?key", data: "so much wow");"#,
        "815292959633f0e63666d90d6f47cb79",
    );
}

#[test]
fn hmac_ripemd160() {
    check_code_result(
        r#"HMAC_RIPEMD160(key: "my_shared?key", data: "so much wow");"#,
        "e337eca2ca86bd2d4678462b491d72f03dbc70c8",
    );
}

#[test]
fn hmac_sha1() {
    check_code_result(
        r#"HMAC_SHA1(key: "my_shared?key", data: "so much wow");"#,
        "3815da2d914cdddd3fe2ca620dd1f1a2ba5f17bc",
    );
}

#[test]
fn hmac_sha256() {
    check_code_result(
        r#"HMAC_SHA256(key: "my_shared?key", data: "so much wow");"#,
        "08e56e5751d78aaeb49f16142a8b5fb6636a88f7fbf6ee7a93bbfa9be18c4ea6",
    );
}

#[test]
fn hmac_sha384() {
    check_code_result(r#"HMAC_SHA384(key: "my_shared?key", data: "so much wow");"#, "fce1f12094a52a4654c4a0f7086a470e74096fa200187a79f770384e33dd9f1a224b7bd86f6ced2dd1be6d922f8418b2");
}

#[test]
fn hmac_sha512() {
    check_code_result(r#"HMAC_SHA512(key: "my_shared?key", data: "so much wow");"#, "7e251167d67f7f29fc978048d338f6ebe0d8bb5213f5ccacca50359b3435df19e60fa709241b98b0ed9e1aeb994df6f900c5fa87201c3fc971b0120968c96cb3");
}
