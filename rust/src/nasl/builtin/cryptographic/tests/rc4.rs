// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::test_prelude::*;

use super::helper::decode_hex;

#[test]
fn rc4_encrypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key =  raw_string(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xF);"#);
    t.run(r#"data = raw_string(0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);"#);
    t.run(r#"crypt = rc4_encrypt(key: key, data: data);"#);
    t.ok(
        r#"crypt = rc4_encrypt(key: key, data: data);"#,
        decode_hex("699c40f947e219cc").unwrap(),
    );
}

#[test]
fn rc4_open_encrypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key =  raw_string(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xF);"#);
    t.run(r#"data = raw_string(0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);"#);
    t.run(r#"hd = open_rc4_cipher(key: key);"#);
    t.ok(
        r#"crypt = rc4_encrypt(hd: hd, data: data);"#,
        decode_hex("699c40f947e219cc").unwrap(),
    );
    t.ok(r#"hd;"#, 5000);
    t.ok(r#"close_stream_cipher(hd: hd);"#, 0);
}
