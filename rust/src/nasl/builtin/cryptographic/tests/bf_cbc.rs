// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::test_prelude::*;

use super::helper::decode_hex;

#[test]
fn bf_cbc_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key =  raw_string(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xF);"#);
    t.run(r#"iv = raw_string(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);"#);
    t.run(r#"data = raw_string(0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);"#);
    t.run(r#"crypt = bf_cbc_encrypt(key: key, iv: iv, data: data);"#);
    t.ok(
        r#"crypt = bf_cbc_encrypt(key: key, iv: iv, data: data);"#,
        decode_hex("56f4c9607998aa4a").unwrap(),
    );
    t.ok(
        r#"bf_cbc_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("8000000000000000").unwrap(),
    );
}
