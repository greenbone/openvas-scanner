// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::{builtin::cryptographic::tests::helper::decode_hex, test_utils::TestBuilder};

#[test]
fn dh_compute_key() {
    let mut t = TestBuilder::default();
    t.run(r#"k1 = raw_string(0x03);"#);
    t.run(r#"k2 = raw_string(0x03);"#);
    t.run(r#"k3 = raw_string(0x07);"#);
    t.run(r#"n = raw_string(0x00);"#);
    t.ok(
        r#"dh_compute_key(p: k3, g: n, dh_server_pub: k1, pub_key: n, priv_key: k2);"#,
        decode_hex("06").unwrap(),
    );
}

#[test]
fn dh_generate_key() {
    let mut t = TestBuilder::default();
    t.run(r#"k1 = raw_string(0x03);"#);
    t.run(r#"k2 = raw_string(0x03);"#);
    t.run(r#"k3 = raw_string(0x07);"#);
    t.ok(
        r#"dh_generate_key(p: k3, g: k1, priv: k2);"#,
        decode_hex("06").unwrap(),
    );
}
