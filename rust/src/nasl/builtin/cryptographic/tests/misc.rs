// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use super::helper::decode_hex;
use crate::nasl::test_prelude::*;

#[test]
fn des_encrypt() {
    let mut t = TestBuilder::default();
    t.run(r#"data = hexstr_to_data("010101");"#);
    t.ok(
        r#"insert_hexzeros(in: data);"#,
        decode_hex("010001000100").unwrap(),
    );
}

#[test]
fn bn_cmp_less() {
    let mut t = TestBuilder::default();
    t.run(r#"key1 = "A";"#);
    t.run(r#"key2 = "B";"#);

    t.ok(r#"bn_cmp(key1: key1, key2: key2);"#, -1);
}

#[test]
fn bn_cmp_equal() {
    let mut t = TestBuilder::default();
    t.run(r#"key1 = "A";"#);
    t.run(r#"key2 = "A";"#);

    t.ok(r#"bn_cmp(key1: key1, key2: key2);"#, 0);
}

#[test]
fn bn_cmp_greater() {
    let mut t = TestBuilder::default();
    t.run(r#"key1 = "B";"#);
    t.run(r#"key2 = "A";"#);

    t.ok(r#"bn_cmp(key1: key1, key2: key2);"#, 1);
}

#[test]
fn bn_random() {
    let mut t = TestBuilder::default();
    t.check(
        r#"num = bn_random(need: 20);"#,
        |r| matches!(r, Ok(NaslValue::Data(d)) if d.len() == 3),
        Some("bn_random(need:20) should return 3 bytes"),
    );
}
