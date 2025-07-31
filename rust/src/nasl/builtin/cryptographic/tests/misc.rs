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
