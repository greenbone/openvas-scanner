// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::helper::decode_hex;
use crate::nasl::test_prelude::*;

#[test]
fn aes_mac_cbc() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("e3ceb929b52a6eec02b99b13bf30721b");"#);
    t.run(r#"data = hexstr_to_data("d2e8a3e86ae0b9edc7cc3116d929a16f13ee3643");"#);
    t.ok(
        r#"crypt = aes_mac_cbc(key: key, data: data);"#,
        decode_hex("10f3d29e89e4039b85e16438b2b2a470").unwrap(),
    );
}
