// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::helper::decode_hex;
use crate::nasl::test_prelude::*;

#[test]
fn aes_mac_gcm() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");"#);
    t.run(r#"data = hexstr_to_data("d5de42b461646c255c87bd2962d3b9a2");"#);
    t.run(r#"iv = hexstr_to_data("ee283a3fc75575e33efd48");"#);
    t.ok(
        r#"aes_mac_gcm(key: key, data: data, iv: iv);"#,
        decode_hex("7d20ca663e32dbf64a69bf84dbf990ba").unwrap(),
    );
}
