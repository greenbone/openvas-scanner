// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::nasl::Code;

#[test]
fn validate_recursion_depth_to_prevent_stackoverflow() {
    // Reported by @sepehrdaddev, VSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:L/SA:H
    // Crash due to depth limit on recursion.
    let code = include_str!("data/crash-recursion-depth.nasl");
    assert_eq!(code.len(), 708);
    assert!(Code::from_string(code).parse().result().is_err());

    let code = include_str!("data/crash-prefix-recursion.nasl");
    assert_eq!(code.len(), 636);
    assert!(Code::from_string(code).parse().result().is_err());
}
