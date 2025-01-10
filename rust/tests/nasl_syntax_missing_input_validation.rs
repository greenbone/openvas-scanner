// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[test]
fn validate_recursion_depth_to_prevent_stackoverflow() {
    // Reported by @sepehrdaddev, VSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:L/SA:H
    // Crash due to depth limit on recursion.
    let code = include_str!("data/crash-recursion-depth.nasl");
    assert_eq!(code.len(), 708);
    let result = scannerlib::nasl::syntax::parse(code).collect::<Vec<_>>();

    assert_eq!(
        result.iter().filter_map(|x| x.as_ref().ok()).count(),
        0,
        "crash-recursion-depth should not have any valid statements."
    );

    let code = include_str!("data/crash-prefix-recursion.nasl");
    assert_eq!(code.len(), 636);
    let result = scannerlib::nasl::syntax::parse(code).collect::<Vec<_>>();
    assert_eq!(
        result.iter().filter_map(|x| x.as_ref().ok()).count(),
        0,
        "crash-prefix-recursion should not have any valid statements."
    );
}
