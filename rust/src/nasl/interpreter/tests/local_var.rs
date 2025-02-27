// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Tests local_var behavior

use crate::nasl::test_prelude::*;

#[test]
fn in_if() {
    let t = TestBuilder::from_code(
        r###"
a = 1;
if (a) {
    local_var a;
    a = 23;
}
a;
        "###,
    );
    assert!(matches!(
        t.results().last().unwrap(),
        &Ok(NaslValue::Number(1))
    ));
}

#[test]
fn in_function() {
    let t = TestBuilder::from_code(
        r###"
function foo(a) {
    return a;
}
a = 1;
foo(a: 2);
b = a;
        "###,
    );
    assert!(matches!(
        t.results().last().unwrap(),
        &Ok(NaslValue::Number(1))
    ));
}
