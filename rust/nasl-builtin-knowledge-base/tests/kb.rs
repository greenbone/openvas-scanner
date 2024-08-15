// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;
    use test_utils::{check_ok, TestBuilder};
    use FunctionErrorKind::*;

    #[test]
    fn set_kb_item() {
        check_ok(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        check_err_matches!(r#"set_kb_item(name: "test");"#, MissingArguments { .. });
        check_err_matches!(r#"set_kb_item(value: 1);"#, MissingArguments { .. });
    }

    #[test]
    fn get_kb_item() {
        let mut t = TestBuilder::default();
        t.ok(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        t.ok(r#"get_kb_item("test");"#, 1);
        check_err_matches!(
            t,
            r#"get_kb_item("test", 1);"#,
            FunctionErrorKind::TrailingPositionalArguments { .. }
        );
        check_err_matches!(
            t,
            r#"get_kb_item();"#,
            FunctionErrorKind::MissingPositionalArguments { .. }
        );
    }
}
