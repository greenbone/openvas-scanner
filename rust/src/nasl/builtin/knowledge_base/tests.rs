// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;
    use ArgumentError::*;

    #[test]
    fn set_kb_item() {
        check_code_result(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        check_err_matches!(r#"set_kb_item(name: "test");"#, MissingNamed { .. });
        check_err_matches!(r#"set_kb_item(value: 1);"#, MissingNamed { .. });
    }

    #[test]
    fn get_kb_item() {
        let mut t = TestBuilder::default();
        t.ok(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        t.ok(r#"get_kb_item("test");"#, 1);
        check_err_matches!(t, r#"get_kb_item("test", 1);"#, TrailingPositionals { .. },);
        check_err_matches!(t, r#"get_kb_item();"#, MissingPositionals { .. });
    }

    #[test]
    fn get_kb_list() {
        let mut t = TestBuilder::default();
        t.ok(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        t.ok(r#"set_kb_item(name: "test", value: 2);"#, NaslValue::Null);
        t.ok(r#"get_kb_list("test");"#, vec![1, 2]);
    }

    #[test]
    fn replace_kb_item() {
        let mut t = TestBuilder::default();
        t.ok(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        t.ok(
            r#"replace_kb_item(name: "test", value: 2);"#,
            NaslValue::Null,
        );
        t.ok(r#"get_kb_item("test");"#, 2);
    }
}
