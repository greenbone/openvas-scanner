// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use nasl_interpreter::*;
    use FunctionErrorKind::*;

    #[test]
    fn set_kb_item() {
        nasl_test! {
            r#"set_kb_item(name: "test", value: 1);"# == NaslValue::Null,
            r#"set_kb_item(name: "test");"# throws MissingArguments { .. },
            r#"set_kb_item(value: 1);"# throws MissingArguments { .. },
        }
    }

    #[test]
    fn get_kb_item() {
        nasl_test! {
            r#"set_kb_item(name: "test", value: 1);"# == NaslValue::Null,
            r#"get_kb_item("test");"# == 1,
            r#"get_kb_item("test", 1);"# throws FunctionErrorKind::TrailingPositionalArguments { .. },
            r#"get_kb_item();"# throws FunctionErrorKind::MissingPositionalArguments { .. },
        }
    }
}
