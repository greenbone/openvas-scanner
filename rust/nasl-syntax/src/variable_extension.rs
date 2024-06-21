// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod test {
    use crate::{parse, AssignOrder, Statement, StatementKind, TokenCategory};

    use StatementKind::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(result("a;").kind(), &StatementKind::Variable)
    }

    #[test]
    fn arrays() {
        assert!(matches!(result("a[0];").kind(), Array(Some(_))));
        let re = result("a = [1, 2, 3];");
        match re.kind() {
            Assign(TokenCategory::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(arr.kind(), Array(None)))
            }
            _ => panic!("{re} must be an assign statement"),
        }

        let re = result("a[0] = [1, 2, 4];");
        match re.kind() {
            Assign(TokenCategory::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(arr.kind(), &Array(Some(_))))
            }
            _ => panic!("{re} must be an assign statement"),
        }
    }

    #[test]
    fn anon_function_call() {
        assert!(matches!(result("a(1, 2, 3);").kind(), &Call(..)))
    }

    #[test]
    fn named_function_call() {
        assert!(matches!(
            result("script_tag(name:\"cvss_base\", value:1 + 1 % 2);").kind(),
            &Call(..)
        ));
    }
}
