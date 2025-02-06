// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
#[cfg(test)]
mod tests {
    use crate::nasl::{builtin::isotime::IsotimeError, test_prelude::*};

    #[test]
    fn isotime_is_valid() {
        check_code_result("isotime_is_valid(\"\");", false);
        check_code_result("isotime_is_valid(\"a8691002T123456\");", false);
        check_code_result("isotime_is_valid(\"18691002T123456\");", true);
        check_code_result("isotime_is_valid(\"18691002T1234\");", false);
        check_code_result("isotime_is_valid(\"18691002T1234512\");", false);
        check_code_result("isotime_is_valid(\"1869-10-02 12:34:56\");", true);
        check_code_result("isotime_is_valid(\"1869-10-02 12:34\");", true);
        check_code_result("isotime_is_valid(\"1869-10-02 12\");", true);
        check_code_result("isotime_is_valid(\"1869-10-02\");", true);
        check_code_result("isotime_is_valid(\"1869-10-02T12:34:56\");", false);
    }

    #[test]
    fn isotime_scan() {
        check_err_matches!("isotime_scan(\"\");", IsotimeError { .. });
        check_err_matches!("isotime_scan(\"a8691002T123456\");", IsotimeError { .. });
        check_err_matches!("isotime_scan(\"18691002T1234\");", IsotimeError { .. });
        check_err_matches!("isotime_scan(\"18691002T1234512\");", IsotimeError { .. });
        check_err_matches!(
            "isotime_scan(\"1869-10-02T12:34:56\");",
            IsotimeError { .. }
        );

        check_code_result("isotime_scan(\"18691002T123456\");", "18691002T123456");
        check_code_result("isotime_scan(\"1869-10-02 12:34:56\");", "18691002T123456");
        check_code_result("isotime_scan(\"1869-10-02 12:34\");", "18691002T123400");
        check_code_result("isotime_scan(\"1869-10-02 12\");", "18691002T120000");
    }

    #[test]
    fn isotime_print() {
        check_err_matches!("isotime_print(\"\");", IsotimeError { .. });
        check_err_matches!("isotime_print(\"a8691002T123456\");", IsotimeError { .. });
        check_err_matches!("isotime_print(\"18691002T1234\");", IsotimeError { .. });
        check_err_matches!(
            "isotime_print(\"1869-10-02T12:34:56\");",
            IsotimeError { .. }
        );

        check_code_result("isotime_print(\"18691002T123456\");", "1869-10-02 12:34:56");
        check_code_result("isotime_print(\"18691002T123451\");", "1869-10-02 12:34:51");
        check_code_result(
            "isotime_print(\"1869-10-02 12:34:56\");",
            "1869-10-02 12:34:56",
        );
        check_code_result(
            "isotime_print(\"1869-10-02 12:34\");",
            "1869-10-02 12:34:00",
        );
        check_code_result("isotime_print(\"1869-10-02 12\");", "1869-10-02 12:00:00");
    }

    #[test]
    fn isotime_add() {
        check_err_matches!("isotime_add(\"\", years: 0);", IsotimeError { .. });
        check_err_matches!(
            "isotime_add(\"50001002T120000\", years: 5000);",
            IsotimeError { .. }
        );
        check_err_matches!(
            "isotime_add(\"50001002T120000\", years: -5001);",
            IsotimeError { .. }
        );

        check_code_result(
            "isotime_add(\"20240228T000000\", days: 1);",
            "20240229T000000",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", years: 1);",
            "20250228T000000",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", seconds: 1);",
            "20240228T000001",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", days: -1);",
            "20240227T000000",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", years: -1);",
            "20230228T000000",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", seconds: -1);",
            "20240227T235959",
        );
        check_code_result(
            "isotime_add(\"20240228T000000\", years: 1, days: -1, seconds: -1);",
            "20250226T235959",
        );
    }
}
