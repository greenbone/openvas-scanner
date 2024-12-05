// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;

    #[test]
    fn ereg_rnul_true_success() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'NASL' + raw_string(0x00) + 'Test';"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASL.+Test", icase:FALSE, rnul:TRUE);"#,
            true,
        );
    }

    /// In this test, the string is truncated at the first '\0', therefore there is no match
    #[test]
    fn ereg_rnul_false_failed() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'NASL' + raw_string(0x00) + 'Test';"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASL.+Test", icase:FALSE, rnul:FALSE);"#,
            false,
        );
    }

    #[test]
    fn ereg_icase_true_success() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'NASL' + raw_string(0x00) + 'Test';"#);
        t.ok(
            r#"ereg(string:string, pattern:"nasl.+test", icase:TRUE);"#,
            true,
        );
    }

    #[test]
    fn ereg_icase_false_failed() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'NASL' + raw_string(0x00) + 'Test';"#);
        t.ok(r#"ereg(string:string, pattern:"nasl.+test");"#, false);
    }

    // The following test for multiline are done to behave exactly as C implementation.
    #[test]
    fn ereg_multiline_true_success() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'AAAAAAAA\n NASLTest';"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASLTest", multiline: TRUE);"#,
            true,
        );
    }

    #[test]
    fn ereg_multiline_false_failed() {
        let mut t = TestBuilder::default();
        t.run(r#"string = 'AAAAAAAA\n NASLTest';"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASLTest", multiline: FALSE);"#,
            false,
        );
    }

    #[test]
    fn ereg_multiline_string_true_success() {
        let mut t = TestBuilder::default();
        t.run(r#"string = "AAAAAAAA\n NASLTest";"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASLTest", multiline: TRUE);"#,
            true,
        );
    }

    #[test]
    fn ereg_multiline_string_false_success() {
        let mut t = TestBuilder::default();
        t.run(r#"string = "AAAAAAAA\n NASLTest";"#);
        t.ok(
            r#"ereg(string:string, pattern:"NASLTest", multiline: FALSE);"#,
            true,
        );
    }

    #[test]
    fn ereg_replace() {
        let mut t = TestBuilder::default();
        t.run(r#"string = "Greenbone Network Gmbh";"#);
        t.ok(
            r#"ereg_replace(string:string, pattern:"Network Gmbh", replace: "AG");"#,
            "Greenbone AG",
        );
    }

    #[test]
    fn egrep() {
        let t = TestBuilder::from_code(
            r#"
        string = "Pair 0
        Odd 1
        Pair 2
        Odd 3";
        egrep(string:string, pattern:"Pair");
        "#,
        );
        assert_eq!(
            t.results()[1].as_ref().unwrap(),
            &NaslValue::String("Pair 0\n        Pair 2\n".to_string())
        );
    }

    #[test]
    fn egrep_data() {
        let t = TestBuilder::from_code(
            r#"
        string = 'Pair 0
        Odd 1
        Pair 2
        Odd 3';
        egrep(string:string, pattern:"Pair");
        "#,
        );
        assert_eq!(
            t.results()[1].as_ref().unwrap(),
            &NaslValue::String("Pair 0\n        Pair 2\n".to_string())
        );
    }

    #[test]
    fn eregmatch_all() {
        let mut t = TestBuilder::default();
        t.run(r#"string = "Foo Bar Bee 123 true false";"#);
        t.ok(
            r#"eregmatch(string: string, pattern: "Bar|true", find_all: TRUE);"#,
            vec!["Bar".to_string(), "true".to_string()],
        );
    }

    #[test]
    fn eregmatch_first() {
        let mut t = TestBuilder::default();
        t.run(r#"string = "Foo Bar Bee 123 true false";"#);
        t.ok(
            r#"eregmatch(string: string, pattern: "Bar|true", find_all: FALSE);"#,
            vec!["Bar".to_string()],
        );
    }
}
