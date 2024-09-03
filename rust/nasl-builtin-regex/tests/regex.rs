// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {
    use nasl_builtin_std::ContextFactory;
    use nasl_builtin_utils::Register;
    use nasl_interpreter::CodeInterpreter;
    use nasl_syntax::NaslValue;

    #[test]
    fn ereg_rnul_true_success() {
        let code = r#"
        string = 'NASL' + raw_string(0x00) + 'Test';
        ereg(string:string, pattern:"NASL.+Test", icase:FALSE, rnul:TRUE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    /// In this test, the string is truncated at the first '\0', therefore there is no match
    #[test]
    fn ereg_rnul_false_failed() {
        let code = r#"
        string = 'NASL' + raw_string(0x00) + 'Test';
        ereg(string:string, pattern:"NASL.+Test", icase:FALSE, rnul:FALSE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(false))));
    }

    #[test]
    fn ereg_icase_true_success() {
        let code = r#"
        string = 'NASL' + raw_string(0x00) + 'Test';
        ereg(string:string, pattern:"nasl.+test", icase:TRUE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn ereg_icase_false_failed() {
        let code = r#"
        string = 'NASL' + raw_string(0x00) + 'Test';
        ereg(string:string, pattern:"nasl.+test");
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(false))));
    }

    // The following test for multiline are done to behave exactly as C implementation.
    #[test]
    fn ereg_multiline_true_success() {
        let code = r#"
        string = 'AAAAAAAA\n NASLTest';
        ereg(string:string, pattern:"NASLTest", multiline: TRUE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn ereg_multiline_false_failed() {
        let code = r#"
        string = 'AAAAAAAA\n NASLTest';
        ereg(string:string, pattern:"NASLTest", multiline: FALSE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(false))));
    }

    #[test]
    fn ereg_multiline_string_true_success() {
        let code = r#"
        string = "AAAAAAAA\n NASLTest";
        ereg(string:string, pattern:"NASLTest", multiline: TRUE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn ereg_multiline_string_false_success() {
        let code = r#"
        string = "AAAAAAAA\n NASLTest";
        ereg(string:string, pattern:"NASLTest", multiline: FALSE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn ereg_replace() {
        let code = r#"
        string = "Greenbone Network Gmbh";
        ereg_replace(string:string, pattern:"Network Gmbh", replace: "AG");
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("Greenbone AG".to_string())))
        );
    }

    #[test]
    fn egrep() {
        let code = r#"
        string = "Pair 0
        Odd 1
        Pair 2
        Odd 3";
        egrep(string:string, pattern:"Pair");
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String(
                "Pair 0\n        Pair 2\n".to_string()
            )))
        );
    }

    #[test]
    fn egrep_data() {
        let code = r#"
        string = 'Pair 0
        Odd 1
        Pair 2
        Odd 3';
        egrep(string:string, pattern:"Pair");
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String(
                "Pair 0\n        Pair 2\n".to_string()
            )))
        );
    }

    #[test]
    fn eregmatch_all() {
        let code = r#"
        string = "Foo Bar Bee 123 true false";
        eregmatch(string: string, pattern: "Bar|true", find_all: TRUE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::String("Bar".to_string()),
                NaslValue::String("true".to_string())
            ])))
        );
    }

    #[test]
    fn eregmatch_first() {
        let code = r#"
        string = "Foo Bar Bee 123 true false";
        eregmatch(string: string, pattern: "Bar|true", find_all: FALSE);
        "#;
        let register = Register::default();
        let mut binding = ContextFactory::default();
        binding
            .functions
            .push_executer(nasl_builtin_regex::RegularExpressions);

        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![NaslValue::String(
                "Bar".to_string()
            )])))
        );
    }
}
