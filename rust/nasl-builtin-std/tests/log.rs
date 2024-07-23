// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {

    use nasl_builtin_std::ContextFactory;
    use nasl_builtin_utils::Register;
    use nasl_interpreter::CodeInterpreter;

    fn verify(function: &str, result_type: models::ResultType) {
        let code = format!(
            r###"
        {function}(data: "test0", port: 12, proto: "udp", uri: "moep");
        {function}(data: "test1", port: 12, proto: "tcp", uri: "moep");
        {function}(data: "test2", port: 12, proto: "nonsense", uri: "moep");
        {function}(data: "test3");
        "###
        );
        let register = Register::default();
        let binding = ContextFactory::default();
        let context = binding.build(Default::default(), Default::default());

        let mut parser = CodeInterpreter::new(&code, register, &context);
        let no_error = parser.find_map(|x| x.err());
        assert_eq!(
            no_error, None,
            "there should be no error when creating log_messages"
        );
        let results = context
            .retriever()
            .results(context.key())
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(
            results.len(),
            4,
            "expected the same results as log_message calls"
        );

        let create_expected = |id, port, protocol| models::Result {
            id,
            r_type: result_type.clone(),
            ip_address: Some(context.target().to_string()),
            hostname: None,
            oid: Some(context.key().value()),
            port,
            protocol: Some(protocol),
            message: Some(format!("test{id}")),
            detail: None,
        };
        let udp = context
            .retriever()
            .result(context.key(), 0)
            .expect("expected udp result of first call")
            .unwrap();
        let expected = create_expected(0, Some(12), models::Protocol::UDP);
        assert_eq!(udp, expected);

        let tcp = context
            .retriever()
            .result(context.key(), 1)
            .expect("expected udp result of first call")
            .unwrap();
        let expected = create_expected(1, Some(12), models::Protocol::TCP);
        assert_eq!(tcp, expected);
        let defaults_to_tcp = context
            .retriever()
            .result(context.key(), 2)
            .expect("expected udp result of first call")
            .unwrap();
        let expected = create_expected(2, Some(12), models::Protocol::TCP);
        assert_eq!(defaults_to_tcp, expected);
        let default = context
            .retriever()
            .result(context.key(), 3)
            .expect("expected udp result of first call")
            .unwrap();
        let expected = create_expected(3, None, models::Protocol::TCP);
        assert_eq!(default, expected);
    }

    #[test]
    fn log_message() {
        verify("log_message", models::ResultType::Log)
    }

    #[test]
    fn security_message() {
        verify("security_message", models::ResultType::Alarm)
    }

    #[test]
    fn error_message() {
        verify("error_message", models::ResultType::Error)
    }
}
