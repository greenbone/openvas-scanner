// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use crate::{
        models::{self, Protocol, ResultType},
        nasl::test_prelude::*,
    };

    fn verify(function: &str, result_type: ResultType) {
        let mut t = TestBuilder::default();
        t.run_all(format!(
            r###"
        {function}(data: "test0", port: 12, proto: "udp", uri: "moep");
        {function}(data: "test1", port: 12, proto: "tcp", uri: "moep");
        {function}(data: "test2", port: 12, proto: "nonsense", uri: "moep");
        {function}(data: "test3");
        "###
        ));
        t.check_no_errors();
        let results = t.results();
        let context = t.context();
        let get_result = |index| {
            context
                .retriever()
                .result(context.key(), index)
                .unwrap()
                .unwrap()
        };
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

        let udp = get_result(0);
        let expected = create_expected(0, Some(12), Protocol::UDP);
        assert_eq!(udp, expected);
        let tcp = get_result(1);
        let expected = create_expected(1, Some(12), Protocol::TCP);
        assert_eq!(tcp, expected);
        let defaults_to_tcp = get_result(2);
        let expected = create_expected(2, Some(12), Protocol::TCP);
        assert_eq!(defaults_to_tcp, expected);
        let default = get_result(3);
        let expected = create_expected(3, None, Protocol::TCP);
        assert_eq!(default, expected);
    }

    #[test]
    fn log_message() {
        verify("log_message", ResultType::Log)
    }

    #[test]
    fn security_message() {
        verify("security_message", ResultType::Alarm)
    }

    #[test]
    fn error_message() {
        verify("error_message", ResultType::Error)
    }
}
