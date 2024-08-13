// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use nasl_interpreter::{test_utils::run, *};
    #[test]
    fn get_host_name() {
        let results = run(r#"
                get_host_name();
                get_host_names();
            "#);
        matches!(results[0], Ok(NaslValue::String(_)));
        matches!(results[1], Ok(NaslValue::Array(_)));
    }
}
