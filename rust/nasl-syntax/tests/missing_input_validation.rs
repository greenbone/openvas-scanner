// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod test {

    use nasl_syntax::{logger::NaslLogger, parse};

    #[test]
    fn validate_recursion_depth_to_prevent_stackoverflow() {
        // Reported by Anon, VSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:L/SA:H
        // Crash due to depth limit on recursion.
        let code = include_str!("crash-recursion-depth.nasl");
        assert_eq!(code.len(), 587);
        let result = nasl_syntax::parse(code).collect::<Vec<_>>();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_err())
    }
}
