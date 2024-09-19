// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use crate::{check_code_result_matches, nasl::prelude::*};

    #[test]
    fn get_host_name() {
        check_code_result_matches!("get_host_name();", NaslValue::String(_));
        check_code_result_matches!("get_host_names();", NaslValue::Array(_));
    }
}
