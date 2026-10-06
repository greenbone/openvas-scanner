// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// Include behavior in NASL is weird - including a file
// a.inc from subfolder/b.inc first looks for subfolder/a.inc
// then for a.inc in the feed root.
#[cfg(test)]
mod tests {
    use crate::{interpreter_test_multi, nasl::test_prelude::*};

    interpreter_test_multi!(
        include_from_relative_dir,
        {
            "plugins/main.nasl" => r#"
                include("values.inc");
                value;
                get_value();
            "#,
            "plugins/values.inc" => r#"
                value = 41;
                function get_value() { return 42; }
            "#,
            "values.inc" => r#"
                value = 0;
                function get_value() { return 0; }
            "#,
        },
        NaslValue::Null,
        41,
        42,
    );

    interpreter_test_multi!(
        include_falls_back_to_the_feed_root,
        {
            "plugins/main.nasl" => r#"
                include("values.inc");
                value;
            "#,
            "values.inc" => "value = 42;",
        },
        NaslValue::Null,
        42,
    );
}
