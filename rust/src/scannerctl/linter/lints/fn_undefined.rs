use std::collections::HashSet;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::nasl_std_executor;

use crate::linter::{LintMsgs, calls::RootCalls};

// C builtins from nasl/nasl_init.c that are not registered by the Rust executor.
const C_ONLY_BUILTINS: &[&str] = &[
    "dsa_do_sign",
    "dsa_do_verify",
    "file_close",
    "file_open",
    "file_read",
    "file_seek",
    "file_write",
    "get_host_kb_index",
    "psrp_cli",
    "script_get_preference_file_location",
    "smb_close",
    "smb_connect",
    "smb_file_SDDL",
    "smb_file_group_sid",
    "smb_file_owner_sid",
    "smb_file_trustee_rights",
    "socket_check_ssl_safe_renegotiation",
    "socket_ssl_do_handshake",
    "tls1_prf",
    "update_table_driven_lsc_data",
    "win_cmd_exec",
    "wmi_close",
    "wmi_connect",
    "wmi_connect_reg",
    "wmi_connect_rsop",
    "wmi_query",
    "wmi_query_rsop",
    "wmi_reg_create_key",
    "wmi_reg_delete_key",
    "wmi_reg_enum_key",
    "wmi_reg_enum_value",
    "wmi_reg_get_bin_val",
    "wmi_reg_get_dword_val",
    "wmi_reg_get_ex_string_val",
    "wmi_reg_get_mul_string_val",
    "wmi_reg_get_qword_val",
    "wmi_reg_get_sz",
    "wmi_reg_set_dword_val",
    "wmi_reg_set_ex_string_val",
    "wmi_reg_set_qword_val",
    "wmi_reg_set_string_val",
];

pub fn fn_undefined(root: &RootCalls) -> Vec<LintMsgs> {
    let builtins: HashSet<String> = nasl_std_executor()
        .iter()
        .chain(C_ONLY_BUILTINS.iter().copied())
        .map(str::to_owned)
        .collect();
    root.files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let msgs = root
                .calls_in(index)
                .filter(|call| {
                    !root.definitions.contains_key(call.name.as_str())
                        && !builtins.contains(&call.name)
                })
                .map(|call| {
                    Diagnostic::error()
                        .with_message(format!("Undefined function '{}'", call.name))
                        .with_labels(vec![
                            Label::primary((), call.span).with_message("undefined function"),
                        ])
                        .into()
                })
                .collect();
            LintMsgs {
                file: file.file.clone(),
                msgs,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{linter_test, linter_test_multi};

    linter_test!(undefined_fn, "foo();");
    linter_test!(defined_fn, "function foo() {} foo();");
    linter_test!(builtin_fn, "display(\"hello\");");
    linter_test!(
        c_only_builtins,
        "win_cmd_exec(); wmi_connect(); smb_file_SDDL(); socket_ssl_do_handshake(); update_table_driven_lsc_data();"
    );

    linter_test!(
        unused_functions,
        "function unused() { missing(); } function recursive() { recursive(); missing(); }"
    );

    linter_test!(
        recursive_calls,
        "function a() { b(); } function b() { a(); missing(); } a();"
    );

    linter_test!(
        nested_function_calls,
        "function outer() { function inner() { nested_missing(); } outer_missing(); } outer(); top_missing();"
    );

    linter_test!(
        duplicate_definitions_keep_both_bodies,
        "function foo() { missing_a(); } function foo() { missing_b(); } foo();"
    );

    linter_test_multi!(
        reachable_calls_are_root_specific,
        files: {
            "unused.nasl" => "include(\"shared.inc\");",
            "used.nasl" => "include(\"shared.inc\"); start();",
            "shared.inc" => "function start() { helper(); } function helper() { display(missing()); missing(); } function unused() { ignored(); }",
        },
    );

    linter_test_multi!(
        included_top_level_calls_seed_reachability,
        files: {
            "root.nasl" => "include(\"shared.inc\");",
            "shared.inc" => "if (0) { start(); } function start() { missing(); }",
        },
    );

    linter_test_multi!(
        included_fn,
        files: {
            "first.nasl" => "include(\"shared.inc\"); shared();",
            "second.nasl" => "include(\"shared.inc\"); shared();",
            "shared.inc" => "function shared() {}",
        },
    );

    linter_test_multi!(
        unrelated_fn,
        files: {
            "first.nasl" => "include(\"shared.inc\"); shared();",
            "shared.inc" => "function shared() {}",
            "second.nasl" => "shared();",
        },
    );

    linter_test_multi!(
        transitive_fn,
        files: {
            "first.nasl" => "include(\"lib/outer.inc\"); shared();",
            "second.nasl" => "include(\"lib/outer.inc\"); shared();",
            "lib/outer.inc" => "if (0) { include(\"inner.inc\"); }",
            "lib/inner.inc" => "function shared() {}",
        },
    );

    linter_test_multi!(
        shared_and_cyclic_includes,
        files: {
            "root.nasl" => "include(\"left.inc\"); include(\"right.inc\"); shared();",
            "left.inc" => "include(\"shared.inc\");",
            "right.inc" => "include(\"shared.inc\");",
            "shared.inc" => "include(\"left.inc\"); function shared() {}",
        },
    );

    linter_test_multi!(
        undefined_include_call_reported_for_each_root,
        files: {
            "first.nasl" => "include(\"outer.inc\");",
            "second.nasl" => "include(\"outer.inc\");",
            "outer.inc" => "include(\"inner.inc\");",
            "inner.inc" => "missing();",
        },
    );
}
