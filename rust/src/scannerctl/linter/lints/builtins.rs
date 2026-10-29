use std::collections::HashSet;

use scannerlib::nasl::nasl_std_executor;

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

pub(super) fn builtin_functions() -> HashSet<String> {
    nasl_std_executor()
        .iter()
        .chain(C_ONLY_BUILTINS.iter().copied())
        .map(str::to_owned)
        .collect()
}
