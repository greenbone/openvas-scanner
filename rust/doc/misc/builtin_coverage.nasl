# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

functions = make_array("built-in-plugins",make_list("plugin_run_find_service","plugin_run_openvas_tcp_scanner","plugin_run_synscan"),"cert-functions",make_list("cert_close","cert_open","cert_query"),"cryptographic",make_list("aes128_cbc_encrypt","aes128_ccm_decrypt_auth","aes128_ccm_decrypt","aes128_ccm_encrypt_auth","aes128_ccm_encrypt","aes128_ctr_encrypt","aes128_gcm_decrypt_auth","aes128_gcm_decrypt","aes128_gcm_encrypt_auth","aes128_gcm_encrypt","aes256_cbc_encrypt","aes256_ccm_decrypt_auth","aes256_ccm_decrypt","aes256_ccm_encrypt_auth","aes256_ccm_encrypt","aes256_ctr_encrypt","aes256_gcm_decrypt_auth","aes256_gcm_decrypt","aes256_gcm_encrypt_auth","aes256_gcm_encrypt","aes_mac_cbc","aes_mac_gcm","bf_cbc_decrypt","bf_cbc_encrypt","bn_cmp","bn_random","close_stream_cipher","des_ede_cbc_encrypt","DES","dh_compute_key","dh_generate_key","dsa_do_sign","dsa_do_verify","get_signature","get_smb2_signature","HMAC_MD2","HMAC_MD5","HMAC_RIPEMD160","HMAC_SHA1","HMAC_SHA256","HMAC_SHA384","HMAC_SHA512","insert_hexzeros","key_exchange","lm_owf_gen","MD2","MD4","MD5","ntlm2_response","ntlm_response","NTLMv1_HASH","NTLMv2_HASH","ntlmv2_response","nt_owf_gen","ntv2_owf_gen","open_rc4_cipher","pem_to_dsa","pem_to_rsa","prf_sha256","prf_sha384","rc4_encrypt","RIPEMD160","rsa_private_decrypt","rsa_public_decrypt","rsa_public_encrypt","rsa_sign","SHA1","SHA256","SHA512","smb3kdf","smb_cmac_aes_signature","smb_gmac_aes_signature","tls1_prf"),"description-functions",make_list("script_add_preference","script_category","script_copyright","script_cve_id","script_dependencies","script_exclude_keys","script_family","script_mandatory_keys","script_name","script_oid","script_require_keys","script_require_ports","script_require_udp_ports","script_tag","script_timeout","script_version","script_xref"),"glue-functions",make_list("get_preference","get_script_oid","script_get_preference_file_content","script_get_preference_file_location","script_get_preference","vendor_version"),"host-functions",make_list("add_host_name","get_host_names","get_host_name_source","resolve_host_name","resolve_hostname_to_multiple_ips","same_host","TARGET_IS_IPV6"),"http-functions",make_list("cgibin","http_close_socket","http_delete","http_get","http_head","http_open_socket","http_post","http_put"),"isotime-functions",make_list("isotime_add","isotime_is_valid","isotime_now","isotime_print","isotime_scan"),"knowledge-base",make_list("get_host_kb_index","get_kb_item","get_kb_list","replace_kb_item","set_kb_item"),"misc",make_list("dec2str","defined_func","dump_ctxt","exit","get_byte_order","gettimeofday","gunzip","gzip","isnull","keys","localtime","make_array","make_list","max_index","mktime","open_sock_kdc","rand","safe_checks","sleep","sort","typeof","unixtime","usleep"),"network-functions",make_list("close","end_denial","ftp_get_pasv_port","ftp_log_in","get_host_ip","get_host_name","get_host_open_port","get_mtu","get_port_state","get_port_transport","get_source_port","get_tcp_port_state","get_udp_port_state","islocalhost","islocalnet","join_multicast_group","leave_multicast_group","open_priv_sock_tcp","open_priv_sock_udp","open_sock_tcp","open_sock_udp","recv_line","recv","scanner_add_port","scanner_get_port","send","start_denial","tcp_ping","telnet_init","this_host","this_host_name"),"raw-ip-functions",make_list("dump_frame","dump_icmp_packet","dump_icmp_v6_packet","dump_ip_packet","dump_ip_v6_packet","dump_ipv6_packet","dump_tcp_packet","dump_tcp_v6_packet","dump_udp_packet","dump_udp_v6_packet","forge_frame","forge_icmp_packet","forge_icmp_v6_packet","forge_igmp_packet","forge_igmp_v6_packet","forge_ip_packet","forge_ip_v6_packet","forge_ipv6_packet","forge_tcp_packet","forge_tcp_v6_packet","forge_udp_packet","forge_udp_v6_packet","get_icmp_element","get_icmp_v6_element","get_ip_element","get_ip_v6_element","get_ipv6_element","get_local_mac_address_from_ip","get_tcp_element","get_tcp_option","get_tcp_v6_element","get_tcp_v6_option","get_udp_element","get_udp_v6_element","insert_ip_options","insert_ip_v6_options","insert_ipv6_options","insert_tcp_options","insert_tcp_v6_options","pcap_next","send_arp_request","send_capture","send_frame","send_packet","send_v6packet","set_ip_elements","set_ip_v6_elements","set_ipv6_elements","set_tcp_elements","set_tcp_v6_elements","set_udp_elements","set_udp_v6_elements","tcp_ping","tcp_v6_ping"),"regular-expressions",make_list("egrep","eregmatch","ereg","ereg_replace"),"report-functions",make_list("error_message","log_message","scanner_status","security_message"),"smb-functions",make_list("smb_close","smb_connect","smb_file_group_sid","smb_file_owner_sid","smb_file_SDDL","smb_file_trustee_rights","smb_versioninfo","win_cmd_exec"),"snmp-functions",make_list("snmpv1_get","snmpv1_getnext","snmpv2c_get","snmpv2c_getnext","snmpv3_get","snmpv3_getnext"),"ssh-functions",make_list("sftp_enabled_check","ssh_connect","ssh_disconnect","ssh_get_auth_methods","ssh_get_host_key","ssh_get_issue_banner","ssh_get_server_banner","ssh_get_sock","ssh_login_interactive","ssh_login_interactive_pass","ssh_request_exec","ssh_session_id_from_sock","ssh_set_login","ssh_shell_close","ssh_shell_open","ssh_shell_read","ssh_shell_write","ssh_userauth"),"string-functions",make_list("chomp","crap","display","hex","hexstr","insstr","int","match","ord","raw_string","split","strcat","stridx","string","strlen","str_replace","strstr","substr","tolower","toupper"),"tls",make_list("get_sock_info","socket_cert_verify","socket_check_ssl_safe_renegotiation","socket_get_cert","socket_get_error","socket_get_ssl_ciphersuite","socket_get_ssl_session_id","socket_get_ssl_version","socket_negotiate_ssl","socket_ssl_do_handshake"),"unsafe",make_list("file_close","file_open","file_read","file_seek","file_stat","file_write","find_in_path","fread","fwrite","get_tmp_dir","pread","unlink"),"wmi-functions",make_list("openvas-smb","wmi_close","wmi_connect","wmi_connect_reg","wmi_connect_rsop","wmi_query","wmi_query_rsop","wmi_reg_create_key","wmi_reg_delete_key","wmi_reg_enum_key","wmi_reg_enum_value","wmi_reg_get_bin_val","wmi_reg_get_dword_val","wmi_reg_get_ex_string_val","wmi_reg_get_mul_string_val","wmi_reg_get_qword_val","wmi_reg_get_sz","wmi_reg_set_dword_val","wmi_reg_set_ex_string_val","wmi_reg_set_qword_val","wmi_reg_set_string_val","wmi_versioninfo"));
categories = make_list("built-in-plugins","cert-functions","cryptographic","description-functions","glue-functions","host-functions","http-functions","isotime-functions","knowledge-base","misc","network-functions","raw-ip-functions","regular-expressions","report-functions","smb-functions","snmp-functions","ssh-functions","string-functions","tls","unsafe","wmi-functions");

covered = make_array();
not_covered = make_array();

display("# Coverage of NASL builtin-functions of rust implementation");
display();


number_of_functions = 0;
number_of_functions_covered = 0;
number_of_functions_not_covered = 0;

foreach category (categories) {
    covered[category] = make_list();
    not_covered[category] = make_list();
    foreach fn (functions[category]) {
        number_of_functions++;
        if (defined_func(fn)) {
            number_of_functions_covered++;
            covered[category] = make_list(covered[category], fn);
        } else {
            number_of_functions_not_covered++;
            not_covered[category] = make_list(not_covered[category], fn);
        }
    }
}

display("Number of Functions: ", number_of_functions);
display();
display("Functions covered: ", number_of_functions_covered);
display();
display("Functions missing: ", number_of_functions_not_covered);
display();

foreach category (categories) {
    display("## ", category);
    display();

    covered_cat = covered[category];
    not_covered_cat = not_covered[category];
    display("Number of Functions: ", max_index(covered_cat) + max_index(not_covered_cat));
    display();
    display("Functions covered: ", max_index(covered_cat));
    display();
    display("Functions missing: ", max_index(not_covered_cat));
    display();

    display("|covered|not covered|");
    display("|-|-|");
    a = max_index(covered[category]);
    b = max_index(not_covered[category]);
    max_value = 0;
    if (a > b) {
        max_value = a;
    } else {
        max_value = b;
    }

    for(i = 0; i < max_value; i++) {
        display("|", covered_cat[i], "|", not_covered_cat[i], "|");
    }
    display();
}
