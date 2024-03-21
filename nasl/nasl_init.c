/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_init.h"

#include "../misc/network.h"        /* for OPENVAS_ENCAPS_* */
#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "exec.h"
#include "nasl.h"
#include "nasl_builtin_plugins.h"
#include "nasl_cert.h"
#include "nasl_cmd_exec.h"
#include "nasl_crypto.h"
#include "nasl_crypto2.h"
#include "nasl_debug.h"
#include "nasl_frame_forgery.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_host.h"
#include "nasl_http.h"
#include "nasl_http2.h"
#include "nasl_isotime.h"
#include "nasl_lex_ctxt.h"
#include "nasl_misc_funcs.h"
#include "nasl_packet_forgery.h"
#include "nasl_packet_forgery_v6.h"

#include <stdlib.h> /* for getenv.  */
#include <string.h> /* for memset */
/* to e.g. favour BSD, but also for IPPROTO_TCP and TH_FIN */
#include "nasl_raw.h"
#include "nasl_scanner_glue.h"
#include "nasl_smb.h"
#include "nasl_snmp.h"
#include "nasl_socket.h"
#include "nasl_ssh.h"
#include "nasl_text_utils.h"
#include "nasl_tree.h"
#include "nasl_var.h"
#include "nasl_wmi.h"

/* **************************************************************** */

typedef struct
{
  /* XXX: Unify with nasl_func */
  const char *name;
  tree_cell *(*c_code) (lex_ctxt *);
} init_func;

/**
 * Mapping of function names in NASL (eg. script_name("english")) to the
 * C function pointers (e.g. script_name (lex_ctx**) ), argument count and
 * argument Meta-information (names).
 */
static init_func libfuncs[] = {
  {"script_name", script_name},
  {"script_version", script_version},
  {"script_timeout", script_timeout},
  {"script_copyright", script_copyright},
  {"script_category", script_category},
  {"script_family", script_family},
  {"script_dependencies", script_dependencies},
  {"script_require_keys", script_require_keys},
  {"script_mandatory_keys", script_mandatory_keys},
  {"script_require_ports", script_require_ports},
  {"script_require_udp_ports", script_require_udp_ports},
  {"script_exclude_keys", script_exclude_keys},
  {"script_add_preference", script_add_preference},
  {"script_get_preference", script_get_preference},
  {"script_get_preference_file_content", script_get_preference_file_content},
  {"script_get_preference_file_location", script_get_preference_file_location},
  {"script_oid", script_oid},
  {"script_cve_id", script_cve_id},
  {"script_xref", script_xref},
  {"script_tag", script_tag},
  {"vendor_version", nasl_vendor_version},
  {"update_table_driven_lsc_data", nasl_update_table_driven_lsc_data},
  {"get_preference", nasl_get_preference},
  {"safe_checks", safe_checks},
  {"get_script_oid", get_script_oid},
  {"replace_kb_item", replace_kb_item},
  {"set_kb_item", set_kb_item},
  {"get_kb_item", get_kb_item},
  {"get_kb_list", get_kb_list},
  {"get_host_kb_index", get_host_kb_index},
  {"security_message", security_message},
  {"log_message", log_message},
  {"error_message", error_message},
  {"open_sock_tcp", nasl_open_sock_tcp},
  {"open_sock_udp", nasl_open_sock_udp},
  {"open_priv_sock_tcp", nasl_open_priv_sock_tcp},
  {"open_priv_sock_udp", nasl_open_priv_sock_udp},
  {"socket_get_error", nasl_socket_get_error},
  {"recv", nasl_recv},
  {"recv_line", nasl_recv_line},
  {"send", nasl_send},
  {"get_mtu", nasl_get_mtu},
  {"socket_negotiate_ssl", nasl_socket_negotiate_ssl},
  {"socket_check_ssl_safe_renegotiation",
   nasl_socket_check_ssl_safe_renegotiation},
  {"socket_ssl_do_handshake", nasl_socket_ssl_do_handshake},
  {"socket_get_cert", nasl_socket_get_cert},
  {"socket_get_ssl_version", nasl_socket_get_ssl_version},
  {"socket_get_ssl_ciphersuite", nasl_socket_get_ssl_ciphersuite},
  {"socket_get_ssl_session_id", nasl_socket_get_ssl_session_id},
  {"socket_cert_verify", nasl_socket_cert_verify},
  {"close", nasl_close_socket},
  {"join_multicast_group", nasl_join_multicast_group},
  {"leave_multicast_group", nasl_leave_multicast_group},
  {"get_source_port", nasl_get_source_port},
  {"get_sock_info", nasl_get_sock_info},
  {"cgibin", cgibin},
  {"http_open_socket", http_open_socket},
  {"http_head", http_head},
  {"http_get", http_get},
  {"http_post", http_post},
  {"http_delete", http_delete},
  {"http_put", http_put},
  {"http_close_socket", http_close_socket},
  {"http2_handle", nasl_http2_handle},
  {"http2_get_response_code", nasl_http2_get_response_code},
  {"http2_close_handle", nasl_http2_close_handle},
  {"http2_set_custom_header", nasl_http2_set_custom_header},
  {"http2_get", nasl_http2_get},
  {"http2_head", nasl_http2_head},
  {"http2_post", nasl_http2_post},
  {"http2_delete", nasl_http2_delete},
  {"http2_put", nasl_http2_put},
  {"add_host_name", add_hostname},
  {"get_host_name", get_hostname},
  {"get_host_names", get_hostnames},
  {"get_host_name_source", get_hostname_source},
  {"resolve_host_name", resolve_hostname},
  {"resolve_hostname_to_multiple_ips", resolve_hostname_to_multiple_ips},
  {"get_host_ip", get_host_ip},
  {"get_local_mac_address_from_ip", nasl_get_local_mac_address_from_ip},
  {"same_host", nasl_same_host},
  {"TARGET_IS_IPV6", nasl_target_is_ipv6},
  {"get_host_open_port", get_host_open_port},
  {"get_port_state", get_port_state},
  {"get_tcp_port_state", get_port_state},
  {"get_udp_port_state", get_udp_port_state},
  {"scanner_add_port", nasl_scanner_add_port},
  {"scanner_status", nasl_scanner_status},
  {"scanner_get_port", nasl_scanner_get_port},
  {"islocalhost", nasl_islocalhost},
  {"islocalnet", nasl_islocalnet},
  {"get_port_transport", get_port_transport},
  {"this_host", nasl_this_host},
  {"this_host_name", nasl_this_host_name},
  {"string", nasl_string},
  {"raw_string", nasl_rawstring},
  {"strcat", nasl_strcat},
  {"display", nasl_display},
  {"ord", nasl_ord},
  {"hex", nasl_hex},
  {"hexstr", nasl_hexstr},
  {"strstr", nasl_strstr},
  {"ereg", nasl_ereg},
  {"ereg_replace", nasl_ereg_replace},
  {"egrep", nasl_egrep},
  {"eregmatch", nasl_eregmatch},
  {"match", nasl_match},
  {"substr", nasl_substr},
  {"insstr", nasl_insstr},
  {"tolower", nasl_tolower},
  {"toupper", nasl_toupper},
  {"crap", nasl_crap},
  {"strlen", nasl_strlen},
  {"split", nasl_split},
  {"chomp", nasl_chomp},
  {"int", nasl_int},
  {"stridx", nasl_stridx},
  {"str_replace", nasl_str_replace},
  {"make_list", nasl_make_list},
  {"make_array", nasl_make_array},
  {"keys", nasl_keys},
  {"max_index", nasl_max_index},
  {"sort", nasl_sort_array},
  {"unixtime", nasl_unixtime},
  {"gettimeofday", nasl_gettimeofday},
  {"localtime", nasl_localtime},
  {"mktime", nasl_mktime},
  {"open_sock_kdc", nasl_open_sock_kdc},
  {"telnet_init", nasl_telnet_init},
  {"ftp_log_in", nasl_ftp_log_in},
  {"ftp_get_pasv_port", nasl_ftp_get_pasv_address},
  {"start_denial", nasl_start_denial},
  {"end_denial", nasl_end_denial},
  {"dump_ctxt", nasl_dump_ctxt},
  {"typeof", nasl_typeof},
  {"exit", nasl_do_exit},
  {"rand", nasl_rand},
  {"usleep", nasl_usleep},
  {"sleep", nasl_sleep},
  {"isnull", nasl_isnull},
  {"defined_func", nasl_defined_func},

  /* Following 5 entries needed for backwards compatibility.
   * TODO: Once versions older than 20.08 are no longer in use these 5 entries
   * can be deleted. */
  {"forge_ipv6_packet", forge_ip_v6_packet},
  {"get_ipv6_element", get_ip_v6_element},
  {"set_ipv6_elements", set_ip_v6_elements},
  {"insert_ipv6_options", insert_ip_v6_options},
  {"dump_ipv6_packet", dump_ip_v6_packet},

  {"forge_ip_packet", forge_ip_packet},
  {"forge_ip_v6_packet", forge_ip_v6_packet},
  {"get_ip_element", get_ip_element},
  {"get_ip_v6_element", get_ip_v6_element},
  {"set_ip_elements", set_ip_elements},
  {"set_ip_v6_elements", set_ip_v6_elements},
  {"insert_ip_options", insert_ip_options},
  {"insert_ip_v6_options", insert_ip_v6_options},
  {"dump_ip_packet", dump_ip_packet},
  {"dump_ip_v6_packet", dump_ip_v6_packet},
  {"forge_tcp_packet", forge_tcp_packet},
  {"forge_tcp_v6_packet", forge_tcp_v6_packet},
  {"get_tcp_element", get_tcp_element},
  {"get_tcp_v6_element", get_tcp_v6_element},
  {"get_tcp_option", get_tcp_option},
  {"get_tcp_v6_option", get_tcp_v6_option},
  {"set_tcp_elements", set_tcp_elements},
  {"set_tcp_v6_elements", set_tcp_v6_elements},
  {"insert_tcp_options", insert_tcp_options},
  {"insert_tcp_v6_options", insert_tcp_v6_options},
  {"dump_tcp_packet", dump_tcp_packet},
  {"dump_tcp_v6_packet", dump_tcp_v6_packet},
  {"tcp_ping", nasl_tcp_ping},
  {"tcp_v6_ping", nasl_tcp_v6_ping},
  {"forge_udp_packet", forge_udp_packet},
  {"forge_udp_v6_packet", forge_udp_v6_packet},
  {"get_udp_element", get_udp_element},
  {"get_udp_v6_element", get_udp_v6_element},
  {"set_udp_elements", set_udp_elements},
  {"set_udp_v6_elements", set_udp_v6_elements},
  {"dump_udp_packet", dump_udp_packet},
  {"dump_udp_v6_packet", dump_udp_v6_packet},
  {"forge_icmp_packet", forge_icmp_packet},
  {"forge_icmp_v6_packet", forge_icmp_v6_packet},
  {"get_icmp_element", get_icmp_element},
  {"get_icmp_v6_element", get_icmp_v6_element},
  {"dump_icmp_packet", dump_icmp_packet},
  {"dump_icmp_v6_packet", dump_icmp_v6_packet},
  {"forge_igmp_packet", forge_igmp_packet},
  {"forge_igmp_v6_packet", forge_igmp_v6_packet},
  {"send_packet", nasl_send_packet},
  {"send_v6packet", nasl_send_v6packet},
  {"send_arp_request", nasl_send_arp_request},
  {"forge_frame", nasl_forge_frame},
  {"send_frame", nasl_send_frame},
  {"dump_frame", nasl_dump_frame},
  {"pcap_next", nasl_pcap_next},
  {"send_capture", nasl_send_capture},
  {"MD2", nasl_md2},
  {"MD4", nasl_md4},
  {"MD5", nasl_md5},
  {"SHA1", nasl_sha1},
  {"SHA256", nasl_sha256},
  {"SHA512", nasl_sha512},
  {"RIPEMD160", nasl_ripemd160},
  {"HMAC_MD2", nasl_hmac_md2},
  {"HMAC_MD5", nasl_hmac_md5},
  {"HMAC_SHA1", nasl_hmac_sha1},
  {"HMAC_SHA256", nasl_hmac_sha256},
  {"HMAC_SHA384", nasl_hmac_sha384},
  {"HMAC_SHA512", nasl_hmac_sha512},
  {"HMAC_RIPEMD160", nasl_hmac_ripemd160},
  {"prf_sha256", nasl_prf_sha256},
  {"prf_sha384", nasl_prf_sha384},
  {"tls1_prf", nasl_tls1_prf},
  {"ntlmv2_response", nasl_ntlmv2_response},
  {"ntlm2_response", nasl_ntlm2_response},
  {"ntlm_response", nasl_ntlm_response},
  {"key_exchange", nasl_keyexchg},
  {"NTLMv1_HASH", nasl_ntlmv1_hash},
  {"NTLMv2_HASH", nasl_ntlmv2_hash},
  {"nt_owf_gen", nasl_nt_owf_gen},
  {"lm_owf_gen", nasl_lm_owf_gen},
  {"ntv2_owf_gen", nasl_ntv2_owf_gen},
  {"insert_hexzeros", nasl_insert_hexzeros},
  {"dec2str", nasl_dec2str},
  {"get_signature", nasl_get_sign},
  {"get_smb2_signature", nasl_get_smb2_sign},
  {"smb_cmac_aes_signature", nasl_smb_cmac_aes_sign},
  {"smb_gmac_aes_signature", nasl_smb_gmac_aes_sign},
  {"dh_generate_key", nasl_dh_generate_key},
  {"bn_random", nasl_bn_random},
  {"bn_cmp", nasl_bn_cmp},
  {"dh_compute_key", nasl_dh_compute_key},
  {"rsa_public_encrypt", nasl_rsa_public_encrypt},
  {"rsa_private_decrypt", nasl_rsa_private_decrypt},
  {"rsa_public_decrypt", nasl_rsa_public_decrypt},
  {"bf_cbc_encrypt", nasl_bf_cbc_encrypt},
  {"bf_cbc_decrypt", nasl_bf_cbc_decrypt},
  {"rc4_encrypt", nasl_rc4_encrypt},
  {"aes_mac_cbc", nasl_aes_mac_cbc},
  {"aes_mac_gcm", nasl_aes_mac_gcm},
  {"aes128_cbc_encrypt", nasl_aes128_cbc_encrypt},
  {"aes256_cbc_encrypt", nasl_aes256_cbc_encrypt},
  {"aes128_ctr_encrypt", nasl_aes128_ctr_encrypt},
  {"aes256_ctr_encrypt", nasl_aes256_ctr_encrypt},
  {"aes128_gcm_encrypt", nasl_aes128_gcm_encrypt},
  {"aes128_gcm_encrypt_auth", nasl_aes128_gcm_encrypt_auth},
  {"aes128_gcm_decrypt", nasl_aes128_gcm_decrypt},
  {"aes128_gcm_decrypt_auth", nasl_aes128_gcm_decrypt_auth},
  {"aes256_gcm_encrypt", nasl_aes256_gcm_encrypt},
  {"aes256_gcm_encrypt_auth", nasl_aes256_gcm_encrypt_auth},
  {"aes256_gcm_decrypt", nasl_aes256_gcm_decrypt},
  {"aes256_gcm_decrypt_auth", nasl_aes256_gcm_decrypt_auth},
  {"aes128_ccm_encrypt", nasl_aes128_ccm_encrypt},
  {"aes128_ccm_encrypt_auth", nasl_aes128_ccm_encrypt_auth},
  {"aes128_ccm_decrypt", nasl_aes128_ccm_decrypt},
  {"aes128_ccm_decrypt_auth", nasl_aes128_ccm_decrypt_auth},
  {"aes256_ccm_encrypt", nasl_aes256_ccm_encrypt},
  {"aes256_ccm_encrypt_auth", nasl_aes256_ccm_encrypt_auth},
  {"aes256_ccm_decrypt", nasl_aes256_ccm_decrypt},
  {"aes256_ccm_decrypt_auth", nasl_aes256_ccm_decrypt_auth},
  {"smb3kdf", nasl_smb3kdf},
  {"des_ede_cbc_encrypt", nasl_des_ede_cbc_encrypt},
  {"open_rc4_cipher", nasl_open_rc4_cipher},
  {"close_stream_cipher", nasl_close_stream_cipher},
  {"dsa_do_verify", nasl_dsa_do_verify},
  {"pem_to_rsa", nasl_pem_to_rsa},
  {"pem_to_dsa", nasl_pem_to_dsa},
  {"rsa_sign", nasl_rsa_sign},
  {"dsa_do_sign", nasl_dsa_do_sign},
  {"gunzip", nasl_gunzip},
  {"gzip", nasl_gzip},
  {"DES", nasl_cipher_des},
  {"snmpv1_get", nasl_snmpv1_get},
  {"snmpv1_getnext", nasl_snmpv1_getnext},
  {"snmpv2c_get", nasl_snmpv2c_get},
  {"snmpv2c_getnext", nasl_snmpv2c_getnext},
  {"snmpv3_get", nasl_snmpv3_get},
  {"snmpv3_getnext", nasl_snmpv3_getnext},
  {"ssh_connect", nasl_ssh_connect},
  {"ssh_disconnect", nasl_ssh_disconnect},
  {"ssh_session_id_from_sock", nasl_ssh_session_id_from_sock},
  {"ssh_get_sock", nasl_ssh_get_sock},
  {"ssh_set_login", nasl_ssh_set_login},
  {"ssh_userauth", nasl_ssh_userauth},
  {"ssh_login_interactive", nasl_ssh_login_interactive},
  {"ssh_login_interactive_pass", nasl_ssh_login_interactive_pass},
  {"ssh_request_exec", nasl_ssh_request_exec},
  {"ssh_shell_open", nasl_ssh_shell_open},
  {"ssh_shell_read", nasl_ssh_shell_read},
  {"ssh_shell_write", nasl_ssh_shell_write},
  {"ssh_shell_close", nasl_ssh_shell_close},
  {"ssh_get_issue_banner", nasl_ssh_get_issue_banner},
  {"ssh_get_server_banner", nasl_ssh_get_server_banner},
  {"ssh_get_auth_methods", nasl_ssh_get_auth_methods},
  {"ssh_get_host_key", nasl_ssh_get_host_key},
  {"ssh_execute_netconf_subsystem", nasl_ssh_execute_netconf_subsystem},
  {"sftp_enabled_check", nasl_sftp_enabled_check},
#ifdef HAVE_LIBKSBA
  {"cert_open", nasl_cert_open},
  {"cert_close", nasl_cert_close},
  {"cert_query", nasl_cert_query},
#endif /*HAVE_LIBKSBA*/

  {"pread", nasl_pread},
  {"find_in_path", nasl_find_in_path},
  {"fread", nasl_fread},
  {"fwrite", nasl_fwrite},
  {"unlink", nasl_unlink},
  {"get_tmp_dir", nasl_get_tmp_dir},
  {"get_byte_order", nasl_get_byte_order},
  {"file_stat", nasl_file_stat},
  {"file_open", nasl_file_open},
  {"file_close", nasl_file_close},
  {"file_read", nasl_file_read},
  {"file_write", nasl_file_write},
  {"file_seek", nasl_file_seek},
  {"wmi_versioninfo", nasl_wmi_versioninfo},
  {"wmi_connect", nasl_wmi_connect},
  {"wmi_close", nasl_wmi_close},
  {"wmi_query", nasl_wmi_query},
  {"wmi_connect_rsop", nasl_wmi_connect_rsop},
  {"wmi_query_rsop", nasl_wmi_query_rsop},
  {"wmi_connect_reg", nasl_wmi_connect_reg},
  {"wmi_reg_enum_key", nasl_wmi_reg_enum_key},
  {"wmi_reg_enum_value", nasl_wmi_reg_enum_value},
  {"wmi_reg_get_sz", nasl_wmi_reg_get_sz},
  {"wmi_reg_get_bin_val", nasl_wmi_reg_get_bin_val},
  {"wmi_reg_get_dword_val", nasl_wmi_reg_get_dword_val},
  {"wmi_reg_get_ex_string_val", nasl_wmi_reg_get_ex_string_val},
  {"wmi_reg_get_mul_string_val", nasl_wmi_reg_get_mul_string_val},
  {"wmi_reg_get_qword_val", nasl_wmi_reg_get_qword_val},
  {"wmi_reg_set_dword_val", nasl_wmi_reg_set_dword_val},
  {"wmi_reg_set_qword_val", nasl_wmi_reg_set_qword_val},
  {"wmi_reg_set_ex_string_val", nasl_wmi_reg_set_ex_string_val},
  {"wmi_reg_set_string_val", nasl_wmi_reg_set_string_val},
  {"wmi_reg_create_key", nasl_wmi_reg_create_key},
  {"wmi_reg_delete_key", nasl_wmi_reg_delete_key},
  {"smb_versioninfo", nasl_smb_versioninfo},
  {"smb_connect", nasl_smb_connect},
  {"smb_close", nasl_smb_close},
  {"smb_file_SDDL", nasl_smb_file_SDDL},
  {"smb_file_owner_sid", nasl_smb_file_owner_sid},
  {"smb_file_group_sid", nasl_smb_file_group_sid},
  {"smb_file_trustee_rights", nasl_smb_file_trustee_rights},
  {"win_cmd_exec", nasl_win_cmd_exec},
  {"plugin_run_find_service", plugin_run_find_service},
  {"plugin_run_openvas_tcp_scanner", plugin_run_openvas_tcp_scanner},
  {"plugin_run_synscan", plugin_run_synscan},
  {"isotime_now", nasl_isotime_now},
  {"isotime_is_valid", nasl_isotime_is_valid},
  {"isotime_scan", nasl_isotime_scan},
  {"isotime_print", nasl_isotime_print},
  {"isotime_add", nasl_isotime_add},
  {NULL, NULL}};

/* String variables */
static struct
{
  const char *name;
  const char *val;
} libsvars[] = {
  {"OPENVAS_VERSION", OPENVASLIB_VERSION},
  {NULL, NULL},
};

/* Integer variables */
static struct
{
  const char *name;
  int val;
} libivars[] = {
  {"TRUE", 1},
  {"FALSE", 0},
  {"IPPROTO_TCP", IPPROTO_TCP},
  {"IPPROTO_UDP", IPPROTO_UDP},
  {"IPPROTO_ICMP", IPPROTO_ICMP},
  {"IPPROTO_ICMPV6", IPPROTO_ICMPV6},
  {"IPPROTO_IP", IPPROTO_IP},
  {"IPPROTO_IGMP", IPPROTO_IGMP},
  {"ENCAPS_AUTO", OPENVAS_ENCAPS_AUTO},
  {"ENCAPS_IP", OPENVAS_ENCAPS_IP},
  {"ENCAPS_SSLv23", OPENVAS_ENCAPS_SSLv23},
  {"ENCAPS_SSLv2", OPENVAS_ENCAPS_SSLv2},
  {"ENCAPS_SSLv3", OPENVAS_ENCAPS_SSLv3},
  {"ENCAPS_TLSv1", OPENVAS_ENCAPS_TLSv1},
  {"ENCAPS_TLSv11", OPENVAS_ENCAPS_TLSv11},
  {"ENCAPS_TLSv12", OPENVAS_ENCAPS_TLSv12},
  {"ENCAPS_TLSv13", OPENVAS_ENCAPS_TLSv13},
  {"ENCAPS_TLScustom", OPENVAS_ENCAPS_TLScustom},
  {"ENCAPS_MAX", OPENVAS_ENCAPS_MAX},
  {"TH_FIN", TH_FIN},
  {"TH_SYN", TH_SYN},
  {"TH_RST", TH_RST},
  {"TH_PUSH", TH_PUSH},
  {"TH_ACK", TH_ACK},
  {"TH_URG", TH_URG},
  {"IP_RF", IP_RF},
  {"IP_DF", IP_DF},
  {"IP_MF", IP_MF},
  {"IP_OFFMASK", IP_OFFMASK},
  {"TCPOPT_MAXSEG", TCPOPT_MAXSEG},
  {"TCPOPT_WINDOW", TCPOPT_WINDOW},
  {"TCPOPT_SACK_PERMITTED", TCPOPT_SACK_PERMITTED},
  {"TCPOPT_TIMESTAMP", TCPOPT_TIMESTAMP},
  {"ACT_INIT", ACT_INIT},
  {"ACT_GATHER_INFO", ACT_GATHER_INFO},
  {"ACT_ATTACK", ACT_ATTACK},
  {"ACT_MIXED_ATTACK", ACT_MIXED_ATTACK},
  {"ACT_DESTRUCTIVE_ATTACK", ACT_DESTRUCTIVE_ATTACK},
  {"ACT_DENIAL", ACT_DENIAL},
  {"ACT_SCANNER", ACT_SCANNER},
  {"ACT_SETTINGS", ACT_SETTINGS},
  {"ACT_KILL_HOST", ACT_KILL_HOST},
  {"ACT_FLOOD", ACT_FLOOD},
  {"ACT_END", ACT_END},
  {"MSG_OOB", MSG_OOB},
  {"NOERR", NASL_ERR_NOERR},
  {"ETIMEDOUT", NASL_ERR_ETIMEDOUT},
  {"ECONNRESET", NASL_ERR_ECONNRESET},
  {"EUNREACH", NASL_ERR_EUNREACH},
  {"EUNKNOWN", NASL_ERR_EUNKNOWN},
  {NULL, 0},
};

/* See also in exec.c:
 * COMMAND_LINE
 * description
 */

/**
 * @brief Adds "built-in" variable and function definitions to a context.
 */
void
init_nasl_library (lex_ctxt *lexic)
{
  tree_cell tc;
  unsigned i;

  memset (&tc, 0, sizeof (tc));

  // Initialize constant integer terms
  tc.type = CONST_INT;
  for (i = 0; i < sizeof (libivars) / sizeof (libivars[0]) - 1; i++)
    {
      tc.x.i_val = libivars[i].val;
      if (add_named_var_to_ctxt (lexic, libivars[i].name, &tc) == NULL)
        {
          nasl_perror (lexic, "init_nasl_library: could not define var '%s'\n",
                       libivars[i].name);
          continue;
        }
    }

  // Initialize constant string terms
  tc.type = CONST_DATA;
  for (i = 0; i < sizeof (libsvars) / sizeof (libsvars[0]) - 1; i++)
    {
      tc.x.str_val = (char *) libsvars[i].val;
      tc.size = strlen (libsvars[i].val);
      if (add_named_var_to_ctxt (lexic, libsvars[i].name, &tc) == NULL)
        {
          nasl_perror (lexic, "init_nasl_library: could not define var '%s'\n",
                       libsvars[i].name);
          continue;
        }
    }

  // Add the "NULL" variable
  if (add_named_var_to_ctxt (lexic, "NULL", NULL) == NULL)
    nasl_perror (lexic, "init_nasl_library: could not define var 'NULL'\n");
}

nasl_func *
func_is_internal (const char *name)
{
  size_t i;

  if (!name)
    return NULL;

  for (i = 0; i < sizeof (libfuncs) / sizeof (libfuncs[0]) - 1; i++)
    {
      if (!strcmp (name, libfuncs[i].name))
        return (nasl_func *) &libfuncs[i];
    }
  return NULL;
}

char *
nasl_version ()
{
  static char vers[sizeof (OPENVASLIB_VERSION) + 1];
  strncpy (vers, OPENVASLIB_VERSION, sizeof (vers) - 1);
  vers[sizeof (vers) - 1] = '\0';
  return vers;
}

/**
 * @brief Add "built-in" variables to a list.
 */
void
add_nasl_library (GSList **list)
{
  int i;
  for (i = 0; libivars[i].name != NULL; i++)
    *list = g_slist_append (*list, g_strdup (libivars[i].name));
  for (i = 0; libsvars[i].name != NULL; i++)
    *list = g_slist_append (*list, g_strdup (libsvars[i].name));
}
