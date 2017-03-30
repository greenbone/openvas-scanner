/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "nasl_raw.h"       /* to e.g. favour BSD, but also for IPPROTO_TCP
                               and TH_FIN */

#include <string.h>         /* for memset */
#include <stdlib.h>         /* for getenv.  */

#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "../misc/network.h"      /* for OPENVAS_ENCAPS_* */

#include "nasl.h"
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "nasl_packet_forgery.h"
#include "nasl_debug.h"
#include "nasl_socket.h"
#include "nasl_http.h"
#include "nasl_host.h"
#include "nasl_text_utils.h"
#include "nasl_scanner_glue.h"
#include "nasl_misc_funcs.h"
#include "nasl_cmd_exec.h"
#include "nasl_crypto.h"
#include "nasl_crypto2.h"
#include "nasl_wmi.h"
#include "nasl_smb.h"
#include "nasl_packet_forgery_v6.h"
#include "nasl_builtin_plugins.h"
#include "nasl_ssh.h"
#include "nasl_snmp.h"
#include "nasl_cert.h"
#include "nasl_isotime.h"


/* **************************************************************** */

typedef struct
{
  const char *name;
  tree_cell *(*c_code) (lex_ctxt *);
  int unnamed;          /**< Number of unnamed arguments. */
  const char *args[16]; /**< Must be sorted and terminated with NULL. */
} init_func;

/**
 * Mapping of function names in NASL (eg. script_name("english")) to the
 * C function pointers (e.g. script_name (lex_ctx**) ), argument count and
 * argument Meta-information (names).
 */
static init_func libfuncs[] = {
  {"script_name", script_name, 1, {NULL}},
  {"script_version", script_version, 1, {NULL}},
  {"script_timeout", script_timeout, 1, {NULL}},
  {"script_copyright", script_copyright, 999, {NULL}},
  {"script_summary", script_summary, 999, {NULL}},
  {"script_category", script_category, 1, {NULL}},
  {"script_family", script_family, 999, {NULL}},
  {"script_dependencies", script_dependencies, 999, {NULL}},
  {"script_require_keys", script_require_keys, 999, {NULL}},
  {"script_mandatory_keys", script_mandatory_keys, 999, {NULL}},
  {"script_require_ports", script_require_ports, 999, {NULL}},
  {"script_require_udp_ports", script_require_udp_ports, 999, {NULL}},
  {"script_exclude_keys", script_exclude_keys, 999, {NULL}},
  {"script_add_preference", script_add_preference, 0,
   {"name", "type", "value", NULL}},
  {"script_get_preference", script_get_preference, 1, {NULL}},
  {"script_get_preference_file_content", script_get_preference_file_content, 1,
   {NULL}},
  {"script_get_preference_file_location", script_get_preference_file_location,
   1, {NULL}},

  {"script_id", script_id, 1, {NULL}},
  {"script_oid", script_oid, 1, {NULL}},
  {"script_cve_id", script_cve_id, 999, {NULL}},
  {"script_bugtraq_id", script_bugtraq_id, 999, {NULL}},
  {"script_xref", script_xref, 0, {"name", "value", NULL}},
  {"script_tag", script_tag, 0, {"name", "value", NULL}},
  {"get_preference", nasl_get_preference, 1, {NULL}},
  {"safe_checks", safe_checks, 0, {NULL}},
  {"get_script_oid", get_script_oid, 0, {NULL}},
  {"replace_kb_item", replace_kb_item, 0, {"name", "value", NULL}},
  {"set_kb_item", set_kb_item, 0, {"name", "value", NULL}},
  {"get_kb_item", get_kb_item, 2, {NULL}},
  {"get_kb_list", get_kb_list, 1, {NULL}},
  {"security_message", security_message, 1,
   {"data", "port", "proto", "protocol", NULL}},

  {"log_message", log_message, 1, {"data", "port", "proto", "protocol", NULL}},
  {"error_message", error_message, 1,
   {"data", "port", "proto", "protocol", NULL}},

  {"open_sock_tcp", nasl_open_sock_tcp, 1,
   {"bufsz", "priority", "timeout", "transport", NULL}},
  {"open_sock_udp", nasl_open_sock_udp, 1, {NULL}},
  {"open_priv_sock_tcp", nasl_open_priv_sock_tcp, 0,
   {"dport", "sport", "timeout", NULL}},
  {"open_priv_sock_udp", nasl_open_priv_sock_udp, 0, {"dport", "sport", NULL}},
  {"socket_get_error", nasl_socket_get_error, 1, {NULL}},

  {"recv", nasl_recv, 0, {"length", "min", "socket", "timeout", NULL}},
  {"recv_line", nasl_recv_line, 0, {"length", "socket", "timeout", NULL}},
  {"send", nasl_send, 0, {"data", "length", "option", "socket", NULL}},
  {"socket_negotiate_ssl", nasl_socket_negotiate_ssl, 0,
   {"socket", "transport", NULL}},
  {"socket_get_cert", nasl_socket_get_cert, 0, {"socket", NULL}},
  {"socket_get_ssl_version", nasl_socket_get_ssl_version, 0, {"socket", NULL}},
  {"socket_get_ssl_ciphersuite", nasl_socket_get_ssl_ciphersuite, 0,
   {"socket", NULL}},
  {"socket_get_ssl_session_id", nasl_socket_get_ssl_session_id, 0,
   {"socket", NULL}},
  {"socket_get_ssl_compression", nasl_socket_get_ssl_compression, 0,
   {"socket", NULL}},
  {"close", nasl_close_socket, 1, {NULL}},
  {"join_multicast_group", nasl_join_multicast_group, 1, {NULL}},
  {"leave_multicast_group", nasl_leave_multicast_group, 1, {NULL}},
  {"get_source_port", nasl_get_source_port, 1, {NULL}}, /* DOC! */
  {"get_sock_info", nasl_get_sock_info, 2, {"asstring", NULL}},

  {"cgibin", cgibin, 0, {NULL}},
  {"http_open_socket", http_open_socket, 1, {NULL}},
  {"http_head", http_head, 0, {"data", "item", "port", NULL}},
  {"http_get", http_get, 0, {"data", "item", "port", NULL}},
  {"http_post", http_post, 0, {"data", "item", "port", NULL}},
  {"http_delete", http_delete, 0, {"data", "item", "port", NULL}},
  {"http_put", http_put, 0, {"data", "item", "port", NULL}},
  {"http_close_socket", http_close_socket, 0, {"socket", NULL}},

  {"get_host_name", get_hostname, 0, {NULL}},
  {"get_host_ip", get_host_ip, 0, {NULL}},
  {"same_host", nasl_same_host, 2, {"cmp_hostname"}},
  {"TARGET_IS_IPV6", nasl_target_is_ipv6, 0, {NULL}},

  {"get_host_open_port", get_host_open_port, 0, {NULL}},
  {"get_port_state", get_port_state, 1, {NULL}},
  {"get_tcp_port_state", get_port_state, 1, {NULL}},
  {"get_udp_port_state", get_udp_port_state, 1, {NULL}},
  {"scanner_add_port", nasl_scanner_add_port, 0, {"port", "proto", NULL}},
  {"scanner_status", nasl_scanner_status, 0, {"current", "total", NULL}},
  {"scanner_get_port", nasl_scanner_get_port, 1, {NULL}},
  {"islocalhost", nasl_islocalhost, 0, {NULL}},
  {"islocalnet", nasl_islocalnet, 0, {NULL}},
  {"get_port_transport", get_port_transport, 1, {"asstring", NULL}},
  {"this_host", nasl_this_host, 0, {NULL}},
  {"this_host_name", nasl_this_host_name, 0, {NULL}},

  {"string", nasl_string, 9999, {NULL}},
  {"raw_string", nasl_rawstring, 9999, {NULL}},
  {"strcat", nasl_strcat, 9999, {NULL}},

  {"display", nasl_display, 9999, {NULL}},
  {"ord", nasl_ord, 1, {NULL}},
  {"hex", nasl_hex, 1, {NULL}},
  {"hexstr", nasl_hexstr, 1, {NULL}},
  {"strstr", nasl_strstr, 2, {NULL}},
  {"ereg", nasl_ereg, 0, {"icase", "multiline", "pattern", "string", NULL}},
  {"ereg_replace", nasl_ereg_replace, 0,
   {"icase", "pattern", "replace", "string", NULL}},
  {"egrep", nasl_egrep, 0, {"icase", "pattern", "string", NULL}},
  {"eregmatch", nasl_eregmatch, 0, {"icase", "pattern", "string", NULL}},

  {"match", nasl_match, 0, {"icase", "pattern", "string", NULL}},
  {"substr", nasl_substr, 3, {NULL}},
  {"insstr", nasl_insstr, 4, {NULL}},
  {"tolower", nasl_tolower, 1, {NULL}},
  {"toupper", nasl_toupper, 1, {NULL}},
  {"crap", nasl_crap, 1, {"data", "length", NULL}},
  {"strlen", nasl_strlen, 1, {NULL}},
  {"split", nasl_split, 1, {"keep", "sep", NULL}},
  {"chomp", nasl_chomp, 1, {NULL}},
  {"int", nasl_int, 1, {NULL}},
  {"stridx", nasl_stridx, 3, {NULL}},
  {"str_replace", nasl_str_replace, 0,
   {"count", "find", "replace", "string", NULL}},

  {"make_list", nasl_make_list, 9999, {NULL}},
  {"make_array", nasl_make_array, 9999, {NULL}},
  {"keys", nasl_keys, 9999, {NULL}},
  {"max_index", nasl_max_index, 1, {NULL}},
  {"sort", nasl_sort_array, 9999, {NULL}},

  {"unixtime", nasl_unixtime, 0, {NULL}},
  {"gettimeofday", nasl_gettimeofday, 0, {NULL}},
  {"localtime", nasl_localtime, 1, {"utc"}},
  {"mktime", nasl_mktime, 0,
   {"hour", "isdst", "mday", "min", "mon", "sec", "year"}},

  {"open_sock_kdc", nasl_open_sock_kdc, 0, {NULL}},

  {"telnet_init", nasl_telnet_init, 1, {NULL}},
  {"ftp_log_in", nasl_ftp_log_in, 0, {"pass", "socket", "user", NULL}},
  {"ftp_get_pasv_port", nasl_ftp_get_pasv_address, 0, {"socket", NULL}},
  {"start_denial", nasl_start_denial, 0, {NULL}},
  {"end_denial", nasl_end_denial, 0, {NULL}},

  {"dump_ctxt", nasl_dump_ctxt, 0, {NULL}},
  {"typeof", nasl_typeof, 1, {NULL}},

  {"exit", nasl_do_exit, 1, {NULL}},
  {"rand", nasl_rand, 0, {NULL}},
  {"usleep", nasl_usleep, 1, {NULL}},
  {"sleep", nasl_sleep, 1, {NULL}},
  {"isnull", nasl_isnull, 1, {NULL}},
  {"defined_func", nasl_defined_func, 1, {NULL}},
  {"func_named_args", nasl_func_named_args, 1, {NULL}},
  {"func_unnamed_args", nasl_func_unnamed_args, 1, {NULL}},
  {"func_has_arg", nasl_func_has_arg, 2, {NULL}},

  {"forge_ip_packet", forge_ip_packet, 0,
   {"data", "ip_dst", "ip_hl", "ip_id", "ip_len", "ip_off", "ip_p",
    "ip_src", "ip_sum", "ip_tos", "ip_ttl", "ip_v", NULL}},
  {"forge_ipv6_packet", forge_ipv6_packet, 0,
   {"data", "ip6_dst", "ip6_fl", "ip6_hlim", "ip6_p", "ip6_src",
    "ip6_tc", "ip6_v", NULL}},

  {"get_ip_element", get_ip_element, 0, {"element", "ip", NULL}},
  {"get_ipv6_element", get_ipv6_element, 0, {"element", "ipv6", NULL}},

  {"set_ip_elements", set_ip_elements, 0,
   {"ip", "ip_dst", "ip_hl", "ip_id",
    "ip_len", "ip_off", "ip_p", "ip_src",
    "ip_sum", "ip_tos", "ip_ttl", "ip_v", NULL}},
  {"set_ipv6_elements", set_ipv6_elements, 0,
   {"ip6", "ip6_dst", "ip6_fl", "ip6_hlim", "ip6_nxt", "ip6_plen",
    "ip6_src", "ip6_tc", "ip6_v", NULL}},

  {"insert_ip_options", insert_ip_options, 0,
   {"code", "ip", "length", "value", NULL}},
  {"insert_ipv6_options", insert_ipv6_options, 0,
   {"code", "flags", "ip6", "length", "lifetime", "reacheable_time",
    "retransmit_timer", "value", NULL}},
  {"dump_ip_packet", dump_ip_packet, 9999, {NULL}},
  {"dump_ipv6_packet", dump_ipv6_packet, 9999, {NULL}},

  {"forge_tcp_packet", forge_tcp_packet, 0,
   {"data", "ip", "th_ack", "th_dport", "th_flags", "th_off", "th_seq",
    "th_sport", "th_sum", "th_urp", "th_win", "th_x2", "update_ip_len", NULL}},
  {"forge_tcp_v6_packet", forge_tcp_v6_packet, 0,
   {"data", "ip6", "th_ack", "th_dport", "th_flags", "th_off",
    "th_seq", "th_sport", "th_sum", "th_urp",
    "th_win", "th_x2", NULL}},

  {"get_tcp_element", get_tcp_element, 0,
   {"element", "tcp", NULL}},
  {"get_tcp_v6_element", get_tcp_v6_element, 0,
   {"element", "tcp", NULL}},

  {"set_tcp_elements", set_tcp_elements, 0,
   {"data", "tcp", "th_ack", "th_dport", "th_flags", "th_off", "th_seq",
    "th_sport", "th_sum", "th_urp", "th_win", "th_x2", NULL}},
  {"set_tcp_v6_elements", set_tcp_v6_elements, 0,
   {"data", "tcp", "th_ack", "th_dport",
    "th_flags", "th_off", "th_seq", "th_sport",
    "th_sum", "th_urp", "th_win", "th_x2", NULL}},

  {"dump_tcp_packet", dump_tcp_packet, 999, {NULL}},
  {"dump_tcp_v6_packet", dump_tcp_v6_packet, 999, {NULL}},
  {"tcp_ping", nasl_tcp_ping, 0, {"port", NULL}},
  {"tcp_v6_ping", nasl_tcp_v6_ping, 0, {"port", NULL}},

  {"forge_udp_packet", forge_udp_packet, 0,
   {"data", "ip", "uh_dport", "uh_sport", "uh_sum", "uh_ulen", "update_ip_len",
    NULL}},
  {"forge_udp_v6_packet", forge_udp_v6_packet, 0,
   {"data", "ip6", "uh_dport", "uh_sport", "uh_sum", "uh_ulen",
    "update_ip6_len", NULL}},

  {"get_udp_element", get_udp_element, 0,
   {"element", "udp", NULL}},
  {"get_udp_v6_element", get_udp_v6_element, 0,
   {"element", "udp", NULL}},

  {"set_udp_elements", set_udp_elements, 0,
   {"data", "udp", "uh_dport", "uh_sport", "uh_sum", "uh_ulen", NULL}},
  {"set_udp_v6_elements", set_udp_v6_elements, 0,
   {"data", "udp", "uh_dport", "uh_sport", "uh_sum", "uh_ulen", NULL}},

  {"dump_udp_packet", dump_udp_packet, 999, {NULL}},
  {"dump_udp_v6_packet", dump_udp_v6_packet, 999, {NULL}},

  {"forge_icmp_packet", forge_icmp_packet, 0,
   {"data", "icmp_cksum", "icmp_code", "icmp_id", "icmp_seq", "icmp_type",
    "ip", "update_ip_len", NULL}},
  {"forge_icmp_v6_packet", forge_icmp_v6_packet, 0,
   {"data", "icmp_cksum", "icmp_code", "icmp_id", "icmp_seq", "icmp_type",
    "ip6", "update_ip6_len", NULL}},

  {"get_icmp_element", get_icmp_element, 0,
   {"element", "icmp", NULL}},
  {"get_icmp_v6_element", get_icmp_v6_element, 0,
   {"element", "icmp", NULL}},

  {"forge_igmp_packet", forge_igmp_packet, 0,
   {"code", "data", "group", "ip", "type", "update_ip_len", NULL}},
  {"forge_igmp_v6_packet", forge_igmp_v6_packet, 0,
   {"code", "data", "group", "ip", "type", "update_ip6_len", NULL}},
  {"send_packet", nasl_send_packet, 99,
   {"length", "pcap_active", "pcap_filter", "pcap_timeout", NULL}},
  {"send_v6packet", nasl_send_v6packet, 99,
   {"length", "pcap_active", "pcap_filter", "pcap_timeout", NULL}},

  {"pcap_next", nasl_pcap_next, 1,
   {"interface", "pcap_filter", "timeout", NULL}},
  {"send_capture", nasl_send_capture, 1,
   {"data", "interface", "length", "option", "pcap_filter", "socket", "timeout",
    NULL}},

  {"MD2", nasl_md2, 1, {NULL}},
  {"MD4", nasl_md4, 1, {NULL}},
  {"MD5", nasl_md5, 1, {NULL}},
  {"SHA1", nasl_sha1, 1, {NULL}},
  {"SHA256", nasl_sha256, 1, {NULL}},
  {"RIPEMD160", nasl_ripemd160, 1, {NULL}},
  {"HMAC_MD2", nasl_hmac_md2, 0, {"data", "key", NULL}},
  {"HMAC_MD5", nasl_hmac_md5, 0, {"data", "key", NULL}},
  {"HMAC_SHA1", nasl_hmac_sha1, 0, {"data", "key", NULL}},
  {"HMAC_SHA256", nasl_hmac_sha256, 0, {"data", "key", NULL}},
  {"HMAC_SHA384", nasl_hmac_sha384, 0, {"data", "key", NULL}},
  {"HMAC_SHA512", nasl_hmac_sha512, 0, {"data", "key", NULL}},
  {"HMAC_RIPEMD160", nasl_hmac_ripemd160, 0, {"data", "key", NULL}},
  {"prf_sha256", nasl_prf_sha256, 0, {"label", "outlen", "secret", "seed", NULL}},
  {"prf_sha384", nasl_prf_sha384, 0, {"label", "outlen", "secret", "seed", NULL}},
  {"tls1_prf", nasl_tls1_prf, 0, {"label", "outlen", "secret", "seed", NULL}},
  {"ntlmv2_response", nasl_ntlmv2_response, 0,
   {"address_list", "address_list_len", "crypt_key", "domain", "ntlmv2_hash",
    "user", NULL}},
  {"ntlm2_response", nasl_ntlm2_response, 0,
   {"cryptkey", "nt_hash", "password", NULL}},
  {"ntlm_response", nasl_ntlm_response, 0,
   {"cryptkey", "neg_flags", "nt_hash", "password", NULL}},
  {"key_exchange", nasl_keyexchg, 0,
   {"cryptkey", "nt_hash", "session_key", NULL}},
  {"NTLMv1_HASH", nasl_ntlmv1_hash, 0, {"cryptkey", "passhash", NULL}},
  {"NTLMv2_HASH", nasl_ntlmv2_hash, 0,
   {"cryptkey", "length", "passhash", NULL}},
  {"nt_owf_gen", nasl_nt_owf_gen, 1, {NULL}},
  {"lm_owf_gen", nasl_lm_owf_gen, 1, {NULL}},
  {"ntv2_owf_gen", nasl_ntv2_owf_gen, 0, {"domain", "login", "owf", NULL}},
  {"insert_hexzeros", nasl_insert_hexzeros, 0, {"in", NULL}},
  {"dec2str", nasl_dec2str, 0, {"num", NULL}},
  {"get_signature", nasl_get_sign, 0,
   {"buf", "buflen", "key", "seq_number", NULL}},
  {"get_smb2_signature", nasl_get_smb2_sign, 0,
   {"buf", "key", NULL}},
  {"dh_generate_key", nasl_dh_generate_key, 0, {"g", "p", "priv", NULL}},
  {"bn_random", nasl_bn_random, 0, {"need", NULL}},
  {"bn_cmp", nasl_bn_cmp, 0, {"key1", "key2", NULL}},
  {"dh_compute_key", nasl_dh_compute_key, 0,
   {"dh_server_pub", "g", "p", "priv_key", "pub_key", NULL}},
  {"rsa_public_encrypt", nasl_rsa_public_encrypt, 0,
   {"d", "data", "e", "n", "p", "padd", "q", NULL}},
  {"rsa_private_decrypt", nasl_rsa_private_decrypt, 0,
   {"d", "data", "e", "n", "p", "padd", "q", NULL}},
  {"rsa_public_decrypt", nasl_rsa_public_decrypt, 0, {"e", "n", "sig", NULL}},
  {"bf_cbc_encrypt", nasl_bf_cbc_encrypt, 0, {"data", "iv", "key", NULL}},
  {"bf_cbc_decrypt", nasl_bf_cbc_decrypt, 0, {"data", "iv", "key", NULL}},
  {"rc4_encrypt", nasl_rc4_encrypt, 0, {"data", "key", NULL}},
  {"aes128_cbc_encrypt", nasl_aes128_cbc_encrypt, 0, {"data", "key", NULL}},
  {"aes256_cbc_encrypt", nasl_aes256_cbc_encrypt, 0, {"data", "key", NULL}},
  {"aes128_ctr_encrypt", nasl_aes128_ctr_encrypt, 0, {"data", "key", NULL}},
  {"aes256_ctr_encrypt", nasl_aes256_ctr_encrypt, 0, {"data", "key", NULL}},
  {"aes128_gcm_encrypt", nasl_aes128_gcm_encrypt, 0, {"data", "key", NULL}},
  {"aes256_gcm_encrypt", nasl_aes256_gcm_encrypt, 0, {"data", "key", NULL}},
  {"des_ede_cbc_encrypt", nasl_des_ede_cbc_encrypt, 0, {"data", "key", NULL}},
  {"dsa_do_verify", nasl_dsa_do_verify, 0,
   {"data", "g", "p", "pub", "q", "r", "s", NULL}},
  {"pem_to_rsa", nasl_pem_to_rsa, 0, {"passphrase", "priv", NULL}},
  {"pem_to_dsa", nasl_pem_to_dsa, 0, {"passphrase", "priv", NULL}},
  {"rsa_sign", nasl_rsa_sign, 0, {"d", "data", "e", "n", NULL}},
  {"dsa_do_sign", nasl_dsa_do_sign, 0,
   {"data", "g", "p", "priv", "pub", "q", NULL}},
  {"gunzip", nasl_gunzip, 0, {"data", "len", NULL}},
  {"gzip", nasl_gzip, 0, {"data", "len", NULL}},
  {"DES", nasl_cipher_des, 0, {"data", "key", NULL}},

#ifdef HAVE_NETSNMP
  {"snmpv1_get", nasl_snmpv1_get, 0, {"community", "oid", "port", "protocol",
                                      NULL }},
  {"snmpv2c_get", nasl_snmpv2c_get, 0, {"community", "oid", "port", "protocol",
                                        NULL }},
  {"snmpv3_get", nasl_snmpv3_get, 0, {"authpass", "authproto", "oid", "port",
                                      "privpass", "privproto", "username",
                                      NULL }},
#endif /* HAVE_NETSNMP */

  {"ssh_connect", nasl_ssh_connect, 0, {"port", "socket", NULL }},
  {"ssh_disconnect", nasl_ssh_disconnect, 1, {NULL }},
  {"ssh_session_id_from_sock", nasl_ssh_session_id_from_sock, 1, {NULL }},
  {"ssh_get_sock", nasl_ssh_get_sock, 1, {NULL }},
  {"ssh_set_login", nasl_ssh_set_login, 1, {"login", NULL }},
  {"ssh_userauth", nasl_ssh_userauth, 1, {"login", "password", NULL }},
  {"ssh_request_exec", nasl_ssh_request_exec,
   1, {"cmd", "stderr", "stdout",NULL }},
  {"ssh_shell_open", nasl_ssh_shell_open, 1, { NULL }},
  {"ssh_shell_read", nasl_ssh_shell_read, 1, { NULL }},
  {"ssh_shell_write", nasl_ssh_shell_write, 1, { "cmd" }},
  {"ssh_shell_close", nasl_ssh_shell_close, 1, { NULL }},
  {"ssh_get_issue_banner", nasl_ssh_get_issue_banner, 1, {NULL }},
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT (0, 6, 0)
  {"ssh_get_server_banner", nasl_ssh_get_server_banner, 1, {NULL }},
#endif
  {"ssh_get_auth_methods", nasl_ssh_get_auth_methods, 1, {NULL }},
  {"ssh_get_host_key", nasl_ssh_get_host_key, 1, {NULL }},

#ifdef HAVE_LIBKSBA
  {"cert_open", nasl_cert_open, 1, {"errorvar", NULL }},
  {"cert_close", nasl_cert_close, 1, {NULL }},
  {"cert_query", nasl_cert_query, 2, {"idx", NULL }},
#endif /*HAVE_LIBKSBA*/

  {"pread", nasl_pread, 0, {"argv", "cd", "cmd", "nice", NULL}},
  {"find_in_path", nasl_find_in_path, 1, {NULL}},
  {"fread", nasl_fread, 1, {NULL}},
  {"fwrite", nasl_fwrite, 0, {"data", "file", NULL}},
  {"unlink", nasl_unlink, 1, {NULL}},
  {"get_tmp_dir", nasl_get_tmp_dir, 0, {NULL}},

  {"get_byte_order", nasl_get_byte_order, 0, { NULL }},

  {"file_stat", nasl_file_stat, 1, {NULL}},
  {"file_open", nasl_file_open, 0, {"mode", "name", NULL}},
  {"file_close", nasl_file_close, 1, {NULL}},
  {"file_read", nasl_file_read, 0, {"fp", "length", NULL}},
  {"file_write", nasl_file_write, 0, {"data", "fp", NULL}},
  {"file_seek", nasl_file_seek, 0, {"fp", "offset", NULL}},

  {"wmi_versioninfo", nasl_wmi_versioninfo, 0, {NULL}},
  {"wmi_connect", nasl_wmi_connect, 4,
   {"ns", "password", "username", NULL}},
  {"wmi_close", nasl_wmi_close, 0, {"wmi_handle", NULL}},
  {"wmi_query", nasl_wmi_query, 0, {"query", "wmi_handle", NULL}},
  {"wmi_connect_rsop", nasl_wmi_connect_rsop, 0,
   {"password", "username", NULL}},
  {"wmi_query_rsop", nasl_wmi_query_rsop, 0, {"query", "wmi_handle", NULL}},
  {"wmi_connect_reg", nasl_wmi_connect_reg, 0,
   {"password", "username", NULL}},
  {"wmi_reg_enum_key", nasl_wmi_reg_enum_key, 0,
   {"hive", "key", "wmi_handle", NULL}},
  {"wmi_reg_enum_value", nasl_wmi_reg_enum_value, 0,
   {"hive", "key", "wmi_handle", NULL}},
  {"wmi_reg_get_sz", nasl_wmi_reg_get_sz, 0,
   {"hive", "key", "key_name", "wmi_handle", NULL}},
  {"wmi_reg_get_bin_val", nasl_wmi_reg_get_bin_val, 0,
   {"hive", "key", "val_name", "wmi_handle", NULL}},
  {"wmi_reg_get_dword_val", nasl_wmi_reg_get_dword_val, 0,
   {"hive", "key", "val_name", "wmi_handle", NULL}},
  {"wmi_reg_get_ex_string_val", nasl_wmi_reg_get_ex_string_val, 0,
   {"hive", "key", "val_name", "wmi_handle", NULL}},
  {"wmi_reg_get_mul_string_val", nasl_wmi_reg_get_mul_string_val, 0,
   {"hive", "key", "val_name", "wmi_handle", NULL}},
  {"wmi_reg_get_qword_val", nasl_wmi_reg_get_qword_val, 0,
   {"hive", "key", "val_name", "wmi_handle", NULL}},
  {"wmi_reg_set_dword_val", nasl_wmi_reg_set_dword_val, 0,
   {"hive", "key", "val", "val_name", "wmi_handle"}},
  {"wmi_reg_set_qword_val", nasl_wmi_reg_set_qword_val, 0,
   {"hive", "key", "val", "val_name", "wmi_handle"}},
  {"wmi_reg_set_ex_string_val", nasl_wmi_reg_set_ex_string_val, 0,
   {"hive", "key", "val", "val_name", "wmi_handle"}},
  {"wmi_reg_set_string_val", nasl_wmi_reg_set_string_val, 0,
   {"hive", "key", "val", "val_name", "wmi_handle"}},
  {"wmi_reg_create_key", nasl_wmi_reg_create_key, 0,
   {"hive", "key", "wmi_handle"}},
  {"wmi_reg_delete_key", nasl_wmi_reg_delete_key, 0,
   {"hive", "key", "wmi_handle"}},

  {"smb_versioninfo", nasl_smb_versioninfo, 0, {NULL}},
  {"smb_connect", nasl_smb_connect, 0,
   {"password", "share", "username", NULL}},
  {"smb_close", nasl_smb_close, 0, {"smb_handle", NULL}},
  {"smb_file_SDDL", nasl_smb_file_SDDL, 0, {"filename", "smb_handle", NULL}},
  {"smb_file_owner_sid", nasl_smb_file_owner_sid, 0,
   {"filename", "smb_handle", NULL}},
  {"smb_file_group_sid", nasl_smb_file_group_sid, 0,
   {"filename", "smb_handle", NULL}},
  {"smb_file_trustee_rights", nasl_smb_file_trustee_rights, 0,
   {"filename", "smb_handle", NULL}},
  {"win_cmd_exec", nasl_win_cmd_exec, 0,
   {"cmd", "password", "username"}},

  {"scan_phase", scan_phase, 0, {NULL}},
  {"network_targets", network_targets, 0, {NULL}},

  {"plugin_run_find_service", plugin_run_find_service, 0, {NULL}},
  {"plugin_run_openvas_tcp_scanner", plugin_run_openvas_tcp_scanner, 0, {NULL}},
  {"plugin_run_synscan", plugin_run_synscan, 0, {NULL}},
  {"plugin_run_nmap", plugin_run_nmap, 0, {NULL}},

  {"isotime_now",      nasl_isotime_now, 0, {NULL}},
  {"isotime_is_valid", nasl_isotime_is_valid, 1, {NULL}},
  {"isotime_scan",     nasl_isotime_scan, 1, {NULL}},
  {"isotime_print",    nasl_isotime_print, 1, {NULL}},
  {"isotime_add",      nasl_isotime_add, 1, {"days", "seconds", "years", NULL}},

  {NULL, NULL, 0, {NULL}}
};

/* String variables */
static struct
{
  const char *name;
  const char *val;
} libsvars[] =
{
  {
  "OPENVAS_VERSION", OPENVASLIB_VERSION},
  {
NULL, NULL},};

/* Integer variables */
static struct
{
  const char *name;
  int val;
} libivars[] =
{
  {
  "TRUE", 1},
  {
  "FALSE", 0},
  {
  "pcap_timeout", 5},
  {
  "IPPROTO_TCP", IPPROTO_TCP},
  {
  "IPPROTO_UDP", IPPROTO_UDP},
  {
  "IPPROTO_ICMP", IPPROTO_ICMP},
  {
  "IPROTO_IP", IPPROTO_IP},
  {
  "IPPROTO_IGMP", IPPROTO_IGMP},
  {
  "ENCAPS_AUTO", OPENVAS_ENCAPS_AUTO},
  {
  "ENCAPS_IP", OPENVAS_ENCAPS_IP},
  {
  "ENCAPS_SSLv23", OPENVAS_ENCAPS_SSLv23},
  {
  "ENCAPS_SSLv2", OPENVAS_ENCAPS_SSLv2},
  {
  "ENCAPS_SSLv3", OPENVAS_ENCAPS_SSLv3},
  {
  "ENCAPS_TLSv1", OPENVAS_ENCAPS_TLSv1},
  {
  "ENCAPS_TLSv11", OPENVAS_ENCAPS_TLSv11},
  {
  "ENCAPS_TLSv12", OPENVAS_ENCAPS_TLSv12},
  {
  "ENCAPS_TLScustom", OPENVAS_ENCAPS_TLScustom},
  {
  "ENCAPS_MAX", OPENVAS_ENCAPS_MAX},
  {
  "TH_FIN", TH_FIN},
  {
  "TH_SYN", TH_SYN},
  {
  "TH_RST", TH_RST},
  {
  "TH_PUSH", TH_PUSH},
  {
  "TH_ACK", TH_ACK},
  {
  "TH_URG", TH_URG},
  {
  "IP_RF", IP_RF},
  {
  "IP_DF", IP_DF},
  {
  "IP_MF", IP_MF},
  {
  "IP_OFFMASK", IP_OFFMASK},
  {
  "ACT_INIT", ACT_INIT},
  {
  "ACT_GATHER_INFO", ACT_GATHER_INFO},
  {
  "ACT_ATTACK", ACT_ATTACK},
  {
  "ACT_MIXED_ATTACK", ACT_MIXED_ATTACK},
  {
  "ACT_DESTRUCTIVE_ATTACK", ACT_DESTRUCTIVE_ATTACK},
  {
  "ACT_DENIAL", ACT_DENIAL},
  {
  "ACT_SCANNER", ACT_SCANNER},
  {
  "ACT_SETTINGS", ACT_SETTINGS},
  {
  "ACT_KILL_HOST", ACT_KILL_HOST},
  {
  "ACT_FLOOD", ACT_FLOOD},
  {
  "ACT_END", ACT_END},
  {
  "MSG_OOB", MSG_OOB},
  {
  "NOERR", NASL_ERR_NOERR},
  {
  "ETIMEDOUT", NASL_ERR_ETIMEDOUT},
  {
  "ECONNRESET", NASL_ERR_ECONNRESET},
  {
  "EUNREACH", NASL_ERR_EUNREACH},
  {
  "EUNKNOWN", NASL_ERR_EUNKNOWN},
  {
  /* Since OpenVAS-8, libssh is mandatory. To maintain compatibility of
     the NVT feed with older versions, this variable needs to be set.
     Once OpenVAS-7 is retired, this setting of the variable can be removed
     and also any occurrences in the NVTs, which should lead to some
     significant NASL code removals. */
  "_HAVE_LIBSSH", 1},
  {
NULL, 0},};

/* See also in exec.c:
 * COMMAND_LINE
 * description
 */

/**
 * @brief Adds "built-in" variable and function definitions to a context.
 *
 * @return Number of definitions done -1.
 */
int
init_nasl_library (lex_ctxt * lexic)
{
  int j, c;
  nasl_func *pf;
  tree_cell tc;
  const char **p, *q;
  unsigned i;
  int lint_mode = 0;

  memset (&tc, 0, sizeof (tc));
  for (i = 0, c = 0; i < sizeof (libfuncs) / sizeof (libfuncs[0]) - 1; i++)
    {
      if ((pf = insert_nasl_func (lexic, libfuncs[i].name, NULL, lint_mode)) == NULL)
        {
          nasl_perror (lexic, "init_nasl_library: could not define fct '%s'\n",
                       libfuncs[i].name);
          continue;
        }
      pf->block = libfuncs[i].c_code;
      pf->flags |= FUNC_FLAG_INTERNAL;
      pf->nb_unnamed_args = libfuncs[i].unnamed;

      for (j = 0, p = libfuncs[i].args, q = NULL; (*p) != NULL; j++)
        {
          if (q != NULL && strcmp (q, *p) > 0)
            nasl_perror (lexic,
                         "init_nasl_library: unsorted args for function %s: %s > %s\n",
                         libfuncs[i].name, q, (*p));
          q = (*p);
          p++;
        }
      pf->nb_named_args = j;
      pf->args_names = (char **) libfuncs[i].args;

      c++;
    }

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
      c++;
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
      c++;
    }

  // Add the "NULL" variable
  if (add_named_var_to_ctxt (lexic, "NULL", NULL) == NULL)
    nasl_perror (lexic, "init_nasl_library: could not define var 'NULL'\n");

  return c;
}


char *
nasl_version ()
{
  static char vers[sizeof (OPENVASLIB_VERSION) + 1];
  strncpy (vers, OPENVASLIB_VERSION, sizeof (vers) - 1);
  vers[sizeof (vers) - 1] = '\0';
  return vers;
}
