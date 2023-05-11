/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_PACKET_FORGERY_V6_H
#define NASL_NASL_PACKET_FORGERY_V6_H

tree_cell *
forge_ip_v6_packet (lex_ctxt *);
tree_cell *
set_ip_v6_elements (lex_ctxt *);
tree_cell *
get_ip_v6_element (lex_ctxt *);
tree_cell *
dump_ip_v6_packet (lex_ctxt *);
tree_cell *
insert_ip_v6_options (lex_ctxt *);

tree_cell *
forge_tcp_v6_packet (lex_ctxt *);
tree_cell *
get_tcp_v6_element (lex_ctxt *);
tree_cell *
get_tcp_v6_option (lex_ctxt *);
tree_cell *
set_tcp_v6_elements (lex_ctxt *);
tree_cell *
insert_tcp_v6_options (lex_ctxt *);
tree_cell *
dump_tcp_v6_packet (lex_ctxt *);

tree_cell *
forge_udp_v6_packet (lex_ctxt *);
tree_cell *
set_udp_v6_elements (lex_ctxt *);
tree_cell *
dump_udp_v6_packet (lex_ctxt *);
tree_cell *
get_udp_v6_element (lex_ctxt *);

tree_cell *
forge_icmp_v6_packet (lex_ctxt *);
tree_cell *
get_icmp_v6_element (lex_ctxt *);
tree_cell *
dump_icmp_v6_packet (lex_ctxt *);

tree_cell *
forge_igmp_v6_packet (lex_ctxt *);

tree_cell *
nasl_tcp_v6_ping (lex_ctxt *);
tree_cell *
nasl_send_v6packet (lex_ctxt *);
#endif
