/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_PACKET_FORGERY_H
#define NASL_NASL_PACKET_FORGERY_H

#include "nasl_lex_ctxt.h"

tree_cell *
forge_ip_packet (lex_ctxt *);
tree_cell *
set_ip_elements (lex_ctxt *);
tree_cell *
get_ip_element (lex_ctxt *);
tree_cell *
dump_ip_packet (lex_ctxt *);
tree_cell *
insert_ip_options (lex_ctxt *);

tree_cell *
forge_tcp_packet (lex_ctxt *);
tree_cell *
get_tcp_element (lex_ctxt *);
tree_cell *
get_tcp_option (lex_ctxt *);
tree_cell *
set_tcp_elements (lex_ctxt *);
tree_cell *
insert_tcp_options (lex_ctxt *);
tree_cell *
dump_tcp_packet (lex_ctxt *);

tree_cell *
forge_udp_packet (lex_ctxt *);
tree_cell *
set_udp_elements (lex_ctxt *);
tree_cell *
dump_udp_packet (lex_ctxt *);
tree_cell *
get_udp_element (lex_ctxt *);

tree_cell *
forge_icmp_packet (lex_ctxt *);
tree_cell *
get_icmp_element (lex_ctxt *);
tree_cell *
dump_icmp_packet (lex_ctxt *);

tree_cell *
forge_igmp_packet (lex_ctxt *);

tree_cell *
nasl_tcp_ping (lex_ctxt *);

tree_cell *
nasl_send_packet (lex_ctxt *);
tree_cell *
nasl_pcap_next (lex_ctxt *);
tree_cell *
nasl_send_capture (lex_ctxt *);
#endif
