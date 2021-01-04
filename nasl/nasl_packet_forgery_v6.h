/* Based on work Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Modified for IPv6 packet forgery - 04/02/2010
 * Preeti Subramanian <spreeti@secpod.com>
 * Srinivas NL <nl.srinivas@gmail.com>
 */

#ifndef NASL_PACKET_FORGERY_H

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
