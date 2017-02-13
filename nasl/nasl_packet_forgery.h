/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
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
 */

#ifndef NASL_PACKET_FORGERY_H


tree_cell *forge_ip_packet (lex_ctxt *);
tree_cell *set_ip_elements (lex_ctxt *);
tree_cell *get_ip_element (lex_ctxt *);
tree_cell *dump_ip_packet (lex_ctxt *);
tree_cell *insert_ip_options (lex_ctxt *);


tree_cell *forge_tcp_packet (lex_ctxt *);
tree_cell *get_tcp_element (lex_ctxt *);
tree_cell *set_tcp_elements (lex_ctxt *);
tree_cell *dump_tcp_packet (lex_ctxt *);


tree_cell *forge_udp_packet (lex_ctxt *);
tree_cell *set_udp_elements (lex_ctxt *);
tree_cell *dump_udp_packet (lex_ctxt *);
tree_cell *get_udp_element (lex_ctxt *);


tree_cell *forge_icmp_packet (lex_ctxt *);
tree_cell *get_icmp_element (lex_ctxt *);


tree_cell *forge_igmp_packet (lex_ctxt *);


tree_cell *nasl_tcp_ping (lex_ctxt *);

tree_cell *nasl_send_packet (lex_ctxt *);
tree_cell *nasl_pcap_next (lex_ctxt *);
tree_cell *nasl_send_capture (lex_ctxt *);
#endif
