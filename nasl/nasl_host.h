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

#ifndef NASL_HOST_H
#define NASL_HOST_H

#include "nasl_lex_ctxt.h" /* for lex_ctxt */
#include "nasl_tree.h"     /* for tree_cell */

tree_cell *
add_hostname (lex_ctxt *);

tree_cell *
get_hostname (lex_ctxt *);

tree_cell *
get_hostnames (lex_ctxt *);

tree_cell *
get_hostname_source (lex_ctxt *);

tree_cell *
resolve_hostname (lex_ctxt *);

tree_cell *
resolve_hostname_to_multiple_ips (lex_ctxt *);

tree_cell *
get_host_ip (lex_ctxt *);

tree_cell *
get_host_open_port (lex_ctxt *);

tree_cell *
get_port_state (lex_ctxt *);

tree_cell *
get_udp_port_state (lex_ctxt *);

tree_cell *
nasl_islocalhost (lex_ctxt *);

tree_cell *
nasl_islocalnet (lex_ctxt *);

tree_cell *
nasl_this_host (lex_ctxt *);

tree_cell *
nasl_this_host_name (lex_ctxt *);

tree_cell *
get_port_transport (lex_ctxt *);

tree_cell *
nasl_same_host (lex_ctxt *);

tree_cell *
nasl_target_is_ipv6 (lex_ctxt *lexic);

tree_cell *
nasl_get_local_mac_address_from_ip (lex_ctxt *);

#endif
