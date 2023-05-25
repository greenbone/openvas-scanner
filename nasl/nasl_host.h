/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_HOST_H
#define NASL_NASL_HOST_H

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

#endif
