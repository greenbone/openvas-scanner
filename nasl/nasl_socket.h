/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* -------------------------------------------------------------------- *
 * This file contains all the functions related to the handling of the  *
 * sockets within a NASL script - namely, this is the implementation    *
 * of open_(priv_)?sock_(udp|tcp)(), send(), recv(), recv_line() and    *
 * close().                                                             *
 *----------------------------------------------------------------------*/

/*--------------------------------------------------------------------------*/
#ifndef NASL_NASL_SOCKET_H
#define NASL_NASL_SOCKET_H

#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"

tree_cell *
nasl_open_sock_tcp (lex_ctxt *);
tree_cell *
nasl_open_sock_udp (lex_ctxt *);
/* private func */
tree_cell *
nasl_open_sock_tcp_bufsz (lex_ctxt *, int);
tree_cell *
nasl_socket_get_error (lex_ctxt *);

tree_cell *
nasl_open_priv_sock_tcp (lex_ctxt *);
tree_cell *
nasl_open_priv_sock_udp (lex_ctxt *);

tree_cell *
nasl_get_mtu (lex_ctxt *);

tree_cell *
nasl_send (lex_ctxt *);
tree_cell *
nasl_socket_negotiate_ssl (lex_ctxt *);

tree_cell *
nasl_socket_check_ssl_safe_renegotiation (lex_ctxt *);
tree_cell *
nasl_socket_ssl_do_handshake (lex_ctxt *);

tree_cell *
nasl_recv (lex_ctxt *);
tree_cell *
nasl_recv_line (lex_ctxt *);
tree_cell *
nasl_socket_get_cert (lex_ctxt *);
tree_cell *
nasl_socket_get_ssl_session_id (lex_ctxt *);
tree_cell *
nasl_socket_get_ssl_version (lex_ctxt *);
tree_cell *
nasl_socket_get_ssl_ciphersuite (lex_ctxt *);
tree_cell *
nasl_socket_cert_verify (lex_ctxt *);

tree_cell *
nasl_close_socket (lex_ctxt *);

tree_cell *
nasl_join_multicast_group (lex_ctxt *);
tree_cell *
nasl_leave_multicast_group (lex_ctxt *);

tree_cell *
nasl_get_source_port (lex_ctxt *);

tree_cell *
nasl_get_sock_info (lex_ctxt *lexic);

#endif
