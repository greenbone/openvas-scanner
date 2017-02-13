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

 /* -------------------------------------------------------------------- *
  * This file contains all the functions related to the handling of the  *
  * sockets within a NASL script - namely, this is the implementation    *
  * of open_(priv_)?sock_(udp|tcp)(), send(), recv(), recv_line() and    *
  * close().                                                             *
  *----------------------------------------------------------------------*/



/*--------------------------------------------------------------------------*/
#ifndef NASL_SOCKET_H
#define NASL_SOCKET_H

tree_cell *nasl_open_sock_tcp (lex_ctxt *);
tree_cell *nasl_open_sock_udp (lex_ctxt *);
/* private func */
tree_cell *nasl_open_sock_tcp_bufsz (lex_ctxt *, int);
tree_cell *nasl_socket_get_error (lex_ctxt *);

tree_cell *nasl_open_priv_sock_tcp (lex_ctxt *);
tree_cell *nasl_open_priv_sock_udp (lex_ctxt *);

tree_cell *nasl_send (lex_ctxt *);
tree_cell *nasl_socket_negotiate_ssl (lex_ctxt *);
tree_cell *nasl_recv (lex_ctxt *);
tree_cell *nasl_recv_line (lex_ctxt *);
tree_cell *nasl_socket_get_cert (lex_ctxt *);
tree_cell *nasl_socket_get_ssl_session_id (lex_ctxt *);
tree_cell *nasl_socket_get_ssl_version (lex_ctxt *);
tree_cell *nasl_socket_get_ssl_compression (lex_ctxt *);
tree_cell *nasl_socket_get_ssl_ciphersuite (lex_ctxt *);

tree_cell *nasl_close_socket (lex_ctxt *);

tree_cell *nasl_join_multicast_group (lex_ctxt *);
tree_cell *nasl_leave_multicast_group (lex_ctxt *);

tree_cell *nasl_get_source_port (lex_ctxt *);

tree_cell *nasl_get_sock_info (lex_ctxt *lexic);

#endif
