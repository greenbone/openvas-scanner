/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_HTTP_H
#define NASL_NASL_HTTP_H

#include "nasl_lex_ctxt.h"

tree_cell *
http_open_socket (lex_ctxt *);

tree_cell *
http_close_socket (lex_ctxt *);

tree_cell *
http_get (lex_ctxt *);

tree_cell *
http_head (lex_ctxt *);

tree_cell *
http_post (lex_ctxt *);

tree_cell *
http_delete (lex_ctxt *);

tree_cell *
http_put (lex_ctxt *);

tree_cell *
nasl_http_recv_headers (lex_ctxt *);

tree_cell *
cgibin (lex_ctxt *);

tree_cell *
nasl_is_cgi_installed (lex_ctxt *);

tree_cell *
nasl_http_keepalive_send_recv (lex_ctxt *);

tree_cell *
nasl_http_share_exists (lex_ctxt *);

#endif
