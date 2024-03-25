/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_HTTP2_H
#define NASL_NASL_HTTP2_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_http2_handle (lex_ctxt *);

tree_cell *
nasl_http2_close_handle (lex_ctxt *);

tree_cell *
nasl_http2_get_response_code (lex_ctxt *);

tree_cell *
nasl_http2_set_custom_header (lex_ctxt *);

tree_cell *
nasl_http2_get (lex_ctxt *);

tree_cell *
nasl_http2_head (lex_ctxt *);

tree_cell *
nasl_http2_post (lex_ctxt *);

tree_cell *
nasl_http2_delete (lex_ctxt *);

tree_cell *
nasl_http2_put (lex_ctxt *);

#endif
