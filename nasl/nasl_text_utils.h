/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_TEXT_UTILS_H
#define NASL_NASL_TEXT_UTILS_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_string (lex_ctxt *);

tree_cell *
nasl_rawstring (lex_ctxt *);

tree_cell *
nasl_strlen (lex_ctxt *);

tree_cell *
nasl_strcat (lex_ctxt *);

tree_cell *
nasl_display (lex_ctxt *);

tree_cell *
nasl_hex (lex_ctxt *);

tree_cell *
nasl_hexstr (lex_ctxt *);

tree_cell *
nasl_ord (lex_ctxt *);

tree_cell *
nasl_tolower (lex_ctxt *);

tree_cell *
nasl_toupper (lex_ctxt *);

tree_cell *
nasl_ereg (lex_ctxt *);

tree_cell *
nasl_eregmatch (lex_ctxt *);

tree_cell *
nasl_ereg_replace (lex_ctxt *);

tree_cell *
nasl_egrep (lex_ctxt *);

tree_cell *
nasl_match (lex_ctxt *);

tree_cell *
nasl_split (lex_ctxt *);

tree_cell *
nasl_chomp (lex_ctxt *);

tree_cell *
nasl_substr (lex_ctxt *);

tree_cell *
nasl_insstr (lex_ctxt *);

tree_cell *
nasl_strstr (lex_ctxt *);

tree_cell *
nasl_crap (lex_ctxt *);

tree_cell *
nasl_int (lex_ctxt *);

tree_cell *
nasl_stridx (lex_ctxt *);

tree_cell *
nasl_str_replace (lex_ctxt *);

#endif
