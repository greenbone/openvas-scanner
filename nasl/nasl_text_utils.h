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

#ifndef NASL_TEXT_UTILS_H
#define NASL_TEXT_UTILS_H
tree_cell *nasl_string (lex_ctxt *);
tree_cell *nasl_rawstring (lex_ctxt *);
tree_cell *nasl_strlen (lex_ctxt *);
tree_cell *nasl_strcat (lex_ctxt *);
tree_cell *nasl_display (lex_ctxt *);
tree_cell *nasl_hex (lex_ctxt *);
tree_cell *nasl_hexstr (lex_ctxt *);
tree_cell *nasl_ord (lex_ctxt *);
tree_cell *nasl_tolower (lex_ctxt *);
tree_cell *nasl_toupper (lex_ctxt *);
tree_cell *nasl_ereg (lex_ctxt *);
tree_cell *nasl_eregmatch (lex_ctxt *);
tree_cell *nasl_ereg_replace (lex_ctxt *);
tree_cell *nasl_egrep (lex_ctxt *);
tree_cell *nasl_match (lex_ctxt *);
tree_cell *nasl_split (lex_ctxt *);
tree_cell *nasl_chomp (lex_ctxt *);
tree_cell *nasl_substr (lex_ctxt *);
tree_cell *nasl_insstr (lex_ctxt *);
tree_cell *nasl_strstr (lex_ctxt *);
tree_cell *nasl_crap (lex_ctxt *);
tree_cell *nasl_int (lex_ctxt *);
tree_cell *nasl_stridx (lex_ctxt *);
tree_cell *nasl_str_replace (lex_ctxt *);

#endif
