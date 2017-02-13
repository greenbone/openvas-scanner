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

#ifndef NASL_MISC_FUNCS_H
#define NASL_MISC_FUNCS_H

tree_cell *nasl_rand (lex_ctxt *);
tree_cell *nasl_usleep (lex_ctxt *);
tree_cell *nasl_sleep (lex_ctxt *);
tree_cell *nasl_ftp_log_in (lex_ctxt *);
tree_cell *nasl_ftp_get_pasv_address (lex_ctxt *);
tree_cell *nasl_telnet_init (lex_ctxt *);
tree_cell *nasl_start_denial (lex_ctxt *);
tree_cell *nasl_end_denial (lex_ctxt *);
tree_cell *nasl_dump_ctxt (lex_ctxt *);
tree_cell *nasl_do_exit (lex_ctxt *);
tree_cell *nasl_isnull (lex_ctxt *);
tree_cell *nasl_make_list (lex_ctxt *);
tree_cell *nasl_make_array (lex_ctxt *);
tree_cell *nasl_keys (lex_ctxt *);
tree_cell *nasl_max_index (lex_ctxt *);
tree_cell *nasl_typeof (lex_ctxt *);
tree_cell *nasl_defined_func (lex_ctxt *);
tree_cell *nasl_func_named_args (lex_ctxt *);
tree_cell *nasl_func_unnamed_args (lex_ctxt *);
tree_cell *nasl_func_has_arg (lex_ctxt *);
tree_cell *nasl_sort_array (lex_ctxt *);
tree_cell *nasl_unixtime (lex_ctxt *);
tree_cell *nasl_gettimeofday (lex_ctxt *);
tree_cell *nasl_localtime (lex_ctxt *);
tree_cell *nasl_mktime (lex_ctxt *);
tree_cell *nasl_open_sock_kdc (lex_ctxt *);
tree_cell *nasl_dec2str (lex_ctxt *);
tree_cell *nasl_get_byte_order (lex_ctxt *);
tree_cell *nasl_gunzip (lex_ctxt *);
tree_cell *nasl_gzip (lex_ctxt *);

#endif
