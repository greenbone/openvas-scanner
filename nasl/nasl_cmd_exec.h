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

#ifndef NASL_UNSAFE_H
#define NASL_UNSAFE_H

tree_cell *nasl_pread (lex_ctxt *);
tree_cell *nasl_find_in_path (lex_ctxt *);

tree_cell *nasl_fread (lex_ctxt *);
tree_cell *nasl_fwrite (lex_ctxt *);
tree_cell *nasl_unlink (lex_ctxt *);
tree_cell *nasl_get_tmp_dir (lex_ctxt *);
tree_cell *nasl_file_stat (lex_ctxt *);
tree_cell *nasl_file_open (lex_ctxt *);
tree_cell *nasl_file_close (lex_ctxt *);
tree_cell *nasl_file_read (lex_ctxt *);
tree_cell *nasl_file_write (lex_ctxt *);
tree_cell *nasl_file_seek (lex_ctxt *);

#endif
