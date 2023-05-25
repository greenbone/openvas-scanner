/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_CMD_EXEC_H
#define NASL_NASL_CMD_EXEC_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_pread (lex_ctxt *);

tree_cell *
nasl_find_in_path (lex_ctxt *);

tree_cell *
nasl_fread (lex_ctxt *);

tree_cell *
nasl_fwrite (lex_ctxt *);

tree_cell *
nasl_unlink (lex_ctxt *);

tree_cell *
nasl_get_tmp_dir (lex_ctxt *);

tree_cell *
nasl_file_stat (lex_ctxt *);

tree_cell *
nasl_file_open (lex_ctxt *);

tree_cell *
nasl_file_close (lex_ctxt *);

tree_cell *
nasl_file_read (lex_ctxt *);

tree_cell *
nasl_file_write (lex_ctxt *);

tree_cell *
nasl_file_seek (lex_ctxt *);

#endif
