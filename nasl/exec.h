/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_EXEC_H
#define NASL_EXEC_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_exec (lex_ctxt *, tree_cell *);

long int
cell_cmp (lex_ctxt *, tree_cell *, tree_cell *);

tree_cell *
cell2atom (lex_ctxt *, tree_cell *);

#endif
