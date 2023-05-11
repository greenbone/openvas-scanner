/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_GLOBAL_CTX_H
#define NASL_NASL_GLOBAL_CTX_H

/* for FILE */
#include "nasl_tree.h"

#include <gvm/util/kb.h>
#include <stdio.h>

typedef struct
{
  int line_nb;
  char *name;
  int always_signed; /**< If set disable signature check during scans and feed
                        upload. */
  int exec_descr; /**< Tell grammar that is a feed upload process or a running a
                     scan process. */
  int index;
  unsigned int include_order;
  tree_cell *tree;
  char *buffer;
  kb_t kb;
} naslctxt;

int
init_nasl_ctx (naslctxt *, const char *);

void
nasl_clean_ctx (naslctxt *);

#endif
