/* Based on work Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _NASL_CTX_H
#define _NASL_CTX_H

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
