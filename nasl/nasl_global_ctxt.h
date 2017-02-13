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

#ifndef _NASL_CTX_H
#define _NASL_CTX_H

/* for FILE */
#include <stdio.h>
#include "../base/kb.h"

typedef struct
{
  int line_nb;
  int always_authenticated;
  int maxlen;
  FILE *fp;
  tree_cell *tree;
  char *buffer;
  kb_t kb;
} naslctxt;

int init_nasl_ctx (naslctxt *, const char *);
void nasl_clean_ctx (naslctxt *);

#endif
