/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_FUNC_H
#define NASL_NASL_FUNC_H

/**
 * Type for a built-in nasl function.
 */
typedef struct st_nasl_func
{
  char *func_name;
  void *block; /* Can be pointer to a C function! */
} nasl_func;

nasl_func *
func_is_internal (const char *);

void
free_func (nasl_func *);

#endif
