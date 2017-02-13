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

#ifndef NASL_FUNC_H_INCLUDED
#define NASL_FUNC_H_INCLUDED

#define FUNC_NAME_HASH 17

#define FUNC_FLAG_COMPAT (1 << 0)       /* Old interface */
#define FUNC_FLAG_INTERNAL (1 << 1)     /* Internal C function */

/**
 * Type for a built-in nasl function.
 */
typedef struct st_nasl_func
{
  char *func_name;
  int flags;
  int nb_unnamed_args, nb_named_args;
  char **args_names;
  void *block;                  /* Can be pointer to a C function! */

  struct st_nasl_func *next_func;       /* next function with same name hash */
} nasl_func;

void free_func_chain (nasl_func *);

#endif
