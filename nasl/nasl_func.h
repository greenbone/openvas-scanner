/* NASL Attack Scripting Language
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

/**
 * Type for a built-in nasl function.
 */
typedef struct st_nasl_func
{
  char *func_name;
  void *block;                  /* Can be pointer to a C function! */
} nasl_func;

nasl_func *func_is_internal (const char *);

void free_func (nasl_func *);

#endif
