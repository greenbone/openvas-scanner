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

#ifndef NASL_DEBUG_H__
#define NASL_DEBUG_H__

void nasl_perror (lex_ctxt *, char *, ...);
void nasl_trace (lex_ctxt *, char *, ...);
int nasl_trace_enabled (void);

void
nasl_set_filename (const char *);

void
nasl_set_function_filename (const char *);

const char *
nasl_get_filename (const char *);

void
nasl_set_function_name (const char *);

const char *
nasl_get_function_name (void);
#endif
