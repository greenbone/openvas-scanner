/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_DEBUG_H
#define NASL_NASL_DEBUG_H

#include "nasl_lex_ctxt.h"

void
nasl_perror (lex_ctxt *, char *, ...);

void
nasl_trace (lex_ctxt *, char *, ...);

int
nasl_trace_enabled (void);

const char *
nasl_get_plugin_filename (void);

void
nasl_set_plugin_filename (const char *);

void
nasl_set_filename (const char *);

void
nasl_set_function_filename (const char *);

const char *
nasl_get_filename (const char *);

void
nasl_set_function_name (const char *);

int
nasl_get_include_order (const char *);

const char *
nasl_get_function_name (void);
#endif
