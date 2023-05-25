/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_INIT_H
#define NASL_NASL_INIT_H
#include "nasl_lex_ctxt.h"

#include <glib.h>

void
init_nasl_library (lex_ctxt *);

void
add_nasl_library (GSList **);

#endif
