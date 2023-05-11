/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_LINT_H
#define NASL_LINT_H

#include "nasl_lex_ctxt.h"

enum nasl_lint_feature_flags
{
  NLFF_NONE = 0,
  NLFF_STRICT_INCLUDES = 1
};

void
nasl_lint_feature_flags (int flags);

tree_cell *
nasl_lint (lex_ctxt *lexic, tree_cell *st);

#endif
