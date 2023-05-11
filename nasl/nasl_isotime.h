/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_isotime.h
 * @brief Protos and data structures for ISOTIME functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_isotime.c
 */

#ifndef NASL_NASL_ISOTIME_H
#define NASL_NASL_ISOTIME_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_isotime_now (lex_ctxt *lexic);

tree_cell *
nasl_isotime_is_valid (lex_ctxt *lexic);

tree_cell *
nasl_isotime_scan (lex_ctxt *lexic);

tree_cell *
nasl_isotime_print (lex_ctxt *lexic);

tree_cell *
nasl_isotime_add (lex_ctxt *lexic);

#endif /*NASL_NASL_ISOTIME_H*/
