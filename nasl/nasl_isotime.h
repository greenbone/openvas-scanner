/* Copyright (C) 2012-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

/**
 * @file nasl_isotime.h
 * @brief Protos and data structures for ISOTIME functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_isotime.c
 */

#ifndef NASL_ISOTIME_H
#define NASL_ISOTIME_H

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

#endif /*NASL_ISOTIME_H*/
