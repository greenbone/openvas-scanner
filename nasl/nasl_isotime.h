/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of an API for ISOTIME values.
 *
 * Authors:
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NASL_ISOTIME_H
#define NASL_ISOTIME_H

/**
 * @file nasl_isotime.h
 * @brief Protos and data structures for ISOTIME functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_isotime.c
 */

tree_cell *nasl_isotime_now (lex_ctxt *lexic);
tree_cell *nasl_isotime_is_valid (lex_ctxt *lexic);
tree_cell *nasl_isotime_scan (lex_ctxt *lexic);
tree_cell *nasl_isotime_print (lex_ctxt *lexic);
tree_cell *nasl_isotime_add (lex_ctxt *lexic);

#endif /*NASL_ISOTIME_H*/
