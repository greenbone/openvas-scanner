/* openvas-libraries/nasl
 * $Id$
 * Description: API for X.509 certificates
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

#ifndef NASL_CERT_H
#define NASL_CERT_H

/**
 * @file nasl_cert.h
 * @brief Protos and data structures for CERT functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_cert.c
 */

tree_cell *nasl_cert_open (lex_ctxt *lexic);
tree_cell *nasl_cert_close (lex_ctxt *lexic);
tree_cell *nasl_cert_query (lex_ctxt *lexic);


#endif /*NASL_CERT_H*/
