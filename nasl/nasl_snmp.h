/* openvas-libraries/nasl
 * $Id$
 * Description: Headers of an API for SNMP used by NASL scripts.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

#ifdef HAVE_NETSNMP

tree_cell *
nasl_snmpv1_get (lex_ctxt *);

tree_cell *
nasl_snmpv2c_get (lex_ctxt *);

tree_cell *
nasl_snmpv3_get (lex_ctxt *);

#endif /* HAVE_NETSNMP */
