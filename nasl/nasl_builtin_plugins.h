/* openvas-libraries/nasl
 * $Id$
 * Description: Built-in Plugins header file.
 *
 * Authors:
 * Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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
 * @file nasl_builtin_plugins.h
 * @brief Header file for built-in plugins.
 */

#ifndef _NASL_BUILTIN_PLUGINS_H
#define _NASL_BUILTIN_PLUGINS_H

tree_cell * plugin_run_find_service (lex_ctxt *);

tree_cell * plugin_run_openvas_tcp_scanner (lex_ctxt *);

tree_cell * plugin_run_synscan (lex_ctxt *);

tree_cell * plugin_run_nmap (lex_ctxt *);

#endif /* not _NASL_BUILTIN_PLUGINS_H */
