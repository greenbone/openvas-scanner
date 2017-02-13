/* OpenVAS
 *
 * $Id$
 * Description: NASL API implementation for WMI support
 *
 * Authors:
 * Chandrashekhar B <bchandra@secpod.com>
 *
 * Copyright:
 * Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file nasl_wmi.h
 * @brief Protos for NASL WMI API
 *
 * This file contains the protos for \ref nasl_wmi.c
 */

#ifndef _NASL_NASL_WMI_H
#define _NASL_NASL_WMI_H

/* for lex_ctxt */
#include "nasl_lex_ctxt.h"

/* for tree_cell */
#include "nasl_tree.h"

tree_cell *nasl_wmi_versioninfo (lex_ctxt * lexic);
tree_cell *nasl_wmi_connect (lex_ctxt * lexic);
tree_cell *nasl_wmi_close (lex_ctxt * lexic);
tree_cell *nasl_wmi_query (lex_ctxt * lexic);

tree_cell *nasl_wmi_connect_rsop (lex_ctxt * lexic);
tree_cell *nasl_wmi_query_rsop (lex_ctxt * lexic);

tree_cell *nasl_wmi_connect_reg (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_sz (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_enum_value (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_enum_key (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_bin_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_dword_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_ex_string_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_mul_string_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_get_qword_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_set_dword_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_set_qword_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_set_ex_string_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_set_string_val (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_create_key (lex_ctxt * lexic);
tree_cell *nasl_wmi_reg_delete_key (lex_ctxt * lexic);

#endif
