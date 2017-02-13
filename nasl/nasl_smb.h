/* OpenVAS
 *
 * $Id$
 * Description: NASL API implementation for SMB support
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
 * @file nasl_smb.h
 * @brief Protos for NASL SMB API
 *
 * This file contains the protos for \ref nasl_smb.c
 */

#ifndef _NASL_NASL_SMB_H
#define _NASL_NASL_SMB_H

/* for lex_ctxt */
#include "nasl_lex_ctxt.h"

/* for tree_cell */
#include "nasl_tree.h"

tree_cell *nasl_smb_versioninfo (lex_ctxt * lexic);
tree_cell *nasl_smb_connect (lex_ctxt * lexic);
tree_cell *nasl_smb_close (lex_ctxt * lexic);
tree_cell *nasl_smb_file_SDDL (lex_ctxt * lexic);
tree_cell *nasl_smb_file_owner_sid (lex_ctxt * lexic);
tree_cell *nasl_smb_file_group_sid (lex_ctxt * lexic);
tree_cell *nasl_smb_file_trustee_rights (lex_ctxt * lexic);
tree_cell *nasl_win_cmd_exec (lex_ctxt * lexic);

#endif
