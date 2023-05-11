/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_wmi.h
 * @brief Protos for NASL WMI API
 *
 * This file contains the protos for \ref nasl_wmi.c
 */

#ifndef NASL_NASL_WMI_H
#define NASL_NASL_WMI_H

/* for lex_ctxt */
#include "nasl_lex_ctxt.h"

/* for tree_cell */
#include "nasl_tree.h"

tree_cell *
nasl_wmi_versioninfo (lex_ctxt *lexic);
tree_cell *
nasl_wmi_connect (lex_ctxt *lexic);
tree_cell *
nasl_wmi_close (lex_ctxt *lexic);
tree_cell *
nasl_wmi_query (lex_ctxt *lexic);

tree_cell *
nasl_wmi_connect_rsop (lex_ctxt *lexic);
tree_cell *
nasl_wmi_query_rsop (lex_ctxt *lexic);

tree_cell *
nasl_wmi_connect_reg (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_sz (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_enum_value (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_enum_key (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_bin_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_dword_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_ex_string_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_mul_string_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_get_qword_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_set_dword_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_set_qword_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_set_ex_string_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_set_string_val (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_create_key (lex_ctxt *lexic);
tree_cell *
nasl_wmi_reg_delete_key (lex_ctxt *lexic);

#endif
