/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_SCANNER_GLUE_H
#define NASL_NASL_SCANNER_GLUE_H

#include "nasl_lex_ctxt.h"

tree_cell *
script_timeout (lex_ctxt *);

tree_cell *
script_oid (lex_ctxt *);

tree_cell *
script_cve_id (lex_ctxt *);

tree_cell *
script_xref (lex_ctxt *);

tree_cell *
script_tag (lex_ctxt *);

tree_cell *
script_name (lex_ctxt *);

tree_cell *
script_version (lex_ctxt *);

tree_cell *
script_copyright (lex_ctxt *);

tree_cell *
script_category (lex_ctxt *);

tree_cell *
script_family (lex_ctxt *);

tree_cell *
script_dependencies (lex_ctxt *);

tree_cell *
script_require_keys (lex_ctxt *);

tree_cell *
script_mandatory_keys (lex_ctxt *);

tree_cell *
script_exclude_keys (lex_ctxt *);

tree_cell *
script_require_ports (lex_ctxt *);

tree_cell *
script_require_udp_ports (lex_ctxt *);

tree_cell *
nasl_get_preference (lex_ctxt *);

tree_cell *
script_add_preference (lex_ctxt *);

tree_cell *
script_get_preference (lex_ctxt *);

tree_cell *
script_get_preference_file_content (lex_ctxt *);

tree_cell *
script_get_preference_file_location (lex_ctxt *);

tree_cell *
safe_checks (lex_ctxt *);

tree_cell *
get_script_oid (lex_ctxt *);

tree_cell *
get_host_kb_index (lex_ctxt *);

tree_cell *
get_kb_item (lex_ctxt *);

tree_cell *
get_kb_list (lex_ctxt *);

tree_cell *
set_kb_item (lex_ctxt *);

tree_cell *
replace_kb_item (lex_ctxt *);

tree_cell *
security_message (lex_ctxt *);

tree_cell *
log_message (lex_ctxt *);

tree_cell *
error_message (lex_ctxt *);

tree_cell *
nasl_scanner_get_port (lex_ctxt *);

tree_cell *
nasl_scanner_add_port (lex_ctxt *);

tree_cell *
nasl_scanner_status (lex_ctxt *);

tree_cell *
nasl_vendor_version (lex_ctxt *);

tree_cell *
nasl_update_table_driven_lsc_data (lex_ctxt *);

#endif
