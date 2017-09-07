/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef NASL_SCANNER_GLUE_H
#define NASL_SCANNER_GLUE_H
tree_cell *script_timeout (lex_ctxt *);
tree_cell *script_id (lex_ctxt *);
tree_cell *script_oid (lex_ctxt *);
tree_cell *script_cve_id (lex_ctxt *);
tree_cell *script_bugtraq_id (lex_ctxt *);
tree_cell *script_xref (lex_ctxt *);
tree_cell *script_tag (lex_ctxt *);
tree_cell *script_name (lex_ctxt *);
tree_cell *script_version (lex_ctxt *);
tree_cell *script_copyright (lex_ctxt *);
tree_cell *script_summary (lex_ctxt *);
tree_cell *script_category (lex_ctxt *);
tree_cell *script_family (lex_ctxt *);
tree_cell *script_dependencies (lex_ctxt *);
tree_cell *script_require_keys (lex_ctxt *);
tree_cell *script_mandatory_keys (lex_ctxt *);
tree_cell *script_exclude_keys (lex_ctxt *);
tree_cell *script_require_ports (lex_ctxt *);
tree_cell *script_require_udp_ports (lex_ctxt *);
tree_cell *nasl_get_preference (lex_ctxt *);
tree_cell *script_add_preference (lex_ctxt *);
tree_cell *script_get_preference (lex_ctxt *);
tree_cell *script_get_preference_file_content (lex_ctxt *);
tree_cell *script_get_preference_file_location (lex_ctxt *);
tree_cell *safe_checks (lex_ctxt *);
tree_cell *scan_phase (lex_ctxt *);
tree_cell *network_targets (lex_ctxt *);
tree_cell *get_script_oid (lex_ctxt *);
tree_cell *get_kb_item (lex_ctxt *);
tree_cell *get_kb_list (lex_ctxt *);
tree_cell *set_kb_item (lex_ctxt *);
tree_cell *replace_kb_item (lex_ctxt *);
tree_cell *security_message (lex_ctxt *);
tree_cell *log_message (lex_ctxt *);
tree_cell *error_message (lex_ctxt *);
tree_cell *nasl_scanner_get_port (lex_ctxt *);
tree_cell *nasl_scanner_add_port (lex_ctxt *);
tree_cell *nasl_scanner_status (lex_ctxt *);
tree_cell *nasl_vendor_version (lex_ctxt *);

#endif
