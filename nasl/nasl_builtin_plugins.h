/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_builtin_plugins.h
 * @brief Header file for built-in plugins.
 */

#ifndef NASL_NASL_BUILTIN_PLUGINS_H
#define NASL_NASL_BUILTIN_PLUGINS_H
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
tree_cell *
plugin_run_find_service (lex_ctxt *);

tree_cell *
plugin_run_openvas_tcp_scanner (lex_ctxt *);

tree_cell *
plugin_run_synscan (lex_ctxt *);

#endif /* not NASL_NASL_BUILTIN_PLUGINS_H */
