/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_snmp.h
 * @brief Headers of an API for SNMP used by NASL scripts.
 */
#ifndef NASL_NASL_SNMP_H
#define NASL_NASL_SNMP_H

#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
tree_cell *
nasl_snmpv1_get (lex_ctxt *);

tree_cell *
nasl_snmpv1_getnext (lex_ctxt *);

tree_cell *
nasl_snmpv2c_get (lex_ctxt *);

tree_cell *
nasl_snmpv2c_getnext (lex_ctxt *);

tree_cell *
nasl_snmpv3_get (lex_ctxt *);

tree_cell *
nasl_snmpv3_getnext (lex_ctxt *);

#endif
