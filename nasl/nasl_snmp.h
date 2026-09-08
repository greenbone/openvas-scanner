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

#include <sys/types.h>

typedef struct snmpv1v2_request *snmpv1v2_request_t;
typedef struct snmpv3_request *snmpv3_request_t;
typedef struct snmp_result *snmp_result_t;

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

int
snmpv1v2c_get (const snmpv1v2_request_t, snmp_result_t);

int
snmpv3_get (const snmpv3_request_t, snmp_result_t);

snmpv3_request_t
new_snmpv3_request (char *, char *, char *, char *, int, int);

snmpv1v2_request_t
new_snmpv1v2_request (char *, char *, u_char);

snmp_result_t
new_snmp_result (void);

void destroy_snmp_result (snmp_result_t);
#endif
