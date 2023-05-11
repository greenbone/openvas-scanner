/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_cert.h
 * @brief Protos and data structures for CERT functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_cert.c
 */

#ifndef NASL_NASL_CERT_H
#define NASL_NASL_CERT_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_cert_open (lex_ctxt *lexic);

tree_cell *
nasl_cert_close (lex_ctxt *lexic);

tree_cell *
nasl_cert_query (lex_ctxt *lexic);

#endif /*NASL_NASL_CERT_H*/
