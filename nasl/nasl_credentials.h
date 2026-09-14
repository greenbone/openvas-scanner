/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file credentials.h
 * @brief Module for handling credentials.
 */

#ifndef NASL_CREDENTIALS_H
#define NASL_CREDENTIALS_H

#include "nasl_lex_ctxt.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h> /* for prefs_get */

tree_cell *
nasl_init_host_ssh_credential (lex_ctxt *);

tree_cell *
nasl_init_host_smb_credential (lex_ctxt *);

tree_cell *
nasl_init_host_krb5_credential (lex_ctxt *);

tree_cell *
nasl_init_host_snmp_credential (lex_ctxt *);

tree_cell *
nasl_init_host_esxi_credential (lex_ctxt *);

#endif // NASL_CREDENTIALS_H
