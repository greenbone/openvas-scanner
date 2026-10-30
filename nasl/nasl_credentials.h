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
#include <gvm/util/kb.h>

struct scan_globals;

/* Select and publish one type credential in the per-host scanner process per
 * service. */
void
select_host_ssh_credential (struct scan_globals *, kb_t, const char *);

void
select_host_smb_credential (struct scan_globals *, kb_t, const char *);

void
select_host_snmp_credential (struct scan_globals *, kb_t, const char *);

void
select_host_krb5_credential (struct scan_globals *, kb_t, const char *);

tree_cell *
nasl_init_host_esxi_credential (lex_ctxt *);

#endif // NASL_CREDENTIALS_H
