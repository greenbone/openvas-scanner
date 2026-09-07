/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file credentials.h
 * @brief Module for handling credentials.
 */

#ifndef MISC_CREDENTIALS_H
#define MISC_CREDENTIALS_H

#include "scanneraux.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h> /* for prefs_get */

typedef struct ssh_credential_type ssh_credential_t;
typedef struct smb_credential_type smb_credential_t;
typedef struct krb5_credential_type krb5_credential_t;
typedef struct snmp_credential_type snmp_credential_t;
typedef struct esxi_credential_type esxi_credential_t;

enum credential_type
{
  SSH,
  SMB,
  KRB5,
  SNMP,
  ESXi,
};

int
process_credentials_json (const char *, struct scan_globals **, char **);

void
destroy_credentials (GSList **);

void
set_host_credentials (GSList *, const char *);

#endif // MISC_CREDENTIALS_H
