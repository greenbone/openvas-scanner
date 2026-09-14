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

typedef enum credential_type credential_type_t;

struct credential
{
  credential_type_t type;
  union
  {
    ssh_credential_t *ssh_credential;
    smb_credential_t *smb_credential;
    esxi_credential_t *esxi_credential;
    snmp_credential_t *snmp_credential;
    krb5_credential_t *krb5_credential;
  };
};
typedef struct credential credential_t;

int
process_credentials_json (const char *, struct scan_globals **, char **);

void
destroy_credentials (GSList **);

credential_type_t
get_credential_type (credential_t *);
int
get_ssh_credential_port (credential_t *);
char *
get_ssh_credential_username (credential_t *);
char *
get_ssh_credential_password (credential_t *);
char *
get_ssh_credential_private_key (credential_t *);
char *
get_ssh_credential_private_key_uuid (credential_t *);
char *
get_ssh_credential_privilege_username (credential_t *);
char *
get_ssh_credential_privilege_password (credential_t *);

char *
get_smb_credential_username (credential_t *);
char *
get_smb_credential_password (credential_t *);

char *
get_krb5_credential_username (credential_t *);
char *
get_krb5_credential_password (credential_t *);
char *
get_krb5_credential_realm (credential_t *);
char *
get_krb5_credential_kdc (credential_t *);

char *
get_snmp_credential_username (credential_t *);
char *
get_snmp_credential_password (credential_t *);
char *
get_snmp_credential_community (credential_t *);
char *
get_snmp_credential_privacy_password (credential_t *);
char *
get_snmp_credential_auth_proto (credential_t *);
char *
get_snmp_credential_privacy_proto (credential_t *);

char *
get_esxi_credential_username (credential_t *);
char *
get_esxi_credential_password (credential_t *);

#endif // MISC_CREDENTIALS_H
