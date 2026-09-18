/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file credentials.c
 * @brief Functions to set and get the credentials.
 */

#include "credentials.h"

#include "scanneraux.h"

#include <cjson/cJSON.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <gvm/util/json.h>
#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <libssh/libssh.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

struct ssh_credential_type
{
  int port;
  char *username;
  char *password;
  char *private_key;
  char *private_key_uuid;
  char *privilege_username;
  char *privilege_password;
};

struct smb_credential_type
{
  char *username;
  char *password;
};

struct krb5_credential_type
{
  char *username;
  char *password;
  char *realm;
  char *kdc;
};

struct snmp_credential_type
{
  char *username;
  char *password;
  char *community;
  char *privacy_password;
  char *auth_proto;    // snmp authorization protocol. 0 for md5, 1 for sha1.
  char *privacy_proto; // snmp private protocol. 0 for des, 1 for aes
};

struct esxi_credential_type
{
  char *username;
  char *password;
};

static int
credential_ssh_new (cJSON *service, credential_t **credential)
{
  ssh_credential_t *cred = g_malloc0 (sizeof (ssh_credential_t));
  cJSON *item;

  cred->port = gvm_json_obj_int (service, "port");
  item = cJSON_GetObjectItem (service, "up");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
      cred->privilege_username =
        g_strdup (gvm_json_obj_str (item, "privilege_username"));
      cred->privilege_password =
        g_strdup (gvm_json_obj_str (item, "privilege_password"));
    }
  else
    {
      item = cJSON_GetObjectItem (service, "usk");
      if (item && cJSON_IsObject (item))
        {
          cred->username = g_strdup (gvm_json_obj_str (item, "username"));
          cred->password = g_strdup (gvm_json_obj_str (item, "password"));
          cred->private_key = g_strdup (gvm_json_obj_str (item, "private"));
          cred->privilege_username =
            g_strdup (gvm_json_obj_str (item, "privilege_username"));
          cred->privilege_password =
            g_strdup (gvm_json_obj_str (item, "privilege_password"));
        }
    }
  if (item == NULL)
    {
      g_free (cred);
      return -1;
    }
  (*credential)->type = SSH;
  (*credential)->ssh_credential = cred;
  return 0;
}

static int
credential_smb_new (cJSON *service, credential_t **credential)
{
  smb_credential_t *cred = g_malloc0 (sizeof (smb_credential_t));
  cJSON *item;

  item = cJSON_GetObjectItem (service, "up");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
    }
  if (item == NULL)
    {
      g_free (cred);
      return -1;
    };

  (*credential)->type = SMB;
  (*credential)->smb_credential = cred;
  return 0;
}

static int
credential_esxi_new (cJSON *service, credential_t **credential)
{
  esxi_credential_t *cred = g_malloc0 (sizeof (esxi_credential_t));
  cJSON *item;

  item = cJSON_GetObjectItem (service, "up");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
    }
  if (item == NULL)
    {
      g_free (cred);
      return -1;
    }

  (*credential)->type = ESXi;
  (*credential)->esxi_credential = cred;
  return 0;
}

static int
credential_snmp_new (cJSON *service, credential_t **credential)
{
  snmp_credential_t *cred = g_malloc0 (sizeof (snmp_credential_t));
  cJSON *item;

  item = cJSON_GetObjectItem (service, "snmp");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
      cred->community = g_strdup (gvm_json_obj_str (item, "community"));
      cred->privacy_password =
        g_strdup (gvm_json_obj_str (item, "privacy_password"));
      cred->auth_proto = g_strdup (gvm_json_obj_str (item, "auth_algorithm"));
      cred->privacy_proto =
        g_strdup (gvm_json_obj_str (item, "privacy_algorithm"));
    }
  if (item == NULL)
    {
      g_free (cred);
      return -1;
    }

  (*credential)->type = SNMP;
  (*credential)->snmp_credential = cred;
  return 0;
}

static int
credential_krb5_new (cJSON *service, credential_t **credential)
{
  krb5_credential_t *cred = g_malloc0 (sizeof (krb5_credential_t));
  cJSON *item;

  item = cJSON_GetObjectItem (service, "krb5");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
      cred->realm = g_strdup (gvm_json_obj_str (item, "realm"));
      cred->kdc = g_strdup (gvm_json_obj_str (item, "kdc"));
    }
  if (item == NULL)
    {
      g_free (cred);
      return -1;
    }
  (*credential)->type = KRB5;
  (*credential)->krb5_credential = cred;
  return 0;
}

int
process_credentials_json (const char *json_credentials,
                          struct scan_globals **globals, char **err)
{
  cJSON *parser;
  cJSON *service_obj = NULL;
  int ret = 0;

  parser = cJSON_Parse (json_credentials);
  if (parser == NULL || !cJSON_IsArray (parser))
    {
      *err = g_strdup ("Unable to parse credentials data");
      ret = -1;
      goto res_cleanup;
    }

  cJSON_ArrayForEach (service_obj, parser)
  {
    if (!cJSON_IsObject (service_obj))
      {
        *err = g_strdup ("Unable to parse credential data object");
        ret = -1;
        goto res_cleanup;
      }

    if (service_obj != NULL)
      {
        char *service = gvm_json_obj_str (service_obj, "service");
        credential_t *credential = g_malloc0 (sizeof (credential_t));
        ret = 0;
        if (!g_strcmp0 (service, "ssh"))
          {
            ret = credential_ssh_new (service_obj, &credential);
            if (ret == 0 && credential->ssh_credential->private_key != NULL
                && credential->ssh_credential->private_key[0] != '\0')
              {
                char *file_uuid = gvm_uuid_make ();
                if (store_file (*globals,
                                credential->ssh_credential->private_key,
                                file_uuid))
                  {
                    g_free (file_uuid);
                    g_debug ("%s: Failed to parse file tipe private key.",

                             __func__);
                  }
                else
                  {
                    credential->ssh_credential->private_key_uuid = file_uuid;
                  }
              }
          }
        else if (!g_strcmp0 (service, "smb"))
          {
            ret = credential_smb_new (service_obj, &credential);
          }
        else if (!g_strcmp0 (service, "esxi"))
          {
            ret = credential_esxi_new (service_obj, &credential);
          }
        else if (!g_strcmp0 (service, "snmp"))
          {
            ret = credential_snmp_new (service_obj, &credential);
          }
        else if (!g_strcmp0 (service, "krb5"))
          {
            ret = credential_krb5_new (service_obj, &credential);
          }
        else
          {
            g_free (credential);
            g_warning ("%s: Unknown credential service type %s", __func__,
                       service);
            continue;
          }
        if (ret == 0)
          (*globals)->credentials =
            g_slist_prepend ((*globals)->credentials, credential);
        else
          {
            g_free (credential);
            g_warning (
              "%s: not possible to parse a credential. Missing information",
              __func__);
          }
      }
  }

res_cleanup:
  cJSON_Delete (parser);

  return ret;
}

static void
free_credential (gpointer data)
{
  credential_t *credential = (credential_t *) data;
  if (credential->type == SSH)
    {
      g_free (credential->ssh_credential->username);
      g_free (credential->ssh_credential->password);
      g_free (credential->ssh_credential->private_key);
      g_free (credential->ssh_credential->private_key_uuid);
      g_free (credential->ssh_credential->privilege_username);
      g_free (credential->ssh_credential->privilege_password);
      g_free (credential->ssh_credential);
    }
  else if (credential->type == SMB)
    {
      g_free (credential->smb_credential->username);
      g_free (credential->smb_credential->password);
      g_free (credential->smb_credential);
    }
  else if (credential->type == ESXi)
    {
      g_free (credential->esxi_credential->username);
      g_free (credential->esxi_credential->password);
      g_free (credential->esxi_credential);
    }
  else if (credential->type == KRB5)
    {
      g_free (credential->krb5_credential->username);
      g_free (credential->krb5_credential->password);
      g_free (credential->krb5_credential->realm);
      g_free (credential->krb5_credential->kdc);
      g_free (credential->krb5_credential);
    }
  else if (credential->type == SNMP)
    {
      g_free (credential->snmp_credential->username);
      g_free (credential->snmp_credential->password);
      g_free (credential->snmp_credential->community);
      g_free (credential->snmp_credential->privacy_password);
      g_free (credential->snmp_credential);
    }
}

void
destroy_credentials (GSList **credentials)
{
  g_slist_free_full (*credentials, (GDestroyNotify) free_credential);
}

credential_type_t
get_credential_type (credential_t *credential)
{
  return credential->type;
}

int
get_ssh_credential_port (credential_t *credential)
{
  return credential->ssh_credential->port;
}

char *
get_ssh_credential_username (credential_t *credential)
{
  return credential->ssh_credential->username;
}

char *
get_ssh_credential_password (credential_t *credential)
{
  return credential->ssh_credential->password;
}

char *
get_ssh_credential_private_key (credential_t *credential)
{
  return credential->ssh_credential->private_key;
}

char *
get_ssh_credential_private_key_uuid (credential_t *credential)
{
  return credential->ssh_credential->private_key_uuid;
}

char *
get_ssh_credential_privilege_username (credential_t *credential)
{
  return credential->ssh_credential->privilege_username;
}

char *
get_ssh_credential_privilege_password (credential_t *credential)
{
  return credential->ssh_credential->privilege_password;
}

char *
get_smb_credential_username (credential_t *credential)
{
  return credential->smb_credential->username;
}

char *
get_smb_credential_password (credential_t *credential)
{
  return credential->smb_credential->password;
}

char *
get_krb5_credential_username (credential_t *credential)
{
  return credential->krb5_credential->username;
}
char *
get_krb5_credential_password (credential_t *credential)
{
  return credential->krb5_credential->password;
}

char *
get_krb5_credential_realm (credential_t *credential)
{
  return credential->krb5_credential->realm;
}

char *
get_krb5_credential_kdc (credential_t *credential)
{
  return credential->krb5_credential->kdc;
}

char *
get_snmp_credential_username (credential_t *credential)
{
  return credential->snmp_credential->username;
}

char *
get_snmp_credential_password (credential_t *credential)
{
  return credential->snmp_credential->password;
}

char *
get_snmp_credential_community (credential_t *credential)
{
  return credential->snmp_credential->community;
}
char *
get_snmp_credential_privacy_password (credential_t *credential)
{
  return credential->snmp_credential->privacy_password;
}

char *
get_snmp_credential_auth_proto (credential_t *credential)
{
  return credential->snmp_credential->auth_proto;
}

char *
get_snmp_credential_privacy_proto (credential_t *credential)
{
  return credential->snmp_credential->privacy_proto;
}

char *
get_esxi_credential_username (credential_t *credential)
{
  return credential->esxi_credential->username;
}

char *
get_esxi_credential_password (credential_t *credential)
{
  return credential->esxi_credential->password;
}
