/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file credentials.c
 * @brief Functions to set and get the credentials.
 */

#include "credentials.h"

#include "base/hosts.h"
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

#define OID_SMB_AUTH_USER "1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:"
#define OID_SMB_AUTH_PASS "1.3.6.1.4.1.25623.1.0.90023:2:password:SMB password:"
#define OID_SMB_AUTH_DOMAIN \
  "1.3.6.1.4.1.25623.1.0.90023:3:entry:SMB domain (optional):"

#define OID_SSH_AUTH_PASS \
  "1.3.6.1.4.1.25623.1.0.103591:3:password:SSH password (unsafe!):"
#define OID_SSH_AUTH_USER "1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:"
#define OID_SSH_AUTH_PRIV_USER \
  "1.3.6.1.4.1.25623.1.0.103591:7:entry:SSH privilege login name:"
#define OID_SSH_AUTH_PRIV_PASS \
  "1.3.6.1.4.1.25623.1.0.103591:8:password:SSH privilege password:"
#define OID_SSH_AUTH_PRIV_KEY \
  "1.3.6.1.4.1.25623.1.0.103591:4:file:SSH private key:"
#define OID_SSH_AUTH_PASSPHRASE \
  "1.3.6.1.4.1.25623.1.0.103591:2:password:SSH key passphrase:"

#define OID_KRB5_AUTH_USER "1.3.6.1.4.1.25623.1.0.102114:1:entry:KRB5 login:"
#define OID_KRB5_AUTH_PASS \
  "1.3.6.1.4.1.25623.1.0.102114:2:password:KRB5 password:"
#define OID_KRB5_AUTH_REALM "1.3.6.1.4.1.25623.1.0.102114:3:entry:KRB5 realm:"
#define OID_KRB5_AUTH_KDC "1.3.6.1.4.1.25623.1.0.102114:4:entry:KRB5 kdc:"

#define OID_ESXI_AUTH_USER \
  "1.3.6.1.4.1.25623.1.0.105058:1:entry:ESXi login name:"
#define OID_ESXI_AUTH_PASS \
  "1.3.6.1.4.1.25623.1.0.105058:2:password:ESXi login password:"

#define OID_SNMP_AUTH_USER \
  "1.3.6.1.4.1.25623.1.0.105076:2:entry:SNMPv3 Username:"
#define OID_SNMP_AUTH_PASS \
  "1.3.6.1.4.1.25623.1.0.105076:3:password:SNMPv3 Password:"
#define OID_SNMP_AUTH_COMMUNITY \
  "1.3.6.1.4.1.25623.1.0.105076:1:password:SNMP Community:"
#define OID_SNMP_AUTH_PRIV_PASS \
  "1.3.6.1.4.1.25623.1.0.105076:5:password:SNMPv3 Privacy Password:"
#define OID_SNMP_AUTH_AUTH_ALGO \
  "1.3.6.1.4.1.25623.1.0.105076:4:radio:SNMPv3 Authentication Algorithm:"
#define OID_SNMP_AUTH_PRIV_ALGO \
  "1.3.6.1.4.1.25623.1.0.105076:6:radio:SNMPv3 Privacy Algorithm:"

int ssh_credential_count = 0;
int smb_credential_count = 0;
int snmp_credential_count = 0;
int krb5_credential_count = 0;
int esxi_credential_count = 0;

struct ssh_credential_type
{
  int port;
  char *username;
  char *password;
  char *private_key;
  char *private_key_uuid;
  char *privilege_username;
  char *privilege_password;
  gvm_hosts_t *host_list;
};

struct smb_credential_type
{
  char *username;
  char *password;
  gvm_hosts_t *host_list;
};

struct krb5_credential_type
{
  char *username;
  char *password;
  char *realm;
  char *kdc;
  gvm_hosts_t *host_list;
};

struct snmp_credential_type
{
  char *username;
  char *password;
  char *community;
  char *privacy_password;
  char *auth_proto;    // snmp authorization protocol. 0 for md5, 1 for sha1.
  char *privacy_proto; // snmp private protocol. 0 for des, 1 for aes
  gvm_hosts_t *host_list;
};

struct esxi_credential_type
{
  char *username;
  char *password;
  gvm_hosts_t *host_list;
};

static int
get_ssh_credential_port (credential_t *credential)
{
  return credential->ssh_credential->port;
}

static char *
get_ssh_credential_username (credential_t *credential)
{
  return credential->ssh_credential->username;
}

static char *
get_ssh_credential_password (credential_t *credential)
{
  return credential->ssh_credential->password;
}

static char *
get_ssh_credential_private_key (credential_t *credential)
{
  return credential->ssh_credential->private_key;
}

static char *
get_ssh_credential_private_key_uuid (credential_t *credential)
{
  return credential->ssh_credential->private_key_uuid;
}

static char *
get_ssh_credential_privilege_username (credential_t *credential)
{
  return credential->ssh_credential->privilege_username;
}

static char *
get_ssh_credential_privilege_password (credential_t *credential)
{
  return credential->ssh_credential->privilege_password;
}

static char *
get_smb_credential_username (credential_t *credential)
{
  return credential->smb_credential->username;
}

static char *
get_smb_credential_password (credential_t *credential)
{
  return credential->smb_credential->password;
}

static char *
get_krb5_credential_username (credential_t *credential)
{
  return credential->krb5_credential->username;
}
static char *
get_krb5_credential_password (credential_t *credential)
{
  return credential->krb5_credential->password;
}

static char *
get_krb5_credential_realm (credential_t *credential)
{
  return credential->krb5_credential->realm;
}

static char *
get_krb5_credential_kdc (credential_t *credential)
{
  return credential->krb5_credential->kdc;
}

static char *
get_snmp_credential_username (credential_t *credential)
{
  return credential->snmp_credential->username;
}

static char *
get_snmp_credential_password (credential_t *credential)
{
  return credential->snmp_credential->password;
}

static char *
get_snmp_credential_community (credential_t *credential)
{
  return credential->snmp_credential->community;
}

static char *
get_snmp_credential_privacy_password (credential_t *credential)
{
  return credential->snmp_credential->privacy_password;
}

static char *
get_snmp_credential_auth_proto (credential_t *credential)
{
  return credential->snmp_credential->auth_proto;
}

static char *
get_snmp_credential_privacy_proto (credential_t *credential)
{
  return credential->snmp_credential->privacy_proto;
}

static char *
get_esxi_credential_username (credential_t *credential)
{
  return credential->esxi_credential->username;
}

static char *
get_esxi_credential_password (credential_t *credential)
{
  return credential->esxi_credential->password;
}

static gvm_hosts_t *
create_host_list (cJSON *hosts)
{
  gvm_hosts_t *host_list = NULL;

  if (hosts && cJSON_IsArray (hosts))
    {
      GString *hosts_s = NULL;
      for (int i = 0; i < cJSON_GetArraySize (hosts); i++)
        {
          cJSON *host_item = cJSON_GetArrayItem (hosts, i);
          char *host_value = cJSON_GetStringValue (host_item);
          if (host_value == NULL || host_value[0] == '\0')
            continue;

          if (hosts_s == NULL)
            hosts_s = g_string_new (host_value);
          else
            {
              g_string_append (hosts_s, ",");
              g_string_append (hosts_s, host_value);
            }
        }
      if (hosts_s && hosts_s->len > 0)
        host_list = gvm_hosts_new (hosts_s->str);
      g_string_free (hosts_s, TRUE);
    }
  return host_list;
}

static int
credential_ssh_new (cJSON *service, credential_t **credential)
{
  ssh_credential_t *cred = g_malloc0 (sizeof (ssh_credential_t));
  cJSON *item;
  gvm_hosts_t *host_list = NULL;

  item = cJSON_GetObjectItem (service, "hosts");
  if (item)
    {
      host_list = create_host_list (item);
      if (host_list)
        cred->host_list = host_list;
    }

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
      gvm_hosts_free (host_list);
      g_free (cred);
      return -1;
    }
  (*credential)->type = SSH;
  (*credential)->ssh_credential = cred;
  ssh_credential_count++;

  return 0;
}

static int
credential_smb_new (cJSON *service, credential_t **credential)
{
  smb_credential_t *cred = g_malloc0 (sizeof (smb_credential_t));
  cJSON *item;
  gvm_hosts_t *host_list = NULL;

  item = cJSON_GetObjectItem (service, "hosts");
  if (item)
    {
      host_list = create_host_list (item);
      if (host_list)
        cred->host_list = host_list;
    }
  item = cJSON_GetObjectItem (service, "up");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
    }
  if (item == NULL)
    {
      gvm_hosts_free (host_list);
      g_free (cred);
      return -1;
    };

  (*credential)->type = SMB;
  (*credential)->smb_credential = cred;
  smb_credential_count++;

  return 0;
}

static int
credential_esxi_new (cJSON *service, credential_t **credential)
{
  esxi_credential_t *cred = g_malloc0 (sizeof (esxi_credential_t));
  cJSON *item;
  gvm_hosts_t *host_list = NULL;

  item = cJSON_GetObjectItem (service, "hosts");
  if (item)
    {
      host_list = create_host_list (item);
      if (host_list)
        cred->host_list = host_list;
    }

  item = cJSON_GetObjectItem (service, "up");
  if (item && cJSON_IsObject (item))
    {
      cred->username = g_strdup (gvm_json_obj_str (item, "username"));
      cred->password = g_strdup (gvm_json_obj_str (item, "password"));
    }
  if (item == NULL)
    {
      gvm_hosts_free (host_list);
      g_free (cred);
      return -1;
    }

  (*credential)->type = ESXi;
  (*credential)->esxi_credential = cred;
  esxi_credential_count++;

  return 0;
}

static int
credential_snmp_new (cJSON *service, credential_t **credential)
{
  snmp_credential_t *cred = g_malloc0 (sizeof (snmp_credential_t));
  cJSON *item;
  gvm_hosts_t *host_list = NULL;

  item = cJSON_GetObjectItem (service, "hosts");
  if (item)
    {
      host_list = create_host_list (item);
      if (host_list)
        cred->host_list = host_list;
    }
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
      gvm_hosts_free (host_list);
      g_free (cred);
      return -1;
    }

  (*credential)->type = SNMP;
  (*credential)->snmp_credential = cred;
  snmp_credential_count++;
  return 0;
}

static int
credential_krb5_new (cJSON *service, credential_t **credential)
{
  krb5_credential_t *cred = g_malloc0 (sizeof (krb5_credential_t));
  cJSON *item;
  gvm_hosts_t *host_list = NULL;

  item = cJSON_GetObjectItem (service, "hosts");
  if (item)
    {
      host_list = create_host_list (item);
      if (host_list)
        cred->host_list = host_list;
    }

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
      gvm_hosts_free (host_list);
      g_free (cred);
      return -1;
    }
  (*credential)->type = KRB5;
  (*credential)->krb5_credential = cred;
  krb5_credential_count++;

  return 0;
}

static void
reset_credential_counters (void)
{
  ssh_credential_count = 0;
  smb_credential_count = 0;
  snmp_credential_count = 0;
  krb5_credential_count = 0;
  esxi_credential_count = 0;
}

static int
get_ssh_credential_count (void)
{
  return ssh_credential_count;
}

static int
get_smb_credential_count (void)
{
  return smb_credential_count;
}

static int
get_snmp_credential_count (void)
{
  return snmp_credential_count;
}

static int
get_krb5_credential_count (void)
{
  return krb5_credential_count;
}

static int
get_esxi_credential_count (void)
{
  return esxi_credential_count;
}

int
process_credentials_json (const char *json_credentials,
                          struct scan_globals **globals, char **err)
{
  cJSON *parser;
  cJSON *service_obj = NULL;
  int ret = 0;

  reset_credential_counters ();

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
            g_slist_append ((*globals)->credentials, credential);
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
      gvm_hosts_free (credential->ssh_credential->host_list);
      g_free (credential->ssh_credential);
    }
  else if (credential->type == SMB)
    {
      g_free (credential->smb_credential->username);
      g_free (credential->smb_credential->password);
      gvm_hosts_free (credential->smb_credential->host_list);
      g_free (credential->smb_credential);
    }
  else if (credential->type == ESXi)
    {
      g_free (credential->esxi_credential->username);
      g_free (credential->esxi_credential->password);
      gvm_hosts_free (credential->esxi_credential->host_list);
      g_free (credential->esxi_credential);
    }
  else if (credential->type == KRB5)
    {
      g_free (credential->krb5_credential->username);
      g_free (credential->krb5_credential->password);
      g_free (credential->krb5_credential->realm);
      g_free (credential->krb5_credential->kdc);
      gvm_hosts_free (credential->krb5_credential->host_list);
      g_free (credential->krb5_credential);
    }
  else if (credential->type == SNMP)
    {
      g_free (credential->snmp_credential->username);
      g_free (credential->snmp_credential->password);
      g_free (credential->snmp_credential->community);
      g_free (credential->snmp_credential->privacy_password);
      g_free (credential->snmp_credential->auth_proto);
      g_free (credential->snmp_credential->privacy_proto);
      gvm_hosts_free (credential->snmp_credential->host_list);
      g_free (credential->snmp_credential);
    }
  g_free (credential);
}

void
destroy_credentials (GSList **credentials)
{
  g_slist_free_full (*credentials, (GDestroyNotify) free_credential);
  *credentials = NULL;
}

static void
store_smb_credential (credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_SMB_AUTH_USER, get_smb_credential_username (credential)
                                  ? get_smb_credential_username (credential)
                                  : "");
  prefs_set (OID_SMB_AUTH_PASS, get_smb_credential_password (credential)
                                  ? get_smb_credential_password (credential)
                                  : "");
}

static int
match_smb_host_credential (credential_t *credential, const gvm_host_t *host)
{
  if (host == NULL || credential->smb_credential->host_list == NULL)
    return 0;

  if (!gvm_host_in_hosts (host, NULL, credential->smb_credential->host_list))
    return 0;

  store_smb_credential (credential);
  return 1;
}

static void
store_krb5_credential (credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_KRB5_AUTH_USER, get_krb5_credential_username (credential)
                                   ? get_krb5_credential_username (credential)
                                   : "");
  prefs_set (OID_KRB5_AUTH_PASS, get_krb5_credential_password (credential)
                                   ? get_krb5_credential_password (credential)
                                   : "");
  prefs_set (OID_KRB5_AUTH_REALM, get_krb5_credential_realm (credential)
                                    ? get_krb5_credential_realm (credential)
                                    : "");
  prefs_set (OID_KRB5_AUTH_KDC, get_krb5_credential_kdc (credential)
                                  ? get_krb5_credential_kdc (credential)
                                  : "");
}

static int
match_krb5_host_credential (credential_t *cred, const gvm_host_t *host)
{
  if (host == NULL || cred->krb5_credential->host_list == NULL)
    return 0;

  if (!gvm_host_in_hosts (host, NULL, cred->krb5_credential->host_list))
    return 0;

  store_krb5_credential (cred);
  return 1;
}

static void
store_esxi_credential (credential_t *cred)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_ESXI_AUTH_USER, get_esxi_credential_username (cred)
                                   ? get_esxi_credential_username (cred)
                                   : "");
  prefs_set (OID_ESXI_AUTH_PASS, get_esxi_credential_password (cred)
                                   ? get_esxi_credential_password (cred)
                                   : "");
}

static int
match_esxi_host_credential (credential_t *cred, const gvm_host_t *host)
{
  if (host == NULL || cred->esxi_credential->host_list == NULL)
    return 0;

  if (!gvm_host_in_hosts (host, NULL, cred->esxi_credential->host_list))
    return 0;

  store_esxi_credential (cred);
  return 1;
}

static void
store_snmp_credential (credential_t *credential)
{
  prefs_set (OID_SNMP_AUTH_COMMUNITY,
             get_snmp_credential_community (credential)
               ? get_snmp_credential_community (credential)
               : "");
  prefs_set (OID_SNMP_AUTH_USER, get_snmp_credential_username (credential)
                                   ? get_snmp_credential_username (credential)
                                   : "");
  prefs_set (OID_SNMP_AUTH_PASS, get_snmp_credential_password (credential)
                                   ? get_snmp_credential_password (credential)
                                   : "");
  prefs_set (OID_SNMP_AUTH_AUTH_ALGO,
             get_snmp_credential_auth_proto (credential)
               ? get_snmp_credential_auth_proto (credential)
               : "");
  prefs_set (OID_SNMP_AUTH_PRIV_PASS,
             get_snmp_credential_privacy_password (credential)
               ? get_snmp_credential_privacy_password (credential)
               : "");
  prefs_set (OID_SNMP_AUTH_PRIV_ALGO,
             get_snmp_credential_privacy_proto (credential)
               ? get_snmp_credential_privacy_proto (credential)
               : "");
}

static int
match_snmp_host_credential (credential_t *credential, const gvm_host_t *host)
{
  if (host == NULL || credential->snmp_credential->host_list == NULL)
    return 0;

  if (!gvm_host_in_hosts (host, NULL, credential->snmp_credential->host_list))
    return 0;

  store_snmp_credential (credential);
  return 1;
}

static void
store_ssh_credential (credential_t *credential)
{
  const char *private_key = get_ssh_credential_private_key (credential);
  const char *password = get_ssh_credential_password (credential);
  gboolean key_auth = private_key != NULL && private_key[0] != '\0';
  char port_string[6];
  int port = get_ssh_credential_port (credential);

  if (port)
    {
      g_snprintf (port_string, sizeof (port_string), "%d", port);
      prefs_set ("auth_port_ssh", port_string);
    }
  else
    // Let the nasl script set the default port. See kb_ssh_transport() in
    // ssh_func.inc
    prefs_set ("auth_port_ssh", NULL);

  prefs_set (OID_SSH_AUTH_USER, get_ssh_credential_username (credential)
                                  ? get_ssh_credential_username (credential)
                                  : "");
  prefs_set (OID_SSH_AUTH_PASS, key_auth ? "" : (password ? password : ""));
  prefs_set (OID_SSH_AUTH_PASSPHRASE, key_auth && password ? password : "");
  prefs_set (OID_SSH_AUTH_PRIV_USER,
             get_ssh_credential_privilege_username (credential)
               ? get_ssh_credential_privilege_username (credential)
               : "");
  prefs_set (OID_SSH_AUTH_PRIV_PASS,
             get_ssh_credential_privilege_password (credential)
               ? get_ssh_credential_privilege_password (credential)
               : "");
  prefs_set (OID_SSH_AUTH_PRIV_KEY,
             key_auth && get_ssh_credential_private_key_uuid (credential)
               ? get_ssh_credential_private_key_uuid (credential)
               : "");
}

static int
match_ssh_host_credential (credential_t *credential, const gvm_host_t *host)
{
  if (host == NULL || credential->ssh_credential->host_list == NULL)
    return 0;

  if (!gvm_host_in_hosts (host, NULL, credential->ssh_credential->host_list))
    return 0;

  store_ssh_credential (credential);
  return 1;
}

struct credential_check_data
{
  const gvm_host_t *host;
  credential_type_t type;
  gboolean ssh_selected;
  gboolean smb_selected;
  gboolean snmp_selected;
  gboolean krb5_selected;
  gboolean esxi_selected;
};

/**
 * @brief Stores the first matching credential to be used for the current
 * scanned host
 */
static void
set_host_credential (gpointer credential, gpointer user_data)
{
  struct credential_check_data *data = user_data;
  credential_t *cred = credential;

  if (cred->type != data->type)
    return;

  if (cred->type == SSH && data->ssh_selected != TRUE)
    {
      data->ssh_selected = match_ssh_host_credential (cred, data->host);
    }
  else if (cred->type == SNMP && data->snmp_selected != TRUE)
    {
      data->snmp_selected = match_snmp_host_credential (cred, data->host);
    }
  else if (cred->type == SMB && data->smb_selected != TRUE)
    {
      data->smb_selected = match_smb_host_credential (cred, data->host);
    }
  else if (cred->type == KRB5 && data->krb5_selected != TRUE)
    {
      data->krb5_selected = match_krb5_host_credential (cred, data->host);
    }
  else if (cred->type == ESXi && data->esxi_selected != TRUE)
    {
      data->esxi_selected = match_esxi_host_credential (cred, data->host);
    }
}

static void
set_host_credentials (GSList *credentials, const gvm_host_t *host,
                      credential_type_t type)
{
  if (host == NULL)
    return;

  struct credential_check_data *user_data =
    g_malloc0 (sizeof (struct credential_check_data));
  user_data->host = host;
  user_data->type = type;

  g_slist_foreach (credentials, (GFunc) set_host_credential,
                   (gpointer) user_data);
  g_free (user_data);
}

static void
select_host_ssh_credential (GSList *credentials, const gvm_host_t *host)
{
  if (get_ssh_credential_count () < 1)
    return;

  set_host_credentials (credentials, host, SSH);
}

static void
select_host_smb_credential (GSList *credentials, const gvm_host_t *host)
{
  if (get_smb_credential_count () < 1)
    return;

  set_host_credentials (credentials, host, SMB);
}

static void
select_host_snmp_credential (GSList *credentials, const gvm_host_t *host)
{
  if (get_snmp_credential_count () < 1)
    return;
  set_host_credentials (credentials, host, SNMP);
}

static void
select_host_krb5_credential (GSList *credentials, const gvm_host_t *host)
{
  if (get_krb5_credential_count () < 1)
    return;
  set_host_credentials (credentials, host, KRB5);
}

static void
select_host_esxi_credential (GSList *credentials, const gvm_host_t *host)
{
  if (get_esxi_credential_count () < 1)
    return;

  set_host_credentials (credentials, host, ESXi);
}

void
override_host_credentials (struct scan_globals *globals, const gvm_host_t *host)
{
  if (globals == NULL || globals->credentials == NULL || host == NULL)
    return;

  select_host_ssh_credential (globals->credentials, host);
  select_host_smb_credential (globals->credentials, host);
  select_host_krb5_credential (globals->credentials, host);
  select_host_snmp_credential (globals->credentials, host);
  select_host_esxi_credential (globals->credentials, host);
}
