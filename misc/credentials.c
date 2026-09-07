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

#define OID_SSH_AUTH "1.3.6.1.4.1.25623.1.0.103591"
#define OID_KRB5_AUTH "1.3.6.1.4.1.25623.1.0.102114"
#define OID_SMB_AUTH "1.3.6.1.4.1.25623.1.0.90023"
#define OID_ESXI_AUTH "1.3.6.1.4.1.25623.1.0.105058"
#define OID_SNMP_AUTH "1.3.6.1.4.1.25623.1.0.105076"

#define OID_SMB_AUTH_USER "1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:"
#define OID_SMB_AUTH_PASS "1.3.6.1.4.1.25623.1.0.90023:2:password:SMB password:"

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

#define OID_KRB5_AUTH_USER "1.3.6.1.4.1.25623.1.0.102114:1:entry::"
#define OID_KRB5_AUTH_PASS "1.3.6.1.4.1.25623.1.0.102114:2:password::"
#define OID_KRB5_AUTH_REALM "1.3.6.1.4.1.25623.1.0.102114:3:entry::"
#define OID_KRB5_AUTH_KDC "1.3.6.1.4.1.25623.1.0.102114:4:entry::"

#define OID_ESXI_AUTH_USER "1.3.6.1.4.1.25623.1.0.105058"
#define OID_ESXI_AUTH_PASS "1.3.6.1.4.1.25623.1.0.105058"

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
  char *auth_algorithm;
  char *privacy_password;
  char *privacy_algorithm;
};

struct esxi_credential_type
{
  char *username;
  char *password;
};

typedef struct credential
{
  enum credential_type type;
  union
  {
    ssh_credential_t *ssh_credential;
    smb_credential_t *smb_credential;
    esxi_credential_t *esxi_credential;
    snmp_credential_t *snmp_credential;
    krb5_credential_t *krb5_credential;
  };
} credential_t;

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
      cred->auth_algorithm = g_strdup (gvm_json_obj_str (item, "algorithm"));
      cred->privacy_password = g_strdup (gvm_json_obj_str (item, "password"));
      cred->privacy_algorithm = g_strdup (gvm_json_obj_str (item, "algorithm"));
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
  parser = cJSON_Parse (json_credentials);
  if (parser == NULL || !cJSON_IsArray (parser))
    {
      *err = g_strdup ("Unable to parse credentials data");
      goto res_cleanup;
    }

  cJSON_ArrayForEach (service_obj, parser)
  {
    if (!cJSON_IsObject (service_obj))
      {
        *err = g_strdup ("Unable to parse credential data object");
        goto res_cleanup;
      }

    if (service_obj != NULL)
      {
        char *service = gvm_json_obj_str (service_obj, "service");
        credential_t *credential = g_malloc0 (sizeof (credential_t));
        int ret = 0;
        if (!g_strcmp0 (service, "ssh"))
          {
            ret = credential_ssh_new (service_obj, &credential);
            if (credential->ssh_credential->private_key != NULL
                && credential->ssh_credential->private_key[0] != '\0')
              {
                char *file_uuid = gvm_uuid_make ();
                if (store_file (*globals,
                                credential->ssh_credential->private_key,
                                file_uuid))
                  g_debug ("%s: Failed to parse file tipe private key.",
                           __func__);
                credential->ssh_credential->private_key_uuid =
                  g_strdup (file_uuid);
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
            g_warning ("%s: Unknown credential service type %s", __func__,
                       service);
            continue;
          }
        if (ret == 0)
          (*globals)->credentials =
            g_slist_prepend ((*globals)->credentials, credential);
        else
          g_warning (
            "%s: not possible to parse a credential. Missing information",
            __func__);
      }
  }

res_cleanup:
  if (*err != NULL)
    {
      g_warning ("%s: Unable to parse credentials. Reason: %s", __func__, *err);
    }
  cJSON_Delete (parser);

  return 0;
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
      g_free (credential->snmp_credential->privacy_algorithm);
      g_free (credential->snmp_credential->privacy_password);
      g_free (credential->snmp_credential);
    }
}

void
destroy_credentials (GSList **credentials)
{
  g_slist_free_full (*credentials, (GDestroyNotify) free_credential);
}

static void
store_ssh_credential (ssh_credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_SSH_AUTH_USER, credential->username);
  prefs_set (OID_SSH_AUTH_PASS, credential->password);
  prefs_set (OID_SSH_AUTH_PASSPHRASE, credential->password);
  prefs_set (OID_SSH_AUTH_PRIV_USER, credential->privilege_username);
  prefs_set (OID_SSH_AUTH_PRIV_PASS, credential->privilege_password);
  prefs_set (OID_SSH_AUTH_PRIV_KEY, credential->private_key_uuid);
}

static int
try_ssh_auth_methods (ssh_session session, ssh_credential_t *credential)
{
  int rc, retc_val = -1;
  // try with user pass
  if (credential->password)
    {
      rc = ssh_userauth_password (session, NULL, credential->password);
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }
      g_debug ("SSH password authentication failed : %s",
               ssh_get_error (session));
    }

  // try interactive
  if (credential->password)
    {
      g_debug ("trying interactive method");
      /* Our strategy for kbint is to send the password to the first
         prompt marked as non-echo.  */

      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          const char *s;
          int n, nprompt;
          char echoflag;
          int found_prompt = 0;

          s = ssh_userauth_kbdint_getname (session);
          if (s && *s)
            g_debug ("SSH kbdint name='%s'", s);
          s = ssh_userauth_kbdint_getinstruction (session);
          if (s && *s)
            g_debug ("SSH kbdint instruction='%s'", s);

          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n = 0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s)
                g_debug ("SSH kbdint prompt='%s'%s", s,
                         echoflag ? "" : " [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                {
                  found_prompt = 1;
                  rc = ssh_userauth_kbdint_setanswer (session, n,
                                                      credential->password);
                  if (rc != SSH_AUTH_SUCCESS)
                    {
                      g_debug ("SSH keyboard-interactive authentication "
                               "failed at prompt for session %d: %s",
                               n, ssh_get_error (session));
                    }
                }
            }

          if (rc == SSH_AUTH_SUCCESS)
            {
              retc_val = 0;
              goto leave;
            }

          g_debug ("SSH keyboard-interactive authentication failed for session"
                   ": %s",
                   ssh_get_error (session));
        }
    }

  /* If we have a private key, try public key authentication.  */
  if (credential->private_key && credential->private_key[0] != '\0')
    {
      char *priv_key;
      size_t bytes = 0;
      ssh_key key = NULL;

      g_debug ("trying public key auth method");
      priv_key = (char *) g_base64_decode (credential->private_key, &bytes);
      if (ssh_pki_import_privkey_base64 (priv_key, credential->password, NULL,
                                         NULL, &key))
        {
          g_debug ("SSH public key authentication failed for "
                   "session: %s",
                   "Error converting provided key");
        }
      else if (ssh_userauth_try_publickey (session, NULL, key)
               != SSH_AUTH_SUCCESS)
        {
          g_debug ("SSH public key authentication failed for "
                   "session: %s",
                   "Server does not want our key");
        }
      else if (ssh_userauth_publickey (session, NULL, key) == SSH_AUTH_SUCCESS)
        {
          g_debug ("pubkey success");
          retc_val = 0;
          ssh_key_free (key);
          goto leave;
        }
      g_debug ("SSH pub-key authentication failed for session"
               ": %s",
               ssh_get_error (session));
      g_free (priv_key);
      ssh_key_free (key);
    }
leave:

  return retc_val;
}

static int
try_ssh_credential (ssh_credential_t *credential, const char *host_target)
{
  static int already_set = 0;
  ssh_session session = NULL;
  int rc;

  if (already_set)
    {
      g_debug ("SSH credential already set");
      return already_set;
    }
  // Open session and set options
  session = ssh_new ();
  if (session == NULL)
    exit (-1);
  ssh_options_set (session, SSH_OPTIONS_HOST, host_target);
  ssh_options_set (session, SSH_OPTIONS_PORT, &credential->port);
  ssh_options_set (session, SSH_OPTIONS_USER, credential->username);
  ssh_options_set (session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
  // Connect to server
  rc = ssh_connect (session);
  if (rc != SSH_OK)
    {
      g_debug ("Error connecting to %s: %s\n", host_target,
               ssh_get_error (session));
      ssh_free (session);
      exit (-1);
    }

  // Authenticate
  rc = try_ssh_auth_methods (session, credential);

  if (rc != SSH_AUTH_SUCCESS)
    {
      g_debug ("Error authenticating with password: %s\n",
               ssh_get_error (session));
      ssh_disconnect (session);
      ssh_free (session);
      return already_set;
    }
  already_set = 1;

  ssh_disconnect (session);
  ssh_free (session);

  store_ssh_credential (credential);

  return already_set;
}

static void
set_host_credential (gpointer credential, gpointer host_target)
{
  char *host = host_target;
  credential_t *cred = credential;

  if (cred->type == SSH)
    {
      try_ssh_credential (cred->ssh_credential, host);
    }
}

void
set_host_credentials (GSList *credentials, const char *host)
{
  g_slist_foreach (credentials, (GFunc) set_host_credential, (gpointer) host);
}
