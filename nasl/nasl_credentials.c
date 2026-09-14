/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file credentials.c
 * @brief Functions to set and get the credentials.
 */

#include "nasl_credentials.h"

#include "../misc/credentials.h"
#include "../misc/plugutils.h"
#include "base/networking.h"
#include "nasl_lex_ctxt.h"
#include "nasl_smb.h"
#include "nasl_snmp.h"
#include "nasl_tree.h"

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
  "1.3.6.1.4.1.25623.1.0.105058:1:password:ESXi login password:"

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

static void
store_smb_credential (struct script_infos *args, credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_SMB_AUTH_USER, get_smb_credential_username (credential));
  prefs_set (OID_SMB_AUTH_PASS, get_smb_credential_password (credential));

  plug_replace_key (args, "SMB/login_filled/0", ARG_STRING,
                    get_smb_credential_username (credential));
  plug_replace_key (args, "SMB/password_filled/0", ARG_STRING,
                    get_smb_credential_password (credential));
}

static int
try_smb_credential (struct script_infos *args, credential_t *cred,
                    const char *host)
{
  static int already_set = 0;
  int ret;

  if (already_set)
    {
      g_debug ("SMB credential already set");
      return already_set;
    }

  ret = smb_krb5_login_test (host, get_smb_credential_username (cred),
                             get_smb_credential_password (cred), NULL, NULL);
  if (ret == 0)
    {
      g_debug ("SMB credential worked succesfully ");
      store_smb_credential (args, cred);
      already_set = 1;
    }

  return already_set;
}

static void
store_krb5_credential (struct script_infos *args, credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_KRB5_AUTH_USER, get_krb5_credential_username (credential));
  prefs_set (OID_KRB5_AUTH_PASS, get_krb5_credential_password (credential));
  prefs_set (OID_KRB5_AUTH_REALM, get_krb5_credential_realm (credential));
  prefs_set (OID_KRB5_AUTH_KDC, get_krb5_credential_kdc (credential));

  plug_replace_key (args, "KRB5/login_filled/0", ARG_STRING,
                    get_krb5_credential_username (credential));
  plug_replace_key (args, "KRB5/password_filled/0", ARG_STRING,
                    get_krb5_credential_password (credential));
  plug_replace_key (args, "KRB5/realm_filled/0", ARG_STRING,
                    get_krb5_credential_realm (credential));
  plug_replace_key (args, "KRB5/kdc_filled/0", ARG_STRING,
                    get_krb5_credential_kdc (credential));
}

static void
store_esxi_credential (struct script_infos *args, credential_t *cred)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_ESXI_AUTH_USER, get_esxi_credential_username (cred));
  prefs_set (OID_ESXI_AUTH_PASS, get_esxi_credential_password (cred));

  plug_replace_key (args, "esxi/login_filled/0", ARG_STRING,
                    get_esxi_credential_username (cred));
  plug_replace_key (args, "esxi/password_filled/0", ARG_STRING,
                    get_esxi_credential_password (cred));
}

static int
try_esxi_credential (struct script_infos *args, credential_t *cred,
                     const char *host)
{
  static int already_set = 0;
  int ret = 1;

  if (already_set)
    {
      g_debug ("ESXi credential already set");
      return already_set;
    }

  // TODO: Implement ESXi credential test
  (void) host;

  if (ret == 0)
    {
      g_debug ("ESXi credential worked succesfully ");
      store_esxi_credential (args, cred);
      already_set = 1;
    }

  return already_set;
}

static int
try_krb5_credential (struct script_infos *args, credential_t *cred,
                     const char *host)
{
  static int already_set = 0;
  int ret;

  if (already_set)
    {
      g_debug ("KRB5 credential already set");
      return already_set;
    }

  ret = smb_krb5_login_test (host, get_krb5_credential_username (cred),
                             get_krb5_credential_password (cred),
                             get_krb5_credential_realm (cred),
                             get_krb5_credential_kdc (cred));
  if (ret == 0)
    {
      g_debug ("KRB5 credential worked succesfully ");
      store_krb5_credential (args, cred);
      already_set = 1;
    }

  return already_set;
}

static void
store_snmp_credential (struct script_infos *args, credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_SNMP_AUTH_COMMUNITY,
             get_snmp_credential_community (credential));
  prefs_set (OID_SNMP_AUTH_USER, get_snmp_credential_username (credential));
  prefs_set (OID_SNMP_AUTH_PASS, get_snmp_credential_password (credential));
  prefs_set (OID_SNMP_AUTH_AUTH_ALGO,
             get_snmp_credential_auth_proto (credential));
  prefs_set (OID_SNMP_AUTH_PRIV_PASS,
             get_snmp_credential_privacy_password (credential));
  prefs_set (OID_SNMP_AUTH_PRIV_ALGO,
             get_snmp_credential_privacy_proto (credential));

  plug_replace_key (args, "SNMP/v12c/provided_community", ARG_STRING,
                    get_snmp_credential_community (credential));
  plug_replace_key (args, "SNMP/v3/username", ARG_STRING,
                    get_snmp_credential_username (credential));
  plug_replace_key (args, "SNMP/v3/password", ARG_STRING,
                    get_snmp_credential_password (credential));
  plug_replace_key (args, "SNMP/v3/auth_algorithm", ARG_STRING,
                    get_snmp_credential_auth_proto (credential));
  plug_replace_key (args, "SNMP/v3/privacy_password", ARG_STRING,
                    get_snmp_credential_privacy_password (credential));
  plug_replace_key (args, "SNMP/v3/privacy_algorithm", ARG_STRING,
                    get_snmp_credential_privacy_proto (credential));
}

static int
try_snmp_credential (struct script_infos *args, credential_t *credential,
                     const char *host_target)
{
  static int already_set = 0;
  int ret;
  char peername[2048];
  snmp_result_t result;
  snmpv1v2_request_t requestv1v2c;
  snmpv3_request_t requestv3;

  if (already_set)
    {
      g_debug ("SNMP credential already set");
      return already_set;
    }
  // TODO: get the protocol and port from the kb instead of assuming udp:161,
  // since a script could have stored need values.
  g_snprintf (peername, sizeof (peername), "udp:%s:161", host_target);

  if (get_snmp_credential_community (credential))
    {
      // try SNMP v1
      requestv1v2c = new_snmpv1v2_request (
        peername, get_snmp_credential_community (credential), 0);
      result = new_snmp_result ();

      ret = snmpv1v2c_get (requestv1v2c, result);
      g_free (requestv1v2c);
      destroy_snmp_result (result);
      if (ret != 0)
        g_debug ("%s: Failed authenticating SNMP v1 credential", __func__);
      else
        {
          g_debug ("%s: snmp v1 successfully authenticated", __func__);
          store_snmp_credential (args, credential);
          already_set = 1;
          return already_set;
        }

      // try SNMP v2c
      requestv1v2c = new_snmpv1v2_request (
        peername, get_snmp_credential_community (credential), 1);
      result = new_snmp_result ();

      ret = snmpv1v2c_get (requestv1v2c, result);
      g_free (requestv1v2c);
      destroy_snmp_result (result);
      if (ret != 0)
        g_debug ("%s: Failed authenticating SNMP v2c credential", __func__);
      else
        {
          g_debug ("%s: snmp v2c successfully authenticated", __func__);
          store_snmp_credential (args, credential);
          already_set = 1;
          return already_set;
        }
    }
  // try SNMP v3
  else if (credential && get_snmp_credential_username (credential)
           && get_snmp_credential_password (credential)
           && get_snmp_credential_auth_proto (credential))
    {
      requestv3 = new_snmpv3_request (
        peername, get_snmp_credential_username (credential),
        get_snmp_credential_password (credential),
        get_snmp_credential_privacy_password (credential),
        g_strcmp0 (get_snmp_credential_auth_proto (credential), "md5") ? 1 : 0,
        g_strcmp0 (get_snmp_credential_privacy_proto (credential), "des") ? 1
                                                                          : 0);
      result = new_snmp_result ();

      ret = snmpv3_get (requestv3, result);
      g_free (requestv3);
      destroy_snmp_result (result);
      if (ret != 0)
        g_debug ("%s: Failed authenticating SNMP v2c credential", __func__);
      else
        {
          g_debug ("%s: snmp v3 successfully authenticated", __func__);
          store_snmp_credential (args, credential);
          already_set = 1;
          return already_set;
        }
    }

  return already_set;
}

static void
store_ssh_credential (struct script_infos *args, credential_t *credential)
{
  // prefs set will replace the old values if any.
  prefs_set (OID_SSH_AUTH_USER, get_ssh_credential_username (credential));
  prefs_set (OID_SSH_AUTH_PASS, get_ssh_credential_password (credential));
  prefs_set (OID_SSH_AUTH_PASSPHRASE, get_ssh_credential_password (credential));
  prefs_set (OID_SSH_AUTH_PRIV_USER,
             get_ssh_credential_privilege_username (credential));
  prefs_set (OID_SSH_AUTH_PRIV_PASS,
             get_ssh_credential_privilege_password (credential));
  prefs_set (OID_SSH_AUTH_PRIV_KEY,
             get_ssh_credential_private_key_uuid (credential));

  plug_replace_key (args, "Secret/SSH/login", ARG_STRING,
                    get_ssh_credential_username (credential));
  plug_replace_key (args, "Secret/SSH/password", ARG_STRING,
                    get_ssh_credential_password (credential));
  plug_replace_key (args, "Secret/SSH/privatekey", ARG_STRING,
                    get_ssh_credential_private_key_uuid (credential));
  plug_replace_key (args, "Secret/SSH/passphrase", ARG_STRING,
                    get_ssh_credential_password (credential));
  plug_replace_key (args, "Secret/SSH/privlogin", ARG_STRING,
                    get_ssh_credential_privilege_username (credential));
  plug_replace_key (args, "Secret/SSH/privpassword", ARG_STRING,
                    get_ssh_credential_privilege_password (credential));
}

static int
try_ssh_auth_methods (ssh_session session, credential_t *credential)
{
  int rc, retc_val = -1;
  // try with user pass
  if (get_ssh_credential_password (credential))
    {
      rc = ssh_userauth_password (session, NULL,
                                  get_ssh_credential_password (credential));
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }
      g_debug ("SSH password authentication failed : %s",
               ssh_get_error (session));
    }

  // try interactive
  if (get_ssh_credential_password (credential))
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
                  rc = ssh_userauth_kbdint_setanswer (
                    session, n, get_ssh_credential_password (credential));
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
  if (get_ssh_credential_private_key (credential) != NULL)
    {
      char *priv_key;
      size_t bytes = 0;
      ssh_key key = NULL;

      g_debug ("trying public key auth method");
      priv_key = (char *) g_base64_decode (
        get_ssh_credential_private_key (credential), &bytes);
      if (ssh_pki_import_privkey_base64 (
            priv_key, get_ssh_credential_password (credential), NULL, NULL,
            &key))
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

// TODO: get the port from the kb if the port was not provided. Default
// to 22 in last case.
static int
try_ssh_credential (struct script_infos *args, credential_t *credential,
                    const char *host_target)
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

  int port = get_ssh_credential_port (credential);
  ssh_options_set (session, SSH_OPTIONS_HOST, host_target);
  ssh_options_set (session, SSH_OPTIONS_PORT, &port);
  ssh_options_set (session, SSH_OPTIONS_USER,
                   get_ssh_credential_username (credential));
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

  store_ssh_credential (args, credential);

  return already_set;
}

struct credential_check_data
{
  const char *host;
  struct script_infos *args;
  credential_type_t type;
};

static void
set_host_credential (gpointer credential, gpointer user_data)
{
  struct credential_check_data *data = user_data;
  credential_t *cred = credential;

  if (cred->type != data->type)
    return;

  if (cred->type == SSH)
    {
      try_ssh_credential (data->args, cred, data->host);
    }
  else if (cred->type == SNMP)
    {
      try_snmp_credential (data->args, cred, data->host);
    }
  else if (cred->type == SMB)
    {
      try_smb_credential (data->args, cred, data->host);
    }
  else if (cred->type == KRB5)
    {
      try_krb5_credential (data->args, cred, data->host);
    }
  else if (cred->type == ESXi)
    {
      try_esxi_credential (data->args, cred, data->host);
    }
}

static void
set_host_credentials (struct script_infos *args, GSList *credentials,
                      const char *host, credential_type_t type)
{
  if (host == NULL)
    return;

  struct credential_check_data *user_data =
    g_malloc0 (sizeof (struct credential_check_data));
  user_data->host = host;
  user_data->type = type;
  user_data->args = args;

  g_slist_foreach (credentials, (GFunc) set_host_credential,
                   (gpointer) user_data);
}

tree_cell *
nasl_init_host_ssh_credential (lex_ctxt *lexic)
{
  char *ip_str = NULL;
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SSH);
  return NULL;
}

tree_cell *
nasl_init_host_smb_credential (lex_ctxt *lexic)
{
  char *ip_str = NULL;
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SSH);
  return NULL;
}

tree_cell *
nasl_init_host_snmp_credential (lex_ctxt *lexic)
{
  char *ip_str = NULL;
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SNMP);
  return NULL;
}

tree_cell *
nasl_init_host_krb5_credential (lex_ctxt *lexic)
{
  char *ip_str = NULL;
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, KRB5);
  return NULL;
}

tree_cell *
nasl_init_host_esxi_credential (lex_ctxt *lexic)
{
  char *ip_str = NULL;
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, ESXi);
  return NULL;
}
