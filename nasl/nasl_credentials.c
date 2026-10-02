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
#include <curl/curl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <gvm/util/json.h>
#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <libssh/libssh.h>
#include <unistd.h>

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
  // be carefull with this static var, since it only works under the current
  // forked host process model.
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

static int
try_krb5_credential (struct script_infos *args, credential_t *cred,
                     const char *host)
{
  // be carefull with this static var, since it only works under the current
  // forked host process model.
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

struct data
{
  char *memory;
  size_t size;
};

static size_t
write_memory_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct data *mem = (struct data *) userp;
  char *ptr = realloc (mem->memory, mem->size + realsize + 1);
  if (!ptr)
    return 0;
  mem->memory = ptr;
  memcpy (&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

static char *
extract_xml_tag (const char *xml, const char *tag)
{
  char start_tag[64];
  char end_tag[64];

  if (!xml || !tag)
    return NULL;

  g_snprintf (start_tag, sizeof (start_tag), "<%s", tag);
  g_snprintf (end_tag, sizeof (end_tag), "</%s>", tag);

  char *start = strstr (xml, start_tag);
  if (!start)
    return NULL;

  start = strchr (start, '>');
  if (!start)
    return NULL;
  start += 1;

  char *end = strstr (start, end_tag);
  if (!end)
    return NULL;

  size_t len = end - start;
  char *result = g_malloc0 (len + 1);
  if (!result)
    return NULL;
  memcpy (result, start, len);
  result[len] = '\0';
  return result;
}

static int
try_esxi_credential (struct script_infos *args, credential_t *cred,
                     const char *host)
{
  // be carefull with this static var, since it only works under the current
  // forked host process model.
  static int already_set = 0;
  int ret = 1;

  if (already_set)
    {
      g_debug ("ESXi credential already set");
      return already_set;
    }

  char cookie_file[32];
  char url[256];
  char host_header[256];
  CURL *curl;
  CURLcode res;
  long response_code = 0;

  g_snprintf (url, sizeof (url), "https://%s:443/sdk/webService", host);
  g_snprintf (host_header, sizeof (host_header), "Host: %s", host);
  g_snprintf (cookie_file, sizeof (cookie_file), "/tmp/cookies-%d.txt",
              getpid ());
  // Continuous raw string without layout modifications or newlines
  const char *bootstrap_payload =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope "
    "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
    "xmlns:xsi=\"http://www.w3.org/2001/"
    "XMLSchema-instance\"><soapenv:Body><RetrieveServiceContent "
    "xmlns=\"urn:vim25\"><_this "
    "type=\"ServiceInstance\">ServiceInstance</_this></"
    "RetrieveServiceContent></soapenv:Body></soapenv:Envelope>";

  curl_global_init (CURL_GLOBAL_ALL);
  curl = curl_easy_init ();

  if (curl)
    {
      struct curl_slist *headers = NULL;
      headers = curl_slist_append (headers, "Connection: Close");
      // UA intentioanlly hardcoded, like in the nasl script
      headers = curl_slist_append (headers, "User-Agent: VI Perl");
      headers = curl_slist_append (headers, host_header);
      headers = curl_slist_append (headers, "SOAPAction: \"urn:vim25/\"");
      headers = curl_slist_append (headers, "Content-Type: text/xml");

      curl_easy_setopt (curl, CURLOPT_URL, url);
      curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

      // this is intentionally disabled so we can test unknown targets
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt (curl, CURLOPT_COOKIEFILE, "");

      // get service content
      struct data write_data = {g_malloc0 (1), 0};
      curl_easy_setopt (curl, CURLOPT_POSTFIELDS, bootstrap_payload);
      curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *) &write_data);

      res = curl_easy_perform (curl);

      if (res != CURLE_OK)
        {
          g_debug ("%s: Step 1 Connection failed: %s", __func__,
                   curl_easy_strerror (res));
          g_free (write_data.memory);
          curl_slist_free_all (headers);
          curl_easy_cleanup (curl);
          goto finish;
        }

      char *sm_value = extract_xml_tag (write_data.memory, "sessionManager");
      g_free (write_data.memory);

      if (!sm_value)
        {
          g_debug ("%s: Could not extract dynamic sessionManager string",
                   __func__);
          curl_slist_free_all (headers);
          curl_easy_cleanup (curl);
          goto finish;
        }
      g_debug ("%s: Dynamic SessionManager ID found: %s", __func__, sm_value);

      // authenticate
      size_t login_sz = strlen (sm_value)
                        + strlen (get_esxi_credential_username (cred))
                        + strlen (get_esxi_credential_password (cred)) + 512;
      char *login_payload = g_malloc0 (login_sz);

      g_snprintf (
        login_payload, login_sz,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope "
        "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        "xmlns:xsi=\"http://www.w3.org/2001/"
        "XMLSchema-instance\"><soapenv:Body><Login xmlns=\"urn:vim25\"><_this "
        "type=\"SessionManager\">%s</_this><userName>%s</"
        "userName><password>%s</password></Login></soapenv:Body></"
        "soapenv:Envelope>",
        sm_value, get_esxi_credential_username (cred),
        get_esxi_credential_password (cred));

      g_free (sm_value);

      struct data login_chunk = {g_malloc0 (1), 0};
      curl_easy_setopt (curl, CURLOPT_POSTFIELDS, login_payload);
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *) &login_chunk);
      curl_easy_setopt (curl, CURLOPT_COOKIEJAR, cookie_file);

      res = curl_easy_perform (curl);

      if (res != CURLE_OK)
        {
          g_debug ("%s: Step 2 Connection failed: %s", __func__,
                   curl_easy_strerror (res));
        }
      else
        {
          curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
          if (response_code == 200)
            {
              g_debug ("%s: Credentials verified", __func__);
              ret = 0;
            }
          else
            {
              g_debug (
                "%s: FAILED: Target rejected authentication (HTTP %ld).\n",
                __func__, response_code);
              g_debug ("%s: Raw Server Response: \n %s", __func__,
                       login_chunk.memory);
            }
          remove (cookie_file);
        }

      g_free (login_payload);
      g_free (login_chunk.memory);
      curl_slist_free_all (headers);
      curl_easy_cleanup (curl);
    }

finish:
  curl_global_cleanup ();

  if (ret == 0)
    {
      g_debug ("%s: ESXi credential worked succesfully", __func__);
      store_esxi_credential (args, cred);
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
  // be carefull with this static var, since it only works under the current
  // forked host process model.
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
      free_snmpv1v2_request (requestv1v2c);
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
      free_snmpv1v2_request (requestv1v2c);
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
      free_snmpv3_request (requestv3);
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
  // be carefull with this static var, since it only works under the current
  // forked host process model.
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
  char ip_str[INET6_ADDRSTRLEN];
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SSH);
  return NULL;
}

tree_cell *
nasl_init_host_smb_credential (lex_ctxt *lexic)
{
  char ip_str[INET6_ADDRSTRLEN];
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SMB);
  return NULL;
}

tree_cell *
nasl_init_host_snmp_credential (lex_ctxt *lexic)
{
  char ip_str[INET6_ADDRSTRLEN];
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, SNMP);
  return NULL;
}

tree_cell *
nasl_init_host_krb5_credential (lex_ctxt *lexic)
{
  char ip_str[INET6_ADDRSTRLEN];
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, KRB5);
  return NULL;
}

tree_cell *
nasl_init_host_esxi_credential (lex_ctxt *lexic)
{
  char ip_str[INET6_ADDRSTRLEN];
  GSList *credentials = lexic->script_infos->globals->credentials;

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  set_host_credentials (lexic->script_infos, credentials, ip_str, ESXi);
  return NULL;
}
