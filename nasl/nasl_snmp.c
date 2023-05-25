/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_snmp.c
 * @brief Implementation of an API for SNMP used by NASL scripts.
 */

#include "nasl_snmp.h"

#include "../misc/plugutils.h"
#include "nasl_lex_ctxt.h"

#include <assert.h>
#include <errno.h>
#include <gvm/base/logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/**
 * @brief SNMP V1
 */
#define SNMP_VERSION_1 0

/**
 * @brief SNMP V2c
 */
#define SNMP_VERSION_2c 1

#define FD_STDERR_FLAG 1
#define FD_STDOUT_FLAG 0

/**
 * @brief SNMP Request struct for snmp v1 and v2c
 */
struct snmpv1v2_request
{
  char *peername;  /**< snmp peer name. */
  char *community; /**< snmp community name. */
  char *oid_str;   /**< snmp oid to search for. */
  int version;     /**< snmp version. */
  u_char action;   /**< snmp get or getnext action. */
};

typedef struct snmpv1v2_request *snmpv1v2_request_t;

/**
 * @brief SNMP Request struct for snmp v3
 */
struct snmpv3_request
{
  char *peername; /**< snmp peer name. */
  char *username; /**< snmp username. */
  char *authpass; /**< snmp authorization password. */
  char *privpass; /**< snmp private password. */
  char *oid_str;  /**< snmp oid to search for. */
  int authproto;  /**< snmp authorization protocol. 0 for md5, 1 for sha1. */
  int privproto;  /**< snmp private protocol. 0 for des, 1 for aes. */
  u_char action;  /**< snmp get or getnext action. */
};

typedef struct snmpv3_request *snmpv3_request_t;

struct snmp_result
{
  char *oid_str; /**< oid. */
  char *name;    /**< value in stored under the oid. */
};

typedef struct snmp_result *snmp_result_t;

static void
destroy_snmp_result (snmp_result_t result)
{
  if (result == NULL)
    return;
  g_free (result->name);
  g_free (result->oid_str);
  g_free (result);
}

/*
 * @brief Check that protocol value is valid.
 *
 * param[in]    proto   Protocol string.
 *
 * @return 1 if proto is udp, udp6, tcp or tcp6. 0 otherwise.
 */
static int
proto_is_valid (const char *proto)
{
  if (strcmp (proto, "tcp") && strcmp (proto, "udp") && strcmp (proto, "tcp6")
      && strcmp (proto, "udp6"))
    return 0;
  return 1;
}

/*
 * @brief Create a NASL array from a snmp result.
 *
 * param[in]    ret     Return value.
 * param[in]    result  Result string.
 *
 * @return NASL array.
 */
static tree_cell *
array_from_snmp_result (int ret, const snmp_result_t result)
{
  anon_nasl_var v;

  assert (result);
  assert (result->name);
  tree_cell *retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
  /* Return code */
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;
  v.v.v_int = ret;
  add_var_to_list (retc->x.ref_val, 0, &v);
  /* Name */
  memset (&v, 0, sizeof v);
  v.var_type = VAR2_STRING;
  v.v.v_str.s_val = (unsigned char *) g_strdup (result->name);
  v.v.v_str.s_siz = strlen (result->name);
  add_var_to_list (retc->x.ref_val, 1, &v);
  /* OID */
  if (result->oid_str != NULL)
    {
      memset (&v, 0, sizeof v);
      v.var_type = VAR2_STRING;
      v.v.v_str.s_val = (unsigned char *) g_strdup (result->oid_str);
      v.v.v_str.s_siz = strlen (result->oid_str);
      add_var_to_list (retc->x.ref_val, 2, &v);
    }

  return retc;
}

static tree_cell *
array_from_snmp_error (int ret, const char *err)
{
  anon_nasl_var v;

  assert (err);
  tree_cell *retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
  /* Return code */
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;
  v.v.v_int = ret;
  add_var_to_list (retc->x.ref_val, 0, &v);
  /* Return error */
  memset (&v, 0, sizeof v);
  v.var_type = VAR2_STRING;
  v.v.v_str.s_val = (unsigned char *) err;
  v.v.v_str.s_siz = strlen (err);
  add_var_to_list (retc->x.ref_val, 1, &v);

  return retc;
}

#ifdef HAVE_NETSNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define NASL_SNMP_GET SNMP_MSG_GET
#define NASL_SNMP_GETNEXT SNMP_MSG_GETNEXT

/*
 * @brief SNMP Get query value.
 *
 * param[in]    session     SNMP session.
 * param[in]    oid_str     OID string.
 * param[in]    action      Action to perform to get entry
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmp_get (struct snmp_session *session, const char *oid_str,
          const u_char action, snmp_result_t result)
{
  struct snmp_session *ss;
  struct snmp_pdu *query, *response;
  oid oid_buf[MAX_OID_LEN];
  size_t oid_size = MAX_OID_LEN;
  int status;

  ss = snmp_open (session);
  if (!ss)
    {
      snmp_error (session, &status, &status, &(result->name));
      return -1;
    }

  query = snmp_pdu_create (action);
  read_objid (oid_str, oid_buf, &oid_size);
  snmp_add_null_var (query, oid_buf, oid_size);
  status = snmp_synch_response (ss, query, &response);
  if (status != STAT_SUCCESS)
    {
      snmp_error (ss, &status, &status, &(result->name));
      snmp_close (ss);
      return -1;
    }
  snmp_close (ss);

  if (response->errstat == SNMP_ERR_NOERROR)
    {
      struct variable_list *vars = response->variables;
      size_t res_len = 0, buf_len = 0, res_len1 = 0, buf_len1 = 0;

      netsnmp_ds_set_boolean (NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT,
                              1);
      sprint_realloc_value ((u_char **) &(result->name), &buf_len, &res_len, 1,
                            vars->name, vars->name_length, vars);
      sprint_realloc_objid ((u_char **) &(result->oid_str), &buf_len1,
                            &res_len1, 1, vars->name, vars->name_length);

      snmp_free_pdu (response);
      return 0;
    }

  result->name = g_strdup (snmp_errstring (response->errstat));
  snmp_free_pdu (response);
  return -1;
}

/*
 * @brief SNMPv3 Get query value.
 *
 * param[in]    request     Contains all necessary information for SNMPv3 query.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv3_get (const snmpv3_request_t request, snmp_result_t result)
{
  struct snmp_session session;

  assert (request);
  assert (request->peername);
  assert (request->username);
  assert (request->authpass);
  assert (request->authproto == 0 || request->authproto == 1);
  assert (request->oid_str);
  assert (request->action);

  setenv ("MIBS", "", 1);
  init_snmp ("openvas");
  snmp_sess_init (&session);
  session.version = SNMP_VERSION_3;
  session.peername = (char *) request->peername;
  session.securityName = (char *) request->username;
  session.securityNameLen = strlen (session.securityName);

  if (request->privpass)
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
  else
    session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
  if (request->authproto == 0)
    {
      session.securityAuthProto = usmHMACMD5AuthProtocol;
      session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
    }
  else
    {
      session.securityAuthProto = usmHMACSHA1AuthProtocol;
      session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
    }
  session.securityAuthKeyLen = USM_AUTH_KU_LEN;
  if (generate_Ku (session.securityAuthProto, session.securityAuthProtoLen,
                   (u_char *) request->authpass, strlen (request->authpass),
                   session.securityAuthKey, &session.securityAuthKeyLen)
      != SNMPERR_SUCCESS)
    {
      result->name = g_strdup ("generate_Ku: Error");
      return -1;
    }
  if (request->privpass)
    {
      if (request->privproto)
        {
          session.securityPrivProto = usmAESPrivProtocol;
          session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
        }
      else
        {
#ifdef NETSNMP_DISABLE_DES
          result->name =
            g_strdup ("DES not supported in this net-snmp version.");
          return -1;
#else
          session.securityPrivProto = usmDESPrivProtocol;
          session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#endif
        }
      session.securityPrivKeyLen = USM_PRIV_KU_LEN;
      if (generate_Ku (session.securityAuthProto, session.securityAuthProtoLen,
                       (unsigned char *) request->privpass,
                       strlen (request->privpass), session.securityPrivKey,
                       &session.securityPrivKeyLen)
          != SNMPERR_SUCCESS)
        {
          result->name = g_strdup ("generate_Ku: Error");
          return -1;
        }
    }

  return snmp_get (&session, request->oid_str, request->action, result);
}

/*
 * @brief SNMP v1 or v2c Get query value.
 *
 * param[in]    request     Contains all necessary information for SNMPv1 or
 *                          SNMPv2 query.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv1v2c_get (const snmpv1v2_request_t request, snmp_result_t result)
{
  struct snmp_session session;

  assert (request);
  assert (request->peername);
  assert (request->community);
  assert (request->oid_str);
  assert (request->version == SNMP_VERSION_1
          || request->version == SNMP_VERSION_2c);

  setenv ("MIBS", "", 1);
  snmp_sess_init (&session);
  session.version = request->version;
  session.peername = (char *) request->peername;
  session.community = (u_char *) request->community;
  session.community_len = strlen (request->community);

  return snmp_get (&session, request->oid_str, request->action, result);
}

#else // no libnet. snmpget cmd wrap-up

#define NASL_SNMP_GET 0
#define NASL_SNMP_GETNEXT 1

/**
 * @brief Parse the snmp error.
 *
 * @param result[in,out] The result error to be parsed.
 */
static void
parse_snmp_error (snmp_result_t result)
{
  gchar **res_split, **res_aux;

  res_aux = res_split = g_strsplit (result->name, "\n", 0);

  if (!res_split)
    return;

  while (res_aux)
    {
      /* There is no special reason, we return the whole error message
         but removing the new line char at the end.
       */
      if (*res_aux == NULL)
        {
          char *pos;

          if ((pos = strchr (result->name, '\n')) != NULL)
            *pos = '\0';
          break;
        }

      /* Search for the reason */
      *res_aux = g_strrstr (*res_aux, "Reason: ");
      if (*res_aux)
        {
          g_free (result->name);
          result->name = g_strdup (*res_aux + 8);
          break;
        }
      res_aux += 1;
    }

  g_strfreev (res_split);
  return;
}

/**
 * @brief Read data from a file descriptor.
 *
 * @param fd[in] File descriptor to read from.
 * @param result[out] String to write to.
 *
 * @return 0 success, -1 read error.
 */
static int
check_spwan_output (int fd, snmp_result_t result, int fd_flag)
{
  GString *string = NULL;

  string = g_string_new ("");
  while (1)
    {
      char buf[4096];
      size_t bytes;

      bytes = read (fd, buf, sizeof (buf));
      if (!bytes)
        break;
      else if (bytes > 0)
        g_string_append_len (string, buf, bytes);
      else
        {
          g_warning ("snmpget: %s", strerror (errno));
          g_string_free (string, TRUE);
          return -1;
        }
    }

  // Split the result and store the oid and name
  // in the result struct if there is a result
  if (fd_flag == FD_STDOUT_FLAG)
    {
      gchar **oid_and_name;

      oid_and_name = g_strsplit (string->str, " ", 2);
      result->oid_str = g_strdup (oid_and_name[0]);
      result->name = g_strdup (oid_and_name[1]);
      g_strfreev (oid_and_name);
    }
  else // STDERR, no oid
    result->name = g_strdup (string->str);

  g_string_free (string, TRUE);

  return 0;
}

/**
 * @brief SNMP v1 or v2c Get query value. snmpget cmd wrapper
 *
 * param[in]    request     Contains all necessary information for SNMPv1 or
 *                          SNMPv2 query.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv1v2c_get (const snmpv1v2_request_t request, snmp_result_t result)
{
  char *argv[8], *pos = NULL;
  GError *err = NULL;
  int sout = 0, serr = 0, ret;

  assert (request);
  assert (request->peername);
  assert (request->community);
  assert (request->oid_str);
  assert (request->version == SNMP_VERSION_1
          || request->version == SNMP_VERSION_2c);
  assert (request->action == NASL_SNMP_GET
          || request->action == NASL_SNMP_GETNEXT);

  setenv ("MIBS", "", 1);

  argv[0] = (request->action == NASL_SNMP_GET) ? "snmpget" : "snmpgetnext";
  argv[1] = (request->version == SNMP_VERSION_1) ? "-v1" : "-v2c";
  argv[2] = "-Oqn";
  argv[3] = "-c";
  argv[4] = g_strdup (request->community);
  argv[5] = g_strdup (request->peername);
  argv[6] = g_strdup (request->oid_str);
  argv[7] = NULL;
  ret = g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                                  NULL, NULL, NULL, &sout, &serr, &err);
  g_free (argv[4]);
  g_free (argv[5]);
  g_free (argv[6]);

  if (ret == FALSE)
    {
      g_warning ("snmpget: %s", err ? err->message : "Error");
      if (err)
        g_error_free (err);
      return -1;
    }

  /* As we spawn the process asynchronously, we don't know the exit
     status of the process. Therefore we need to check for errors in
     the output.
     We assume a valid output if there is no errors.
  */
  check_spwan_output (serr, result, FD_STDERR_FLAG);
  if (result->name && result->name[0] != '\0')
    {
      parse_snmp_error (result);
      close (sout);
      close (serr);
      return -1;
    }
  close (serr);
  g_free (result->name);

  check_spwan_output (sout, result, FD_STDOUT_FLAG);
  close (sout);

  /* Remove the last new line char from the result */
  if ((pos = strchr (result->name, '\0')) != NULL)
    {
      pos--;
      if (pos[0] == '\n')
        *pos = '\0';
    }

  return 0;
}

/**
 * @brief SNMPv3 Get query value. snmpget cmd wrapper.
 *
 * param[in]    request     Contains all necessary information for SNMPv3 query.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv3_get (const snmpv3_request_t request, snmp_result_t result)
{
  char *argv[18], *pos = NULL;
  GError *err = NULL;
  int sout = 0, serr = 0, ret;

  assert (request);
  assert (request->peername);
  assert (request->username);
  assert (request->authpass);
  assert (request->authproto == 0 || request->authproto == 1);
  assert (request->oid_str);
  assert (result);

  setenv ("MIBS", "", 1);

  argv[0] = (request->action == NASL_SNMP_GET) ? "snmpget" : "snmpgetnext";
  argv[1] = "-v3";
  argv[2] = "-Oqn";
  argv[3] = "-u";
  argv[4] = g_strdup (request->username);
  argv[5] = "-A";
  argv[6] = g_strdup (request->authpass);
  argv[7] = "-l";
  argv[8] = request->privpass ? "authPriv" : "authNoPriv";
  argv[9] = "-a";
  argv[10] = request->authproto ? "SHA" : "MD5";
  if (request->privpass)
    {
      argv[11] = g_strdup (request->peername);
      argv[12] = g_strdup (request->oid_str);
      argv[13] = "-x";
      argv[14] = request->privproto ? "AES" : "DES";
      argv[15] = "-X";
      argv[16] = g_strdup (request->privpass);
      argv[17] = NULL;
    }
  else
    {
      argv[11] = g_strdup (request->peername);
      argv[12] = g_strdup (request->oid_str);
      argv[13] = NULL;
    }

  ret = g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                                  NULL, NULL, NULL, &sout, &serr, &err);
  g_free (argv[4]);
  g_free (argv[6]);
  g_free (argv[11]);
  g_free (argv[12]);
  if (request->privpass)
    g_free (argv[16]);

  if (ret == FALSE)
    {
      g_warning ("%s: %s", argv[0], err ? err->message : "Error");
      if (err)
        g_error_free (err);
      return -1;
    }

  check_spwan_output (serr, result, FD_STDERR_FLAG);
  if (result->name && result->name[0] != '\0')
    {
      parse_snmp_error (result);
      close (sout);
      close (serr);
      return -1;
    }
  close (serr);
  g_free (result->name);

  check_spwan_output (sout, result, FD_STDOUT_FLAG);
  close (sout);

  /* Remove the last new line char from the result */
  if ((pos = strchr (result->name, '\0')) != NULL)
    {
      pos--;
      if (pos[0] == '\n')
        *pos = '\0';
    }

  return 0;
}

#endif /* HAVE_NETSNMP */

static tree_cell *
nasl_snmpv1v2c_get (lex_ctxt *lexic, int version, u_char action)
{
  tree_cell *retc = NULL;
  const char *proto;
  char peername[2048];
  int port, ret;
  snmpv1v2_request_t request;
  snmp_result_t result;
  char *oid_str;
  static char *next_oid_str;

  request = g_malloc0 (sizeof (struct snmpv1v2_request));

  request->version = version;
  request->action = action;
  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  request->community = get_str_var_by_name (lexic, "community");

  oid_str = get_str_var_by_name (lexic, "oid");
  if (action == NASL_SNMP_GETNEXT && oid_str == NULL && next_oid_str != NULL)
    request->oid_str = next_oid_str;
  else
    request->oid_str = oid_str;

  if (!proto || !request->community || !request->oid_str)
    {
      g_free (request);
      return array_from_snmp_error (-2, "Missing function argument");
    }
  if (port < 0 || port > 65535)
    {
      g_free (request);
      return array_from_snmp_error (-2, "Invalid port value");
    }
  if (!proto_is_valid (proto))
    {
      g_free (request);
      return array_from_snmp_error (-2, "Invalid protocol value");
    }

  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  request->peername = peername;

  result = g_malloc0 (sizeof (struct snmp_result));
  ret = snmpv1v2c_get (request, result);

  // Hack the OID string to adjust format. Replace 'iso.' with '.1.'
  // This Allows to call getnext without an oid, since the last oid
  // is stored.
  if (result->oid_str != NULL && g_strstr_len (result->oid_str, 3, "iso"))
    {
      next_oid_str = result->oid_str + 2;
      next_oid_str[0] = '1';
      result->oid_str = g_strdup (next_oid_str);
    }
  else if (result->oid_str != NULL)
    next_oid_str = result->oid_str;

  /* Free request only, since members are pointers to the nasl lexic context
     which will be free()'d later */
  g_free (request);

  retc = array_from_snmp_result (ret, result);
  destroy_snmp_result (result);
  return retc;
}

tree_cell *
nasl_snmpv1_get (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_1, NASL_SNMP_GET);
}

tree_cell *
nasl_snmpv1_getnext (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_1, NASL_SNMP_GETNEXT);
}

tree_cell *
nasl_snmpv2c_get (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_2c, NASL_SNMP_GET);
}

tree_cell *
nasl_snmpv2c_getnext (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_2c, NASL_SNMP_GETNEXT);
}

static tree_cell *
nasl_snmpv3_get_action (lex_ctxt *lexic, u_char action)
{
  tree_cell *retc = NULL;
  const char *proto, *authproto, *privproto;
  char peername[2048];
  int port, ret;
  snmpv3_request_t request;
  snmp_result_t result;
  char *oid_str;
  static char *next_oid_str;

  request = g_malloc0 (sizeof (struct snmpv3_request));

  request->action = action;
  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  request->username = get_str_var_by_name (lexic, "username");
  request->authpass = get_str_var_by_name (lexic, "authpass");

  oid_str = get_str_var_by_name (lexic, "oid");

  if (action == NASL_SNMP_GETNEXT && oid_str == NULL && next_oid_str != NULL)
    request->oid_str = next_oid_str;
  else
    request->oid_str = oid_str;

  authproto = get_str_var_by_name (lexic, "authproto");
  request->privpass = get_str_var_by_name (lexic, "privpass");
  privproto = get_str_var_by_name (lexic, "privproto");

  if (!proto || !request->username || !request->authpass || !request->oid_str
      || !authproto)
    {
      g_free (request);
      return array_from_snmp_error (-2, "Missing function argument");
    }
  if (port < 0 || port > 65535)
    {
      g_free (request);
      return array_from_snmp_error (-2, "Invalid port value");
    }
  if (!proto_is_valid (proto))
    {
      g_free (request);
      return array_from_snmp_error (-2, "Invalid protocol value");
    }

  if (!privproto || !request->privpass)
    {
      g_free (request);
      return array_from_snmp_error (-2, "Missing privproto or privpass");
    }

  if (!strcasecmp (authproto, "md5"))
    request->authproto = 0;
  else if (!strcasecmp (authproto, "sha1"))
    request->authproto = 1;
  else
    {
      g_free (request);
      return array_from_snmp_error (-2, "authproto should be md5 or sha1");
    }

  if (privproto)
    {
      if (!strcasecmp (privproto, "des"))
        request->privproto = 0;
      else if (!strcasecmp (privproto, "aes"))
        request->privproto = 1;
      else
        {
          g_free (request);
          return array_from_snmp_error (-2, "privproto should be des or aes");
        }
    }

  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  request->peername = peername;

  result = g_malloc0 (sizeof (struct snmp_result));
  ret = snmpv3_get (request, result);

  // Hack the OID string to adjust format. Replace 'iso.' with '.1.'
  // This Allows to call getnext without an oid, since the last oid
  // is stored.
  if (result->oid_str != NULL && g_strstr_len (result->oid_str, 3, "iso"))
    {
      next_oid_str = result->oid_str + 2;
      next_oid_str[0] = '1';
      result->oid_str = g_strdup (next_oid_str);
    }
  else if (result->oid_str != NULL)
    next_oid_str = result->oid_str;

  /* Free request only, since members are pointers to the nasl lexic context
     which will be free()'d later */
  g_free (request);

  retc = array_from_snmp_result (ret, result);
  destroy_snmp_result (result);
  return retc;
}

tree_cell *
nasl_snmpv3_get (lex_ctxt *lexic)
{
  return nasl_snmpv3_get_action (lexic, NASL_SNMP_GET);
}

tree_cell *
nasl_snmpv3_getnext (lex_ctxt *lexic)
{
  return nasl_snmpv3_get_action (lexic, NASL_SNMP_GETNEXT);
}
