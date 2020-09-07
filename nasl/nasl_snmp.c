/* Copyright (C) 2014-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file nasl_snmp.c
 * @brief Implementation of an API for SNMP used by NASL scripts.
 */

#include "../misc/plugutils.h"
#include "nasl_lex_ctxt.h"

#include <assert.h>
#include <errno.h>
#include <gvm/base/logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
array_from_snmp_result (int ret, char *result)
{
  anon_nasl_var v;

  assert (result);
  tree_cell *retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
  /* Return code */
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;
  v.v.v_int = ret;
  add_var_to_list (retc->x.ref_val, 0, &v);
  /* Return value */
  memset (&v, 0, sizeof v);
  v.var_type = VAR2_STRING;
  v.v.v_str.s_val = (unsigned char *) result;
  v.v.v_str.s_siz = strlen (result);
  add_var_to_list (retc->x.ref_val, 1, &v);

  return retc;
}

#ifdef HAVE_NETSNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/*
 * @brief SNMP Get query value.
 *
 * param[in]    session     SNMP session.
 * param[in]    oid_str     OID string.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmp_get (struct snmp_session *session, const char *oid_str, char **result)
{
  struct snmp_session *ss;
  struct snmp_pdu *query, *response;
  oid oid_buf[MAX_OID_LEN];
  size_t oid_size = MAX_OID_LEN;
  int status;

  ss = snmp_open (session);
  if (!ss)
    {
      snmp_error (session, &status, &status, result);
      return -1;
    }
  query = snmp_pdu_create (SNMP_MSG_GET);
  read_objid (oid_str, oid_buf, &oid_size);
  snmp_add_null_var (query, oid_buf, oid_size);
  status = snmp_synch_response (ss, query, &response);
  if (status != STAT_SUCCESS)
    {
      snmp_error (ss, &status, &status, result);
      snmp_close (ss);
      return -1;
    }
  snmp_close (ss);

  if (response->errstat == SNMP_ERR_NOERROR)
    {
      struct variable_list *vars = response->variables;
      size_t res_len = 0, buf_len = 0;

      netsnmp_ds_set_boolean (NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT,
                              1);
      sprint_realloc_value ((u_char **) result, &buf_len, &res_len, 1,
                            vars->name, vars->name_length, vars);
      snmp_free_pdu (response);
      return 0;
    }
  *result = g_strdup (snmp_errstring (response->errstat));
  snmp_free_pdu (response);
  return -1;
}

/*
 * @brief SNMPv3 Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    username    Username value.
 * param[in]    authpass    Authentication password.
 * param[in]    authproto   Authentication protocol. 0 for md5, 1 for sha1.
 * param[in]    privpass    Privacy password.
 * param[in]    privproto   Privacy protocol. 0 for des, 1 for aes.
 * param[in]    oid_str     OID of value to get.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv3_get (const char *peername, const char *username, const char *authpass,
            int authproto, const char *privpass, int privproto,
            const char *oid_str, char **result)
{
  struct snmp_session session;

  assert (peername);
  assert (username);
  assert (authpass);
  assert (authproto == 0 || authproto == 1);
  assert (oid_str);
  assert (result);

  setenv ("MIBS", "", 1);
  init_snmp ("openvas");
  snmp_sess_init (&session);
  session.version = SNMP_VERSION_3;
  session.peername = (char *) peername;
  session.securityName = (char *) username;
  session.securityNameLen = strlen (session.securityName);

  if (privpass)
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
  else
    session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
  if (authproto == 0)
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
                   (u_char *) authpass, strlen (authpass),
                   session.securityAuthKey, &session.securityAuthKeyLen)
      != SNMPERR_SUCCESS)
    {
      *result = g_strdup ("generate_Ku: Error");
      return -1;
    }
  if (privpass)
    {
      if (privproto)
        {
          session.securityPrivProto = usmAESPrivProtocol;
          session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
        }
      else
        {
          session.securityPrivProto = usmDESPrivProtocol;
          session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
        }
      session.securityPrivKeyLen = USM_PRIV_KU_LEN;
      if (generate_Ku (session.securityAuthProto, session.securityAuthProtoLen,
                       (unsigned char *) privpass, strlen (privpass),
                       session.securityPrivKey, &session.securityPrivKeyLen)
          != SNMPERR_SUCCESS)
        {
          *result = g_strdup ("generate_Ku: Error");
          return -1;
        }
    }

  return snmp_get (&session, oid_str, result);
}

/*
 * @brief SNMP v1 or v2c Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    community   SNMP community string.
 * param[in]    oid_str     OID string of value to get.
 * param[in]    version     SNMP_VERSION_1 or SNMP_VERSION_2c.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv1v2c_get (const char *peername, const char *community, const char *oid_str,
               int version, char **result)
{
  struct snmp_session session;

  assert (peername);
  assert (community);
  assert (oid_str);
  assert (version == SNMP_VERSION_1 || version == SNMP_VERSION_2c);

  setenv ("MIBS", "", 1);
  snmp_sess_init (&session);
  session.version = version;
  session.peername = (char *) peername;
  session.community = (u_char *) community;
  session.community_len = strlen (community);

  return snmp_get (&session, oid_str, result);
}

#else

#define SNMP_VERSION_1 0
#define SNMP_VERSION_2c 1

static void
parse_snmp_error (char **result)
{
  gchar **res_split, **res_aux;

  res_aux = res_split = g_strsplit (*result, "\n", 0);

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

          if ((pos = strchr (*result, '\n')) != NULL)
            *pos = '\0';
          break;
        }

      /* Search for the reason */
      *res_aux = g_strrstr (*res_aux, "Reason: ");
      if (*res_aux)
        {
          g_free (*result);
          *result = g_strdup (*res_aux + 8);
          break;
        }
      res_aux += 1;
    }

  g_strfreev (res_split);
  return;
}

static int
check_spwan_output (int fd, char **result)
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

  *result = g_strdup (string->str);
  g_string_free (string, TRUE);

  return 0;
}

/*
 * @brief SNMP v1 or v2c Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    community   SNMP community string.
 * param[in]    oid_str     OID string of value to get.
 * param[in]    version     SNMP_VERSION_1 or SNMP_VERSION_2c.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv1v2c_get (const char *peername, const char *community, const char *oid_str,
               int version, char **result)
{
  char *argv[7], *pos = NULL;
  GError *err = NULL;
  int sout = 0, serr = 0, ret;

  assert (peername);
  assert (community);
  assert (oid_str);
  assert (version == SNMP_VERSION_1 || version == SNMP_VERSION_2c);

  setenv ("MIBS", "", 1);

  argv[0] = "snmpget";
  argv[1] = (version == SNMP_VERSION_1) ? "-v1" : "-v2c";
  argv[2] = "-c";
  argv[3] = g_strdup (community);
  argv[4] = g_strdup (peername);
  argv[5] = g_strdup (oid_str);
  argv[6] = NULL;
  ret = g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                                  NULL, NULL, NULL, &sout, &serr, &err);
  g_free (argv[3]);
  g_free (argv[4]);
  g_free (argv[5]);

  if (ret == FALSE)
    {
      g_warning ("snmpget: %s", err ? err->message : "Error");
      if (err)
        g_error_free (err);
      return -1;
    }

  /* As we spawn the process asyncronously, we don't know the exit
     status of the process. Therefore we need to check for errors in
     the output.
     We assume that if there is no erros, we have an output.
  */
  check_spwan_output (serr, result);
  if (result && *result[0] != '\0')
    {
      parse_snmp_error (result);
      close (sout);
      close (serr);
      return -1;
    }
  close (serr);
  g_free (*result);

  check_spwan_output (sout, result);
  close (sout);

  /* Remove new line char from the result */
  if ((pos = strchr (*result, '\n')) != NULL)
    *pos = '\0';

  return 0;
}

/*
 * @brief SNMPv3 Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    username    Username value.
 * param[in]    authpass    Authentication password.
 * param[in]    authproto   Authentication protocol. 0 for md5, 1 for sha1.
 * param[in]    privpass    Privacy password.
 * param[in]    privproto   Privacy protocol. 0 for des, 1 for aes.
 * param[in]    oid_str     OID of value to get.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv3_get (const char *peername, const char *username, const char *authpass,
            int authproto, const char *privpass, int privproto,
            const char *oid_str, char **result)
{
  char *argv[17], *pos = NULL;
  GError *err = NULL;
  int sout = 0, serr = 0, ret;

  assert (peername);
  assert (username);
  assert (authpass);
  assert (authproto == 0 || authproto == 1);
  assert (oid_str);
  assert (result);

  setenv ("MIBS", "", 1);

  argv[0] = "snmpget";
  argv[1] = "-v3";
  argv[2] = "-u";
  argv[3] = g_strdup (username);
  argv[4] = "-A";
  argv[5] = g_strdup (authpass);
  argv[6] = "-l";
  argv[7] = privpass ? "authPriv" : "authNoPriv";
  argv[8] = "-a";
  argv[9] = authproto ? "SHA" : "MD5";
  if (privpass)
    {
      argv[10] = g_strdup (peername);
      argv[11] = g_strdup (oid_str);
      argv[12] = "-x";
      argv[13] = privproto ? "AES" : "DES";
      argv[14] = "-X";
      argv[15] = g_strdup (privpass);
      argv[16] = NULL;
    }
  else
    {
      argv[10] = g_strdup (peername);
      argv[11] = g_strdup (oid_str);
      argv[12] = NULL;
    }

  ret = g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                                  NULL, NULL, NULL, &sout, &serr, &err);
  g_free (argv[3]);
  g_free (argv[5]);
  g_free (argv[10]);
  g_free (argv[11]);
  if (privpass)
    g_free (argv[15]);

  if (ret == FALSE)
    {
      g_warning ("snmpget: %s", err ? err->message : "Error");
      if (err)
        g_error_free (err);
      return -1;
    }

  check_spwan_output (serr, result);
  if (result && *result[0] != '\0')
    {
      parse_snmp_error (result);
      close (sout);
      close (serr);
      return -1;
    }
  close (serr);
  g_free (*result);

  check_spwan_output (sout, result);
  close (sout);

  /* Remove new line char from the result */
  if ((pos = strchr (*result, '\n')) != NULL)
    *pos = '\0';

  return 0;
}

#endif /* HAVE_NETSNMP */

tree_cell *
nasl_snmpv1v2c_get (lex_ctxt *lexic, int version)
{
  const char *proto, *community, *oid_str;
  char *result = NULL, peername[2048];
  int port, ret;

  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  community = get_str_var_by_name (lexic, "community");
  oid_str = get_str_var_by_name (lexic, "oid");
  if (!proto || !community || !oid_str)
    return array_from_snmp_result (-2, "Missing function argument");
  if (port < 0 || port > 65535)
    return array_from_snmp_result (-2, "Invalid port value");
  if (!proto_is_valid (proto))
    return array_from_snmp_result (-2, "Invalid protocol value");

  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  ret = snmpv1v2c_get (peername, community, oid_str, version, &result);
  return array_from_snmp_result (ret, result);
}

tree_cell *
nasl_snmpv1_get (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_1);
}

tree_cell *
nasl_snmpv2c_get (lex_ctxt *lexic)
{
  return nasl_snmpv1v2c_get (lexic, SNMP_VERSION_2c);
}

tree_cell *
nasl_snmpv3_get (lex_ctxt *lexic)
{
  const char *proto, *username, *authpass, *authproto, *oid_str;
  const char *privpass, *privproto;
  char *result = NULL, peername[2048];
  int port, ret, aproto, pproto = 0;

  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  username = get_str_var_by_name (lexic, "username");
  authpass = get_str_var_by_name (lexic, "authpass");
  oid_str = get_str_var_by_name (lexic, "oid");
  authproto = get_str_var_by_name (lexic, "authproto");
  privpass = get_str_var_by_name (lexic, "privpass");
  privproto = get_str_var_by_name (lexic, "privproto");
  if (!proto || !username || !authpass || !oid_str || !authproto)
    return array_from_snmp_result (-2, "Missing function argument");
  if (port < 0 || port > 65535)
    return array_from_snmp_result (-2, "Invalid port value");
  if (!proto_is_valid (proto))
    return array_from_snmp_result (-2, "Invalid protocol value");
  if ((privpass && !privproto) || (!privpass && privproto))
    return array_from_snmp_result (-2, "Missing privproto or privpass");
  if (!strcasecmp (authproto, "md5"))
    aproto = 0;
  else if (!strcasecmp (authproto, "sha1"))
    aproto = 1;
  else
    return array_from_snmp_result (-2, "authproto should be md5 or sha1");
  if (privproto)
    {
      if (!strcasecmp (privproto, "des"))
        pproto = 0;
      else if (!strcasecmp (privproto, "aes"))
        pproto = 1;
      else
        return array_from_snmp_result (-2, "privproto should be des or aes");
    }

  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  ret = snmpv3_get (peername, username, authpass, aproto, privpass, pproto,
                    oid_str, &result);
  return array_from_snmp_result (ret, result);
}
