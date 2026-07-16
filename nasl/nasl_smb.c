/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_smb.c
 * @brief API for NASL built-in SMB access focussing effective file rights
 *
 * Provides SMB API as built-in functions to NASL via calling
 * corresponding functions of a appropriate library.
 * The focus is on effective files rights which can't be retrieved
 * via WMI.
 */

#include "nasl_smb.h"

#include "../misc/plugutils.h"
#include "base/hosts.h"
#include "glib.h"
#include "glibconfig.h"
#include "nasl_debug.h"
#include "nasl_lex_ctxt.h"
#include "nasl_misc_funcs.h"
#include "nasl_var.h"
#include "openvas_smb_interface.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gvm/base/logging.h>
#include <gvm/base/networking.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define KERBEROS_AUTH_TYPE "Kerberos"
#define IMPORT(var) char *var = get_str_var_by_name (lexic, #var)

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/**
 * @brief Get a version string of the SMB implementation.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case no implementation is present.
 *         Else a tree_cell with the version as string.
 */
tree_cell *
nasl_smb_versioninfo (lex_ctxt *lexic)
{
  char *version = smb_versioninfo ();
  tree_cell *retc;
  (void) lexic;

  if (!version)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (version);
  retc->size = strlen (version);
  return retc;
}

/**
 * @brief Connect to SMB service and return a handle for it.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the connection could not be established.
 *         Else a tree_cell with the handle.
 *
 * Retrieves local variables "host", "username", "password" and "share"
 * from the lexical context, performs and connects to this given
 * SMB service returning a handle for the service as integer.
 */
tree_cell *
nasl_smb_connect (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  char *username = get_str_var_by_name (lexic, "username");
  char *password = get_str_var_by_name (lexic, "password");
  char *share = get_str_var_by_name (lexic, "share");

  tree_cell *retc;
  SMB_HANDLE handle = 0;
  int value;

  if ((host == NULL) || (username == NULL) || (password == NULL)
      || (share == NULL))
    {
      g_message ("nasl_smb_connect: Invalid input arguments");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0) || (strlen (ip) == 0)
      || (strlen (share) == 0))
    {
      g_message ("nasl_smb_connect: Invalid input arguments");
      g_free (ip);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  value = smb_connect (ip, share, username, password, &handle);
  g_free (ip);

  if (value == -1)
    {
      g_message ("nasl_smb_connect: SMB Connect failed");
      return NULL;
    }

  retc->x.i_val = handle;
  return retc;
}

/**
 * @brief Close SMB service handle.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of a serious problem. Else returns a
 *         treecell with integer == 1.
 *
 * Retrieves local variable "smb_handle" from the lexical context
 * and closes the respective handle.
 */
tree_cell *
nasl_smb_close (lex_ctxt *lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  int ret;
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);

  ret = smb_close (handle);
  if (ret == 0)
    {
      retc->x.i_val = 1;
      return retc;
    }
  else
    return NULL;
}

/**
 * @brief Obtain Security Descriptor in SDDL format
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with SDDL string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_SDDL (lex_ctxt *lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      g_message ("smb_file_SDDL failed: Invalid filename");
      return NULL;
    }

  if (!handle)
    {
      g_message ("smb_file_SDDL failed: Invalid smb_handle");
      return NULL;
    }

  tree_cell *retc;
  char *buffer = NULL;

  buffer = smb_file_SDDL (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Obtain File Owner SID
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Owner SID string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_owner_sid (lex_ctxt *lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      g_message ("smb_file_owner_sid failed: Invalid filename");
      return NULL;
    }

  if (!handle)
    {
      g_message ("smb_file_owner_sid failed: Invalid smb_handle");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_OwnerSID (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Obtain File Group SID
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Group SID string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_group_sid (lex_ctxt *lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      g_message ("smb_file_group_sid failed: Invalid filename");
      return NULL;
    }

  if (!handle)
    {
      g_message ("smb_file_group_sid failed: Invalid smb_handle");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_GroupSID (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Obtain File Trustee SID with Access Mask
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Trustee SID and Access Mask string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_trustee_rights (lex_ctxt *lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      g_message ("smb_file_trustee_rights failed: Invalid filename");
      return NULL;
    }

  if (!handle)
    {
      g_message ("smb_file_trustee_rights failed: Invalid smb_handle");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_TrusteeRights (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Execute the command in windows
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL if the query fails.
 *  Else a tree_cell with the command execution result.
 *
 * Retrieves local variables "cmd" from the lexical
 * context, performs the windows command execution operation
 * returning the result.
 */

tree_cell *
nasl_win_cmd_exec (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host_ip = plug_get_host_ip (script_infos);
  gvm_host_t *gvm_host = NULL;
  char *argv[7], *unicode, target[2048], *c;
  tree_cell *retc;
  GString *string = NULL;
  int sout, ret;
  GError *err = NULL;
  bool krb5 = false;
  bool calculate_host = false;
  char first_kdc[INET6_ADDRSTRLEN] = {0};
  const char *delimiter;

  IMPORT (host);
  IMPORT (username);
  IMPORT (password);
  IMPORT (realm);
  IMPORT (kdc);

  IMPORT (cmd);
  krb5 = kdc != NULL;

  if ((username == NULL) || (password == NULL) || (cmd == NULL))
    {
      g_message ("win_cmd_exec: Invalid input arguments");
      return NULL;
    }

  if (host == NULL)
    {
      calculate_host = true;
      host = addr6_as_str (host_ip);
      if (krb5)
        {
          gvm_host = gvm_host_from_str (host);
          g_free (host);
          host = gvm_host_reverse_lookup (gvm_host);
          g_free (gvm_host);
        }
    }
  if (host == NULL)
    {
      g_message ("win_cmd_exec: host must not be empty.");
      return NULL;
    }
  if ((strlen (password) == 0) || (strlen (username) == 0)
      || strlen (host) == 0)
    {
      g_message ("win_cmd_exec: Invalid input arguments");
      if (calculate_host)
        g_free (host);
      return NULL;
    }

  /* wmiexec.py uses domain/username format. */
  if ((c = strchr (username, '\\')))
    *c = '/';
  if (strchr (username, '/') == NULL)
    {
      snprintf (target, sizeof (target), "%s/%s:%s@%s", realm, username,
                password, host);
    }
  else
    {
      snprintf (target, sizeof (target), "%s:%s@%s", username, password, host);
    }
  if (calculate_host)
    g_free (host);

  argv[0] = "impacket-wmiexec";
  if (krb5 == false)
    {
      argv[1] = target;
      argv[2] = cmd;
      argv[3] = NULL;
    }
  else
    {
      delimiter = strchr (kdc, ',');
      if (delimiter && (delimiter - kdc > INET6_ADDRSTRLEN - 1))
        {
          g_warning ("kdc hostname value too long (max 45 chars)");
          return NULL;
        }

      if (delimiter != NULL)
        {
          strncpy (first_kdc, kdc, delimiter - kdc);
        }
      else
        {
          strncpy (first_kdc, kdc, sizeof (first_kdc) - 1);
        }
      argv[1] = "-k";
      argv[2] = "-dc-ip";
      argv[3] = first_kdc;
      argv[4] = target;
      argv[5] = cmd;
      argv[6] = NULL;
    }
  ret = g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                                  NULL, NULL, NULL, &sout, NULL, &err);
  if (ret == FALSE)
    {
      g_warning ("win_cmd_exec: %s", err ? err->message : "Error");
      if (err)
        g_error_free (err);
      return NULL;
    }

  string = g_string_new ("");
  while (1)
    {
      char buf[4096];
      size_t bytes;

      bytes = read (sout, buf, sizeof (buf));
      if (!bytes)
        break;
      else if (bytes > 0)
        g_string_append_len (string, buf, bytes);
      else
        {
          g_warning ("win_cmd_exec: %s", strerror (errno));
          g_string_free (string, TRUE);
          close (sout);
          return NULL;
        }
    }
  close (sout);

  if (g_str_has_prefix (string->str, "[-]"))
    {
      g_warning ("win_cmd_exec: %s", string->str);
      g_string_free (string, TRUE);
      return NULL;
    }
  else if ((unicode = strstr (string->str, "\xff\xfe")))
    {
      /* UTF-16 case. */
      size_t length, diff;
      err = NULL;
      char *tmp;

      diff = unicode - string->str + 1;
      tmp = g_convert (unicode + 2, string->len - diff, "UTF-8", "UTF-16", NULL,
                       &length, &err);
      if (!tmp)
        {
          g_warning ("win_cmd_exec: %s", err->message);
          g_string_free (string, TRUE);
          g_error_free (err);
          return NULL;
        }
      g_free (string->str);
      string->len = length;
      string->str = tmp;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = string->str;
  retc->size = string->len;
  return retc;
}

static tree_cell *
array_from_psrp_error (int ret, char *err)
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

/**
 * @brief Execute the PowerShell command in windows
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Nasl Array. The first element is the exit code.
 *         The second element is the output. Code are 0 for success
 *         1 for error comming from the binary and
 *         2 error from the nasl function.
 *
 * Retrieves local variables "cmd" from the lexical
 * context, performs the windows command execution operation
 * returning the result.
 */

tree_cell *
nasl_psrp_cli (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host_ip = plug_get_host_ip (script_infos);
  gvm_host_t *gvm_host = NULL;
  char *argv[48], *unicode, port_str[6];
  tree_cell *retc;
  anon_nasl_var v;
  GString *string = NULL;
  int sout, ret, port, ssl;
  GError *err = NULL;
  bool krb5 = false;
  bool calculate_host = false;
  char first_kdc[INET6_ADDRSTRLEN] = {0};
  const char *delimiter;
  GString *missing_args;
  int missing_arg_flag = 0;

  IMPORT (interpreter);
  IMPORT (cmd);
  IMPORT (host);
  IMPORT (path);
  IMPORT (authentication);
  IMPORT (username);
  IMPORT (password);
  IMPORT (realm);
  IMPORT (kdc);

  missing_args = g_string_new ("Following are missing arguments:\n");
  if ((ssl = get_int_var_by_name (lexic, "ssl", -1)) < 0)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "ssl\n");
    }

  if ((port = get_int_var_by_name (lexic, "port", -1)) < 0)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "port\n");
    }

  if (interpreter == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "interpreter\n");
    }

  if (cmd == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "cmd\n");
    }

  if (host == NULL && host_ip == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "host\n");
    }

  if (path == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "path\n");
    }

  if (authentication == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "authentication\n");
    }

  if (username == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "username\n");
    }

  if (password == NULL)
    {
      missing_arg_flag = 1;
      g_string_append (missing_args, "password\n");
    }

  if (missing_arg_flag)
    return array_from_psrp_error (2, g_string_free (missing_args, FALSE));
  g_string_free (missing_args, TRUE);

  snprintf (port_str, sizeof (port_str), "%d", port);

  krb5 = !g_strcmp0 (authentication, KERBEROS_AUTH_TYPE);
  if (host == NULL && host_ip != NULL)
    {
      calculate_host = true;
      host = addr6_as_str (host_ip);
      if (host != NULL && krb5)
        {
          gvm_host = gvm_host_from_str (host);
          g_free (host);
          host = gvm_host_reverse_lookup (gvm_host);
          g_free (gvm_host);
        }
    }

  if (host == NULL)
    return array_from_psrp_error (
      2, g_strdup ("Not possible to reverse lookup the target IP"));

  // Mandatory arguments
  int argv_pos = 0;

  argv[argv_pos++] = g_strdup ("pypsrp-cli");
  argv[argv_pos++] = g_strdup ("--interpreter");
  argv[argv_pos++] = g_strdup (interpreter);
  argv[argv_pos++] = g_strdup ("--command");
  argv[argv_pos++] = g_strdup (cmd);
  argv[argv_pos++] = g_strdup ("--target");
  argv[argv_pos++] = g_strdup (host);
  argv[argv_pos++] = g_strdup ("--path");
  argv[argv_pos++] = g_strdup (path);
  argv[argv_pos++] = g_strdup ("--ssl");
  argv[argv_pos++] = g_strdup (ssl ? "1" : "0");
  argv[argv_pos++] = g_strdup ("--port");
  argv[argv_pos++] = g_strdup (port_str);
  argv[argv_pos++] = g_strdup ("--username");
  argv[argv_pos++] = g_strdup (username);
  argv[argv_pos++] = g_strdup ("--password");
  argv[argv_pos++] = g_strdup (password);
  argv[argv_pos++] = g_strdup ("--authentication");
  argv[argv_pos++] = g_strdup (authentication);

  if (calculate_host == true)
    g_free (host);

  // kdc and realm are optional if no krb5 auth method.
  if (krb5 && kdc != NULL && realm != NULL)
    {
      delimiter = strchr (kdc, ',');
      if (delimiter && (delimiter - kdc > INET6_ADDRSTRLEN - 1))
        {
          for (int i = 0; i < argv_pos; i++)
            g_free (argv[i]);
          return array_from_psrp_error (
            2, g_strdup ("kdc hostname value too long (max 45 chars)"));
        }

      if (delimiter != NULL)
        {
          strncpy (first_kdc, kdc, delimiter - kdc);
        }
      else
        {
          strncpy (first_kdc, kdc, sizeof (first_kdc) - 1);
        }

      argv[argv_pos++] = g_strdup ("--kdc");
      argv[argv_pos++] = g_strdup (first_kdc);
      argv[argv_pos++] = g_strdup ("--realm");
      argv[argv_pos++] = g_strdup (realm);
    }

  // additional arguments
  tree_cell *anon_args = get_variable_by_name (lexic, "additional_args");
  if (anon_args != NULL)
    {
      anon_nasl_var *args_var = NULL;
      nasl_array *array_values;
      int n;
      char *str;
      if ((args_var = anon_args->x.ref_val) == NULL)
        {
          deref_cell (anon_args);
          nasl_perror (lexic, "%s empty array for additional arguments\n",
                       __func__);
          for (int i = 0; i < argv_pos; i++)
            g_free (argv[i]);
          return array_from_psrp_error (
            2, g_strdup ("empty array for additional arguments"));
        }

      deref_cell (anon_args);
      if (args_var->var_type == VAR2_ARRAY)
        {
          array_values = &args_var->v.v_arr;

          n = array_max_index (array_values);
          if (n > 9)
            {
              nasl_perror (lexic, "%s: too many additional arguments!\n",
                           __func__);
              for (int i = 0; i < argv_pos; i++)
                g_free (argv[i]);
              return array_from_psrp_error (
                2, g_strdup ("too many additional arguments"));
            }

          for (int i = 0; i < n; i++)
            {
              str = (char *) var2str (array_values->num_elt[i]);
              if (str != NULL)
                argv[argv_pos++] = g_strdup (str);
            }
        }
      else if (args_var->var_type == VAR2_UNDEF)
        {
        }
      else
        {
          nasl_perror (lexic, "%s: argv element must be an array (0x%x)\n",
                       __func__, args_var->var_type);
          for (int i = 0; i < argv_pos; i++)
            g_free (argv[i]);
          return array_from_psrp_error (
            2, g_strdup ("argv element must be an array"));
        }
    }
  argv[argv_pos++] = NULL;

  GPid child_pid;
  int err_code = 0;

  ret = g_spawn_async_with_pipes (
    NULL, argv, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD, NULL,
    NULL, &child_pid, NULL, &sout, NULL, &err);

  for (int i = 0; i < argv_pos; i++)
    g_free (argv[i]);

  if (ret == FALSE)
    {
      char *err_aux = err ? g_strdup (err->message) : g_strdup ("Error");
      g_debug ("%s: %s", __func__, err_aux);
      if (err)
        g_error_free (err);
      return array_from_psrp_error (2, err_aux);
    }

  string = g_string_new ("");
  while (1)
    {
      char buf[4096];
      ssize_t bytes;

      bytes = read (sout, buf, sizeof (buf));
      if (!bytes)
        break;
      else if (bytes > 0)
        g_string_append_len (string, buf, bytes);
      else
        {
          char *err_aux = g_strdup (strerror (errno));
          g_debug ("%s: %s", __func__, err_aux);
          g_string_free (string, TRUE);
          close (sout);
          waitpid (child_pid, NULL, 0);
          g_spawn_close_pid (child_pid);

          return array_from_psrp_error (2, err_aux);
        }
    }
  close (sout);

  /* waitpid(-1) in sighand_chld may have already reaped this child before
   * we get here, which is why g_child_watch_add() fails with ECHILD.
   * Use waitpid() directly and treat ECHILD as a successful reap with
   * an unknown (assumed zero) exit code. */
  int wait_status = 0;
  if (waitpid (child_pid, &wait_status, 0) == -1)
    {
      if (errno == ECHILD)
        err_code = 0; /* already reaped by SIGCHLD handler */
      else
        err_code = -1;
    }
  else
    {
      err_code = WIFEXITED (wait_status) ? WEXITSTATUS (wait_status) : -1;
    }
  g_spawn_close_pid (child_pid);

  if (g_str_has_prefix (string->str, "[-]") || err_code != 0)
    {
      char *err_aux = g_string_free (string, FALSE);
      g_debug ("%s: %s", __func__, err_aux);
      return array_from_psrp_error (1, err_aux);
    }
  else if ((unicode = strstr (string->str, "\xff\xfe")))
    {
      /* UTF-16 case. */
      size_t length, diff;
      err = NULL;
      char *tmp;

      diff = unicode - string->str + 2;
      tmp = g_convert (unicode + 2, string->len - diff, "UTF-8", "UTF-16", NULL,
                       &length, &err);
      if (!tmp)
        {
          char *err_aux = g_strdup (err->message);
          g_debug ("%s: %s", __func__, err_aux);
          g_string_free (string, TRUE);
          g_error_free (err);
          return array_from_psrp_error (2, err_aux);
        }
      g_free (string->str);
      string->len = length;
      string->str = tmp;
    }

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;
  v.v.v_int = 0; // success
  add_var_to_list (retc->x.ref_val, 0, &v);
  memset (&v, 0, sizeof v);
  v.var_type = VAR2_STRING;
  v.v.v_str.s_siz = string->len;
  v.v.v_str.s_val = (unsigned char *) g_string_free (string, FALSE);
  add_var_to_list (retc->x.ref_val, 1, &v);

  return retc;
}
