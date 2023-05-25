/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_wmi.c
 * @brief NASL WMI functions
 *
 * Provides WMI (Windows Management Instrumentation) functionalities via calling
 * functions of a appropriate library.
 * The API offers three groups of functions:
 * 1. WMI_FUNCTIONS
 * 2. WMI_RSOP_FUNCTIONS (RSOP = Resultant Set of Policy)
 * 3. WMI_REGISTRY_FUNCTIONS
 */

#include "nasl_wmi.h"

#include "../misc/plugutils.h"
#include "openvas_wmi_interface.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <gvm/base/logging.h>
#include <gvm/base/networking.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define IMPORT(var) char *var = get_str_var_by_name (lexic, #var)
#define max 5

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/**
 * Returns 0 if any alphabets are present
 */
static int
check_alpha (char *val)
{
  int i, val_len;
  val_len = strlen (val);

  if ((strcmp (val, "-1")) != 0)
    {
      for (i = 0; i < val_len; i++)
        if (!isdigit (val[i]))
          return 0;
    }
  else
    return 0;

  return 1;
}

/**
 * Convert string to unsign int 32 bit
 */
static uint32_t
stoi_uint32_t (char *s)
{
  uint32_t v;
  sscanf (s, "%" PRIu32, &v);
  return v;
}

/**
 * Convert string to unsign int 64 bit
 */
static uint64_t
stoi_uint64_t (char *s)
{
  uint64_t v;
  sscanf (s, "%" PRIu64, &v);
  return v;
}

/**
 * @brief Get a version string of the WMI implementation.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case no implementation is present.
 *         Else a tree_cell with the version as string.
 */
tree_cell *
nasl_wmi_versioninfo (lex_ctxt *lexic)
{
  char *version = wmi_versioninfo ();
  tree_cell *retc;
  (void) lexic;

  if (!version)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (version);
  retc->size = strlen (version);
  return retc;
}

/*
################################################################################
 WMI_FUNCTIONS
################################################################################
*/

/**
 * @brief Connect to a WMI service and  return a handle for it.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the connection could not be established.
 *         Else a tree_cell with the handle.
 *
 * Retrieves local variables "host", "username", "password" and "ns"
 * from the lexical context, performs and connects to this given
 * WMI service returning a handle for the service as integer.
 */
tree_cell *
nasl_wmi_connect (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  char *argv[max];
  WMI_HANDLE handle;
  int argc = 5;
  IMPORT (username);
  IMPORT (password);
  IMPORT (ns);
  IMPORT (options);

  if (ns == NULL)
    ns = "root\\cimv2";

  if ((host == NULL) || (username == NULL) || (password == NULL))
    {
      g_message ("nasl_wmi_connect: Invalid input arguments");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0) || strlen (ip) == 0)
    {
      g_message ("nasl_wmi_connect: Invalid input arguments");
      g_free (ip);
      return NULL;
    }

  // Construct the WMI query
  argv[0] = g_strdup ("wmic");
  argv[1] = g_strdup ("-U");
  argv[2] = g_strdup_printf ("%s%%%s", username, password);
  argv[3] = g_strdup_printf ("//%s%s", ip, options ? options : "[sign]");
  argv[4] = g_strdup (ns);
  g_free (ip);

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  handle = wmi_connect (argc, argv);
  if (!handle)
    {
      g_message ("nasl_wmi_connect: WMI Connect failed or missing WMI support "
                 "for the scanner");
      return NULL;
    }

  retc->x.ref_val = handle;
  return retc;
}

/**
 * @brief Close WMI service handle.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of a serious problem. Else returns a
 *         treecell with integer == 1.
 *
 * Retrieves local variable "wmi_handle" from the lexical context
 * and closes the respective handle.
 */
tree_cell *
nasl_wmi_close (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);
  if (!handle)
    return NULL;

  tree_cell *retc = alloc_typed_cell (CONST_INT);

  if (wmi_close (handle) == 0)
    {
      retc->x.i_val = 1;
      return retc;
    }
  return NULL;
}

/**
 * @brief Perform WQL query.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the query can not be executed properly.
 *         Else a tree_cell with the result of the query as string.
 *
 * Retrieves local variables "wmi_handle" and "query" from the lexical
 * context, performs a WMI query on the given handle and returns the
 * result as a string.
 */
tree_cell *
nasl_wmi_query (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);
  char *query = get_str_var_by_name (lexic, "query");
  char *res = NULL;
  int value;

  if (!handle)
    return NULL;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_query (handle, query, &res);
  if ((value == -1) && (res != NULL))
    {
      g_message ("wmi_query: WMI query failed '%s' with error: '%s'", query,
                 res);
      g_free (res);
      return NULL;
    }
  else if ((value == -1) && (res == NULL))
    {
      g_debug ("wmi_query: WMI query failed '%s'", query);
      return NULL;
    }
  else if (res == NULL)
    return NULL;

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);

  return retc;
}

/*
################################################################################
 WMI_RSOP_FUNCTIONS
################################################################################
*/

/**
 * @brief Connect to a WMI RSOP service and return a handle for it.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the connection could not be established.
 *         Else a tree_cell with the handle.
 *
 * Retrieves local variables "host", "username", "password"
 * from the lexical context, performs and connects to this given
 * WMI service returning a handle for the service as integer.
 */
tree_cell *
nasl_wmi_connect_rsop (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  IMPORT (username);
  IMPORT (password);
  IMPORT (options);

  char *argv[4];
  WMI_HANDLE handle;
  int argc = 4;

  if ((host == NULL) || (username == NULL) || (password == NULL))
    {
      g_message ("nasl_wmi_connect_rsop: Invalid input arguments");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0) || strlen (ip) == 0)
    {
      g_message ("nasl_wmi_connect_rsop: Invalid input arguments");
      g_free (ip);
      return NULL;
    }

  // Construct the WMI query
  argv[0] = g_strdup ("wmic");
  argv[1] = g_strdup ("-U");
  argv[2] = g_strdup_printf ("%s%%%s", username, password);
  argv[3] = g_strdup_printf ("//%s%s", ip, options ? options : "[sign]");
  g_free (ip);

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  handle = wmi_connect_rsop (argc, argv);
  if (!handle)
    {
      g_message ("nasl_wmi_connect_rsop: WMI Connect failed or missing WMI "
                 "support for the scanner");
      return NULL;
    }

  retc->x.ref_val = handle;
  return retc;
}

/**
 * @brief WMI RSOP query.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, 1 on success
 *
 * Retrieves local variables "wmi_handle", "query"
 * from the lexical context, performs the RSOP query returning
 * results in string format.
 */
tree_cell *
nasl_wmi_query_rsop (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);
  if (!handle)
    return NULL;

  char *query = get_str_var_by_name (lexic, "query"); // WQL query
  char *res = NULL;
  int value;
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_query_rsop (handle, query, &res);
  if ((value == -1) && (res != NULL))
    {
      g_message ("wmi_query_rsop: WMI query failed '%s' with error: '%s'",
                 query, res);
      g_free (res);
      return NULL;
    }
  else if ((value == -1) && (res == NULL))
    {
      g_debug ("wmi_query_rsop: WMI query failed");
      return NULL;
    }
  else if (res == NULL)
    return NULL;

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);

  return retc;
}

/*
################################################################################
 WMI_REGISTRY_FUNCTIONS
################################################################################
*/

/**
 * @brief Connect to a WMI Registry service and return a handle for it.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the connection could not be established.
 *         Else a tree_cell with the handle.
 *
 * Retrieves local variables "host", "username", "password"
 * from the lexical context, performs and connects to this given
 * WMI service returning a handle for the service as integer.
 */
tree_cell *
nasl_wmi_connect_reg (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  IMPORT (username);
  IMPORT (password);
  IMPORT (options);

  char *argv[4];
  WMI_HANDLE handle;
  int argc = 4;

  if ((host == NULL) || (username == NULL) || (password == NULL))
    {
      g_message ("nasl_wmi_connect_reg: Invalid input arguments");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0) || strlen (ip) == 0)
    {
      g_message ("nasl_wmi_connect_reg: Invalid input arguments");
      g_free (ip);
      return NULL;
    }

  // Construct the WMI query
  argv[0] = g_strdup ("wmic");
  argv[1] = g_strdup ("-U");
  argv[2] = g_strdup_printf ("%s%%%s", username, password);
  argv[3] = g_strdup_printf ("//%s%s", ip, options ? options : "[sign]");
  g_free (ip);

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  handle = wmi_connect_reg (argc, argv);
  if (!handle)
    {
      g_message ("nasl_wmi_connect_reg: WMI Connect failed or missing WMI "
                 "support for the scanner");
      return NULL;
    }

  retc->x.ref_val = handle;
  return retc;
}

/**
 * @brief Get string value from Registry.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL if the query fails.
 *         Else a tree_cell with the Registry value.
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "key_name"
 * from the lexical context, performs the registry query
 * returning a string value.
 */
tree_cell *
nasl_wmi_reg_get_sz (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *key_name =
    get_str_var_by_name (lexic, "key_name"); // REGISTRY value name

  char *res = NULL;
  int value;
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_sz (handle, hive, key, key_name, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_sz: WMI Registry get failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);

  return retc;
}

/**
 * @brief Enumerate registry values.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL if the query fails.
 *         Else a tree_cell with the Registry values.
 *
 * Retrieves local variables "wmi_handle", "hive", "key"
 * from the lexical context, performs the registry query
 * returning a string value.
 */
tree_cell *
nasl_wmi_reg_enum_value (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY

  char *res = NULL;
  int value;
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_enum_value (handle, hive, key, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_enum_value: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);

  return retc;
}

/**
 * @brief Enumerate registry keys.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL if the query fails.
 *         Else a tree_cell with the Registry keys.
 *
 * Retrieves local variables "wmi_handle", "hive", "key"
 * from the lexical context, performs the registry query
 * returning a string value.
 */
tree_cell *
nasl_wmi_reg_enum_key (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY

  char *res = NULL;
  int value;
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_enum_key (handle, hive, key, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_enum_key: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);

  return retc;
}

/**
 * @brief Get registry binary value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, else tree_cell containing string
 *         representation of binary value
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "val_name"
 * from the lexical context, performs the registry operation
 * querying binary value.
 */
tree_cell *
nasl_wmi_reg_get_bin_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name"); // REGISTRY VALUE NAME

  char *res = NULL;
  int value;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_bin_val (handle, hive, key, val_name, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_bin_val: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  return retc;
}

/**
 * @brief Get registry DWORD value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, else tree_cell containing string
 *         representation of DWORD value
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "val_name"
 * from the lexical context, performs the registry operation
 * querying DWORD value.
 */
tree_cell *
nasl_wmi_reg_get_dword_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name"); // REGISTRY VALUE NAME

  char *res = NULL;
  int value;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_dword_val (handle, hive, key, val_name, &res);

  if ((value == 0) && (res == 0))
    res = "0";

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_dword_val: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  return retc;
}

/**
 * @brief Get registry expanded string value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, else tree_cell containing string
 *         representation of Expanded String value
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "val_name"
 * from the lexical context, performs the registry operation
 * querying Expanded string value.
 */
tree_cell *
nasl_wmi_reg_get_ex_string_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name"); // REGISTRY VALUE NAME

  char *res = NULL;
  int value;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_ex_string_val (handle, hive, key, val_name, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_ex_string_val: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  return retc;
}

/**
 * @brief Get registry multi valued strings.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, else tree_cell containing string
 *         representation of multi valued strings
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "val_name"
 * from the lexical context, performs the registry operation
 * querying Expanded string value.
 */
tree_cell *
nasl_wmi_reg_get_mul_string_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name"); // REGISTRY VALUE NAME

  char *res = NULL;
  int value;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_mul_string_val (handle, hive, key, val_name, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_mul_string_val: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  return retc;
}

/**
 * @brief Get registry QWORD value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure, else tree_cell containing string
 *         representation of QWORD value
 *
 * Retrieves local variables "wmi_handle", "hive", "key", "val_name"
 * from the lexical context, performs the registry operation
 * querying 64-bit unsigned integer.
 */
tree_cell *
nasl_wmi_reg_get_qword_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  unsigned int hive = get_int_var_by_name (lexic, "hive", 0); // REGISTRY Hive
  char *key = get_str_var_by_name (lexic, "key");             // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name"); // REGISTRY VALUE NAME

  char *res = NULL;
  int value;

  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wmi_reg_get_qword_val (handle, hive, key, val_name, &res);

  if ((value == -1) || (res == NULL))
    {
      g_message ("nasl_wmi_reg_get_qword_val: WMI query failed");
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  return retc;
}

/**
 * @brief Set Registry DWORD value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key", "val_name", "val"
 * from the lexical context, performs the registry set/create operation
 * for double word data type.
 *
 * It will work only if the key exist
 */
tree_cell *
nasl_wmi_reg_set_dword_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name");      // REGISTRY VALUE NAME
  char *val = get_str_var_by_name (lexic, "val"); // REGISTRY VALUE TO SET

  uint32_t val1;
  int value;

  // Return NULL if any alphabet is present
  if (check_alpha (val) == 0)
    return NULL;

  // Convert string to proper 64 bit integer
  val1 = stoi_uint32_t (val);

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_set_dword_val (handle, key, val_name, val1);

  if (value == -1)
    {
      g_message ("nasl_wmi_reg_set_dword_val: WMI registry set"
                 " operation failed");
      return NULL;
    }
  return retc;
}

/**
 * @brief Set Registry QWORD value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key", "val_name", "val"
 * from the lexical context, performs the registry set/create operation
 * for 64-bit unsigned integer.
 *
 * It will work only if the key exist
 */
tree_cell *
nasl_wmi_reg_set_qword_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name");      // REGISTRY VALUE NAME
  char *val = get_str_var_by_name (lexic, "val"); // REGISTRY VALUE TO SET

  uint64_t val1;
  int value;

  // Return if alphabets present
  if (check_alpha (val) == 0)
    return NULL;

  // Convert string to proper integer
  val1 = stoi_uint64_t (val);

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_set_qword_val (handle, key, val_name, val1);

  if (value == -1)
    {
      g_message ("nasl_wmi_reg_set_qword_val: WMI register"
                 " set operation failed");
      return NULL;
    }
  return retc;
}

/**
 * @brief Set Registry Expanded string value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key", "val_name", "val"
 * from the lexical context, performs the registry set/create operation
 * for string value.
 *
 * It will work only if the key exist
 */
tree_cell *
nasl_wmi_reg_set_ex_string_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name");      // REGISTRY VALUE NAME
  char *val = get_str_var_by_name (lexic, "val"); // REGISTRY VALUE TO SET

  int value;

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_set_ex_string_val (handle, key, val_name, val);

  if (value == -1)
    {
      g_message (
        "nasl_wmi_reg_set_ex_string_val: WMI registry set operation failed");
      return NULL;
    }
  return retc;
}

/**
 * @brief Set Registry string value.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key", "val_name", "val"
 * from the lexical context, performs the registry set/create operation
 * for string value.
 *
 * It will work only if the key exist
 */
tree_cell *
nasl_wmi_reg_set_string_val (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY
  char *val_name =
    get_str_var_by_name (lexic, "val_name");      // REGISTRY VALUE NAME
  char *val = get_str_var_by_name (lexic, "val"); // REGISTRY VALUE TO SET

  int value;

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_set_string_val (handle, key, val_name, val);

  if (value == -1)
    {
      g_message ("nasl_wmi_reg_set_string_val: WMI registry"
                 " set operation failed");
      return NULL;
    }
  return retc;
}

/**
 * @brief Create Registry key.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key"
 * from the lexical context, performs the registry create operation
 * for the key.
 */
tree_cell *
nasl_wmi_reg_create_key (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY

  int value;

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_create_key (handle, key);

  if (value == -1)
    {
      g_message ("nasl_wmi_reg_create_key: WMI registry key create"
                 " operation failed");
      return NULL;
    }
  return retc;
}

/**
 * @brief Delete Registry key.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL on failure
 *
 * Retrieves local variables "wmi_handle", "key"
 * from the lexical context, performs the registry delete operation
 * for the key.
 *
 * It will work only if the key exist
 */
tree_cell *
nasl_wmi_reg_delete_key (lex_ctxt *lexic)
{
  WMI_HANDLE handle = (WMI_HANDLE) get_int_var_by_name (lexic, "wmi_handle", 0);

  if (!handle)
    return NULL;

  char *key = get_str_var_by_name (lexic, "key"); // REGISTRY KEY

  int value;

  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;

  value = wmi_reg_delete_key (handle, key);

  if (value == -1)
    {
      g_message ("nasl_wmi_reg_delete_key: WMI registry key"
                 " delete operation failed");
      return NULL;
    }
  return retc;
}
