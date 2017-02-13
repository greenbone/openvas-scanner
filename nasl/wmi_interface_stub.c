/* OpenVAS
 *
 * $Id$
 * Description: Stub implementation for a wmi interface.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file wmi_interface_stub.c
 * @brief Stub implementatin for a wmi interface.
 *
 * This file contains an empty implementation that
 * fulfills the wmi interface specfified in \ref openvas_wmi_interface.h
 */

/* for NULL */
#include <string.h>

#include "openvas_wmi_interface.h"

/**
 * @brief Return version info for WMI implementation.
 *
 * @return NULL if this the impementation is a non-functional stub,
 *         else a arbitrary string that explains the version of the
 *         implementation.
 */
char *
wmi_versioninfo ()
{
  return NULL;
}

/**
 * @brief Establish connection to a WMI service.
 *
 * @param[out] handle - A connection handle in case of success.
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_connect (int argc, char **argv, WMI_HANDLE * handle)
{
  (void) argc;
  (void) argv;
  (void) handle;
  return -1;
}

/**
 * @brief Close the connection handle for a WMI service.
 *
 * @param[in] handle - WMI service connection handle
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_close (WMI_HANDLE handle)
{
  (void) handle;
  return -1;
}

/**
 * @brief Query WMI service using a WQL query
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] query - The WQL query string
 *
 * @param[out] result - Result of query as string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_query (WMI_HANDLE handle, const char *query, char **result)
{
  (void) handle;
  (void) query;
  (void) result;
  return -1;
}

/**
 * @brief Establish connection to a WMI RSOP service.
 *
 * @param[out] handle - A connection handle in case of success.
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_connect_rsop (int argc, char **argv, WMI_HANDLE * handle)
{
  (void) argc;
  (void) argv;
  (void) handle;
  return -1;
}

/**
 * @brief WMI RSOP query.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] query - WQL RSOP query
 *
 * @param[in] res - Registry value to be queried
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_query_rsop (WMI_HANDLE handle, const char *query, char **res)
{
  (void) handle;
  (void) query;
  (void) res;
  return -1;
}

/**
 * @brief Establish connection to a WMI Registry service.
 *
 * @param[out] handle - A connection handle in case of success.
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_connect_reg (int argc, char **argv, WMI_HANDLE * handle)
{
  (void) argc;
  (void) argv;
  (void) handle;
  return -1;
}

/**
 * @brief Get Registry string value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry Hive
 *
 * @param[in] key - Registry key name
 *
 * @param[in] key_name - Registry value name.
 *
 * @param[out] res - Result string.
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_sz (WMI_HANDLE handle, unsigned int hive, const char *key,
                const char *key_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) key_name;
  (void) res;
  return -1;
}

/**
 * @brief Enumerate Registry values.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key name
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */

int
wmi_reg_enum_value (WMI_HANDLE handle, unsigned int hive, const char *key,
                    char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) res;
  return -1;
}

/**
 * @brief Enumerate Registry keys.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */

int
wmi_reg_enum_key (WMI_HANDLE handle, unsigned int hive, const char *key,
                  char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) res;
  return -1;
}

/**
 * @brief Get Registry binary value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key containing the value to be queried
 *
 * @param[in] val_name - Registry value to be queried
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_bin_val (WMI_HANDLE handle, unsigned int hive, const char *key,
                     const char *val_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) val_name;
  (void) res;
  return -1;
}

/**
 * @brief Get Registry DWORD value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key containing the value to be queried
 *
 * @param[in] val_name - Registry value to be queried
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_dword_val (WMI_HANDLE handle, unsigned int hive, const char *key,
                       const char *val_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) val_name;
  (void) res;
  return -1;
}

/**
 * @brief Get Registry Expanded string value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key containing the value to be queried
 *
 * @param[in] val_name - Registry value to be queried
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_ex_string_val (WMI_HANDLE handle, unsigned int hive,
                           const char *key, const char *val_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) val_name;
  (void) res;
  return -1;
}

/**
 * @brief Get Registry multi-valued strings.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key containing the value to be queried
 *
 * @param[in] val_name - Registry value to be queried
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_mul_string_val (WMI_HANDLE handle, unsigned int hive,
                            const char *key, const char *val_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) val_name;
  (void) res;
  return -1;
}

/**
 * @brief Get Registry QWORD value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] hive - Registry hive
 *
 * @param[in] key - Registry key containing the value to be queried
 *
 * @param[in] val_name - Registry value to be queried
 *
 * @param[out] res - Result string
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_get_qword_val (WMI_HANDLE handle, unsigned int hive, const char *key,
                       const char *val_name, char **res)
{
  (void) handle;
  (void) hive;
  (void) key;
  (void) val_name;
  (void) res;
  return -1;
}

/**

 * @brief Set Registry DWORD value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key containing the value to be set
 *
 * @param[in] val_name - Registry value to set
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_set_dword_val(WMI_HANDLE handle, const char *key, const char *val_name,
						uint32_t val)
{
  (void) handle;
  (void) key;
  (void) val_name;
  (void) val;
  return -1;
}

/**
 * @brief Set Registry QWORD value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key containing the value to be set
 *
 * @param[in] val_name - Registry value to set
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_set_qword_val(WMI_HANDLE handle, const char *key, const char *val_name,
						uint64_t val)
{
  (void) handle;
  (void) key;
  (void) val_name;
  (void) val;
  return -1;
}

/**
 * @brief Set Registry Expanded string value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key containing the value to be set
 *
 * @param[in] val_name - Registry value to set
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_set_ex_string_val(WMI_HANDLE handle, const char *key,
				 const char *val_name, const char *val)
{
  (void) handle;
  (void) key;
  (void) val_name;
  (void) val;
  return -1;
}

/**
 * @brief Set Registry string value.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key containing the value to be set
 *
 * @param[in] val_name - Registry value to set
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_set_string_val(WMI_HANDLE handle, const char *key,
				 const char *val_name, const char *val)
{
  (void) handle;
  (void) key;
  (void) val_name;
  (void) val;
  return -1;
}

/**
 * @brief Create Registry Key.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key need to be created
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_create_key(WMI_HANDLE handle, const char *key)
{
  (void) handle;
  (void) key;
  return -1;
}

/**
 * @brief Delete Registry Key.
 *
 * @param[in] handle - WMI connection handle
 *
 * @param[in] key - Registry key need to be Deleted
 *
 * @return, 0 on success, -1 on failure
 */
int
wmi_reg_delete_key(WMI_HANDLE handle, const char *key)
{
  (void) handle;
  (void) key;
  return -1;
}
