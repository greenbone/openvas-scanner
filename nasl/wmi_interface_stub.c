/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file wmi_interface_stub.c
 * @brief Stub implementation for a wmi interface.
 *
 * This file contains an empty implementation that
 * fulfills the wmi interface specfified in \ref openvas_wmi_interface.h
 */

/* for NULL */
#include "openvas_wmi_interface.h"

#include <string.h>

/**
 * @brief Return version info for WMI implementation.
 *
 * @return NULL if this the implementation is a non-functional stub,
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
 * @param[in] argc  Number of arguments.
 *
 * @param[in] argv  Array of arguments.
 *
 * @return, WMI_HANDLE on success, NULL on failure.
 */
WMI_HANDLE
wmi_connect (int argc, char **argv)
{
  (void) argc;
  (void) argv;
  return NULL;
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
 * @param[in] argc  Number of arguments.
 *
 * @param[in] argv  Array of arguments.
 *
 * @return, WMI_HANDLE on success, NULL on failure.
 */
WMI_HANDLE
wmi_connect_rsop (int argc, char **argv)
{
  (void) argc;
  (void) argv;
  return NULL;
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
 * @param[in] argc  Number of arguments.
 *
 * @param[in] argv  Array of arguments.
 *
 * @return, WMI_HANDLE on success, NULL on failure.
 */
WMI_HANDLE
wmi_connect_reg (int argc, char **argv)
{
  (void) argc;
  (void) argv;
  return NULL;
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
wmi_reg_set_dword_val (WMI_HANDLE handle, const char *key, const char *val_name,
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
wmi_reg_set_qword_val (WMI_HANDLE handle, const char *key, const char *val_name,
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
wmi_reg_set_ex_string_val (WMI_HANDLE handle, const char *key,
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
wmi_reg_set_string_val (WMI_HANDLE handle, const char *key,
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
wmi_reg_create_key (WMI_HANDLE handle, const char *key)
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
wmi_reg_delete_key (WMI_HANDLE handle, const char *key)
{
  (void) handle;
  (void) key;
  return -1;
}
