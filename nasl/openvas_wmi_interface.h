/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file openvas_wmi_interface.h
 * @brief API protos describing the interface of a wmi interface implementation.
 *
 * This file contains API protos describing the interface of a wmi
 * interface implementation.
 */

#ifndef NASL_OPENVAS_WMI_INTERFACE_H
#define NASL_OPENVAS_WMI_INTERFACE_H

#include <stdint.h> /* for uint32_t, uint64_t */

typedef void *WMI_HANDLE;

char *
wmi_versioninfo (void);
WMI_HANDLE
wmi_connect (int argc, char **argv);
int wmi_close (WMI_HANDLE);
int
wmi_query (WMI_HANDLE, const char *, char **);

WMI_HANDLE
wmi_connect_rsop (int argc, char **argv);
int
wmi_query_rsop (WMI_HANDLE, const char *, char **);

WMI_HANDLE
wmi_connect_reg (int argc, char **argv);
int
wmi_reg_get_sz (WMI_HANDLE, unsigned int, const char *, const char *, char **);
int
wmi_reg_enum_value (WMI_HANDLE, unsigned int, const char *, char **);
int
wmi_reg_enum_key (WMI_HANDLE, unsigned int, const char *, char **);
int
wmi_reg_get_bin_val (WMI_HANDLE, unsigned int, const char *, const char *,
                     char **);
int
wmi_reg_get_dword_val (WMI_HANDLE, unsigned int, const char *, const char *,
                       char **);
int
wmi_reg_get_ex_string_val (WMI_HANDLE, unsigned int, const char *, const char *,
                           char **);
int
wmi_reg_get_mul_string_val (WMI_HANDLE, unsigned int, const char *,
                            const char *, char **);
int
wmi_reg_get_qword_val (WMI_HANDLE, unsigned int, const char *, const char *,
                       char **);
int
wmi_reg_set_dword_val (WMI_HANDLE, const char *, const char *, uint32_t);
int
wmi_reg_set_qword_val (WMI_HANDLE, const char *, const char *, uint64_t);
int
wmi_reg_set_ex_string_val (WMI_HANDLE, const char *, const char *,
                           const char *);
int
wmi_reg_set_string_val (WMI_HANDLE, const char *, const char *, const char *);
int
wmi_reg_create_key (WMI_HANDLE, const char *);

int
wmi_reg_delete_key (WMI_HANDLE, const char *);

#endif
