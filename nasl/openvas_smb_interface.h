/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file openvas_smb_interface.h
 * @brief API protos describing the interface of a smb interface implementation.
 *
 * This file contains API protos describing the interface of a smb
 * interface implementation.
 */

#ifndef NASL_OPENVAS_SMB_INTERFACE_H
#define NASL_OPENVAS_SMB_INTERFACE_H

typedef long int SMB_HANDLE;

char *
smb_versioninfo (void);
int
smb_connect (const char *, const char *, const char *, const char *,
             SMB_HANDLE *);
int smb_close (SMB_HANDLE);
char *
smb_file_SDDL (SMB_HANDLE, const char *);
char *
smb_file_OwnerSID (SMB_HANDLE, const char *);
char *
smb_file_GroupSID (SMB_HANDLE, const char *);
char *
smb_file_TrusteeRights (SMB_HANDLE, const char *);

#endif
