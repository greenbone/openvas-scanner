/* Copyright (C) 2009-2022 Greenbone Networks GmbH
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
 * @file openvas_smb_interface.h
 * @brief API protos describing the interface of a smb interface implementation.
 *
 * This file contains API protos describing the interface of a smb
 * interface implementation.
 */

#ifndef _NASL_OPENVAS_SMB_INTERFACE_H
#define _NASL_OPENVAS_SMB_INTERFACE_H

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
int
wincmd (int argc, char *argv[], char **res);

#endif
