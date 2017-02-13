/* OpenVAS
 *
 * $Id$
 * Description: Stub implementation for a smb interface.
 *
 * Authors:
 * Chandrashekhar B <bchandra@secpod.com>
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
 * @file smb_interface_stub.c
 * @brief Stub implementatin for SMB interface.
 *
 * This file contains an empty implementation that
 * fulfills the SMB interface specfified in \ref openvas_smb_interface.h
 */

/* for NULL */
#include <string.h>

#include "openvas_smb_interface.h"

/**
 * @brief Return version info for SMB implementation.
 *
 * @return NULL if this the impementation is a non-functional stub,
 *         else a arbitrary string that explains the version of the
 *         implementation.
 */
char *
smb_versioninfo ()
{
  return NULL;
}

/**
 * @brief Establish connection to a SMB service.
 *
 * @param[in] server - The host system to connect to
 *
 * @param[in] share - The file system share.
 *
 * @param[in] username - The username for getting access to SMB service
 *
 * @param[in] password - The password that corresponds to username
 *
 * @param[out] con - A connection handle in case of success.
 *
 * @return, 0 on success, -1 on failure
 */
int smb_connect(const char *server, const char *share,
                const char *username, const char *password,
                SMB_HANDLE *con)
{
  (void) server;
  (void) share;
  (void) username;
  (void) password;
  (void) con;
  return -1;
}

/**
 * @brief Close the connection handle for SMB service.
 *
 * @param[in] handle - SMB connection handle
 *
 * @return, 0 on success, -1 on failure
 */
int smb_close(SMB_HANDLE handle)
{
  (void) handle;
  return -1;
}

/**
 * @brief Obtain Windows file rights in SDDL format
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Security Descriptor in SDDL format on success, NULL on failure.
 */
char *smb_file_SDDL(SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Obtain the SID of the Owner for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Owner SID string on success, NULL on failure.
 */
char *smb_file_OwnerSID(SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}


/**
 * @brief Obtain the SID of the Group for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Group SID string on success, NULL on failure.
 */
char *smb_file_GroupSID(SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Obtain the Trustee SID and their rights for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Trustee SID:Access_Mask string on success, NULL on failure.
 */
char *smb_file_TrusteeRights(SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Command Execution in Windows
 *
 * @param[in] argc - Connection strings
 *
 * @param[in] argv - Number of arguments
 *
 * @return, 0 on success, -1 on failure
 */
int
wincmd(int argc, char *argv[], char **res)
{
  (void) argc;
  (void) argv;
  (void) res;
  return -1;
}
