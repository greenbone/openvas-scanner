/* OpenVAS
* $Id$
* Description: Authentication manager.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
* as published by the Free Software Foundation
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

/*
 * This authentification scheme is BADLY written, and will NOT
 * be used in the future
 */

#include <openvas/misc/arglists.h>
#include <openvas/misc/network.h> /* for auth_printf */

#include "auth.h"
#include "log.h"

/**
 * @brief Checks if a user has the right to use openvassd.
 */
int
auth_check_user (struct arglist *globals, char *from, char *dname)
{
  char buf[255];

  auth_printf (globals, "User : ");
  auth_gets (globals, buf, 254);

  auth_printf (globals, "Password : ");
  auth_gets (globals, buf, 254);

  if (check_user (dname))
    {
#ifdef DEBUG
      log_write ("successful login from %s\n", from);
#endif
      return 1;
    }

  return 0;
}
