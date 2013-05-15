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

#include <string.h> /* for strlen() */
#include <stdlib.h> /* for exit() */

#include <stdarg.h>

#include <openvas/misc/arglists.h>
#include <openvas/misc/system.h>
#include <openvas/misc/network.h>

#include "auth.h"
#include "comm.h"
#include "log.h"
#include "rules.h"
#include "sighand.h"


/**
 * @brief Checks if a user has the right to use openvassd.
 */
int
auth_check_user (struct arglist *globals, char *from, char *dname)
{
  char *buf_user, *buf_password;
  int free_buf_user = 1;
  int success = 0;

  {
    int l;

    buf_user = emalloc (255);
    buf_password = emalloc (255);

    auth_printf (globals, "User : ");
    auth_gets (globals, buf_user, 254);
    if (buf_user[0] == '\0')
      {
        exit (0);
      }

    auth_printf (globals, "Password : ");
    auth_gets (globals, buf_password, 254);
    if (buf_password[0] == '\0')
      {
        exit (0);
      }

    l = strlen (buf_user);
    if (l && buf_user[l - 1] == '\n')
      buf_user[--l] = '\0';
    if (l && buf_user[l - 1] == '\r')
      buf_user[--l] = '\0';
  }

  if ((success = check_user (buf_user, dname)))
    {
      char *user = emalloc (strlen (buf_user) + 1);
      strncpy (user, buf_user, strlen (buf_user));

#ifdef DEBUG
      log_write ("successful login of %s from %s\n", buf_user, from);
#endif
      if (arg_get_value (globals, "user"))
        arg_set_value (globals, "user", strlen (user), user);
      else
        arg_add_value (globals, "user", ARG_STRING, strlen (user), user);
    }
  if (free_buf_user)
    efree (&buf_user);
  efree (&buf_password);
  return success;
}
