/* OpenVAS
* $Id$
* Description: Provides a user authentication mechanism.
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

#include <stdio.h>      /* for fopen() */
#include <string.h>     /* for strchr() */

#include "log.h"        /* for log_write() */

int
check_user (char *dname)
{
  FILE *f;
  int success = 0;

  if (dname != NULL && *dname != '\0')
    {
      if ((f = fopen (OPENVAS_STATE_DIR "/dname", "r")) == NULL)
        perror (OPENVAS_STATE_DIR "/dname");
      else
        {
          char dnameref[512], *p;

          while (! success
                 && fgets (dnameref, sizeof (dnameref) - 1, f) != NULL)
            {
              if ((p = strchr (dnameref, '\n')) != NULL)
                *p = '\0';
              if (strcmp (dname, dnameref) == 0)
                success = 1;
            }
          if (! success)
            log_write
              ("check_user: Bad DN\nGiven DN=%s\nLast tried DN=%s\n",
               dname, dnameref);
          (void) fclose (f);
        }
    }

  return success;
}
