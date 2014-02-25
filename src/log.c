/* OpenVAS
* $Id$
* Description: Manages the logfile of OpenVAS.
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

#include <string.h>   /* for strchr() */
#include <stdio.h>    /* for fprintf() */
#include <fcntl.h>    /* for open() */
#include <unistd.h>   /* for close() */
#include <errno.h>    /* for errno() */
#include <sys/stat.h> /* for stat() */
#include <time.h>     /* for time() */

#include <stdarg.h>
#include <syslog.h>
#include "comm.h"
#include "utils.h"
#include "log.h"

static FILE *log;

/**
 * @brief Initialization of the log file.
 */
void
log_init (const char *filename)
{
  if ((!filename) || (!strcmp (filename, "stderr")))
    {
      log = stderr;
      dup2 (2, 3);
    }
  else if (!strcmp (filename, "syslog"))
    {
      openlog ("openvassd", 0, LOG_DAEMON);
      log = NULL;
    }

  else
    {
      int fd = open (filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (fd < 0)
        {
          fprintf (stderr, "log_init():open : %s\n", strerror (errno));
          fprintf (stderr, "Could not open the logfile, using stderr\n");
          log = stderr;
        }

      if (fd != 3)
        {
          if (dup2 (fd, 3) < 0)
            {
              perror ("dup2 ");
            }
          close (fd);
        }

      log = fdopen (3, "a");
      if (log == NULL)
        {
          perror ("fdopen ");
          log = stderr;
          dup2 (2, 3);
        }

      setlinebuf (log);
    }
}



void
log_close ()
{
  if (log != NULL)
    {
      log_write ("closing logfile");
      fclose (log);
      log = NULL;
    }
  else
    closelog ();
}


/*
 * write into the logfile using a va_list.
 * Nothing fancy here...
 */
void
log_vwrite (const char *str, va_list arg_ptr)
{
  char disp[4096];
  char *tmp;

  vsnprintf (disp, sizeof (disp), str, arg_ptr);

  tmp = disp;
  while ((tmp = (char *) strchr (tmp, '\n')) != NULL)
    tmp[0] = ' ';


  if (log != NULL)
    {
      char timestr[255];
      time_t t;

      t = time (NULL);
      tmp = ctime (&t);

      timestr[sizeof (timestr) - 1] = '\0';
      strncpy (timestr, tmp, sizeof (timestr) - 1);
      timestr[strlen (timestr) - 1] = '\0';
      fprintf (log, "[%s][%d] %s\n", timestr, getpid (), disp);
    }
  else
    syslog (LOG_NOTICE, "%s", disp);
}

/*
 * write into the logfile
 * Nothing fancy here...
 */
void
log_write (const char *str, ...)
{
  va_list param;

  va_start (param, str);
  log_vwrite (str, param);
  va_end (param);
}
