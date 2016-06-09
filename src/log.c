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

static FILE *log = NULL;

/**
 * @brief Initialization of the log file.
 */
void
log_init (const char *filename)
{
  if ((!filename) || (!strcmp (filename, "stderr")))
    log = stderr;
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
      log = fdopen (fd, "a");
      if (log == NULL)
        {
          perror ("fdopen ");
          log = stderr;
        }

      setlinebuf (log);
    }
}


/**
 * @brief Get the open log file descriptor.
 *
 * @param[out]   Return the log file descriptor.
 */
int
log_get_fd ()
{
  return log ? fileno (log) : -1;
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


/**
 * @brief Write into the logfile / syslog using a va_list.
 *
 * @param[in]   str     Format string.
 * @param[in]   arg_ptr String parameters.
 */
void
log_vwrite (const char *str, va_list arg_ptr)
{
  char *tmp;
  char timestr[255];
  time_t t;

  if (log == NULL)
    {
      vsyslog (LOG_NOTICE, str, arg_ptr);
      return;
    }

  t = time (NULL);
  tmp = ctime (&t);

  timestr[sizeof (timestr) - 1] = '\0';
  strncpy (timestr, tmp, sizeof (timestr) - 1);
  timestr[strlen (timestr) - 1] = '\0';
  fprintf (log, "[%s][%d] ", timestr, getpid ());
  vfprintf (log, str, arg_ptr);
  fprintf (log, "\n");
}

/**
 * @brief Write into the logfile / syslog.
 *
 * @param[in]   str Format string, followed by the corresponding parameters if
 *                  any.
 */
void
log_write (const char *str, ...)
{
  va_list param;

  va_start (param, str);
  log_vwrite (str, param);
  va_end (param);
}
