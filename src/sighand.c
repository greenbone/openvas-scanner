/* OpenVAS
* $Id$
* Description: Provides signal handling functions.
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

#include <signal.h>     /* for kill() */
#include <unistd.h>     /* for getpid() */
#include <errno.h>      /* for errno() */
#include <sys/wait.h>   /* for wait() */
#include <sys/socket.h> /* for shutdown() */
#include <execinfo.h>

#include "log.h"
#include "sighand.h"
#include "utils.h"
#include "string.h"

#include <openvas/base/pidfile.h>

/* do not leave a zombie, hanging around if possible */
void
let_em_die (int pid)
{
  int status;

  waitpid (pid, &status, WNOHANG);
}


void
make_em_die (int sig)
{
  /* number of times, the sig is sent at most */
  int n = 3;

  /* leave if we are session leader */
  if (getpgrp () != getpid ())
    return;

  /* quickly send signals and check the result */
  if (kill (0, sig) < 0)
    return;
  let_em_die (0);
  if (kill (0, 0) < 0)
    return;

  do
    {
      /* send the signal to everybody in the group */
      if (kill (0, sig) < 0)
        return;
      sleep (1);
      /* do not leave a zombie, hanging around if possible */
      let_em_die (0);
    }
  while (--n > 0);

  if (kill (0, 0) < 0)
    return;

  kill (0, SIGKILL);
  sleep (1);
  let_em_die (0);
}

/*
 *  Replacement for the signal() function, written
 *  by Sagi Zeevi <sagiz@yahoo.com>
 */
void (*openvas_signal (int signum, void (*handler) (int))) (int)
{
  struct sigaction saNew, saOld;

  /* Init new handler */
  sigfillset (&saNew.sa_mask);
  sigdelset (&saNew.sa_mask, SIGALRM);  /* make sleep() work */

  saNew.sa_flags = 0;
  saNew.sa_handler = handler;

  sigaction (signum, &saNew, &saOld);
  return saOld.sa_handler;
}


void
sighand_chld (pid_t pid)
{
  int status;

  waitpid (pid, &status, WNOHANG);
}

static void
print_trace ()
{
  void *array[10];
  int fd, ret = 0, left;
  char *message = "SIGSEGV occured !\n";

  fd = log_get_fd ();
  if (fd < 0)
    return;

  left = strlen (message);
  while (left)
    {
      ret = write (fd, message, left);
      if (ret == -1)
        {
          if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
          break;
        }
      left -= ret;
      message += ret;
    }
  ret = backtrace (array, 10);
  backtrace_symbols_fd (array, ret, fd);
}

void
sighand_segv (int given_signal)
{
  signal (SIGSEGV, _exit);
  print_trace ();
  make_em_die (SIGTERM);
  /* Raise signal again, to exit with the correct return value,
   * and to enable core dumping. */
  openvas_signal (given_signal, SIG_DFL);
  raise (given_signal);
}
