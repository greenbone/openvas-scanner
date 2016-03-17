/* OpenVAS
* $Id$
* Description: Creates new threads.
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

#include <signal.h>   /* for kill() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for fork() */
#include <errno.h>    /* for errno() */
#include <time.h>     /* for time() */
#include <string.h>   /* for strerror() */
#include <stdlib.h>   /* for exit() */

#include <setjmp.h>
#include "processes.h"
#include "sighand.h"
#include "log.h"


int
terminate_process (pid_t pid)
{
  int ret;

  if (pid <= 0)
    return 0;

  ret = kill (pid, SIGTERM);

  if (ret == 0)
    {
      usleep (1000);
      if (waitpid (pid, NULL, WNOHANG) >= 0)
        kill (pid, SIGKILL);
    }
  return -1;
}

static void
init_child_signal_handlers ()
{
  /* SIGHUP is only for reloading main scanner process. */
  openvas_signal (SIGHUP, SIG_IGN);
  openvas_signal (SIGTERM, make_em_die);
  openvas_signal (SIGINT, make_em_die);
  openvas_signal (SIGQUIT, make_em_die);
  openvas_signal (SIGSEGV, sighand_segv);
  openvas_signal (SIGPIPE, SIG_IGN);
}

/**
 * @brief Create a new process (fork).
 */
pid_t
create_process (process_func_t function, void *argument)
{
  int pid;

  pid = fork ();

  if (pid == 0)
    {
      init_child_signal_handlers ();
      srand48 (getpid () + getppid () + (long) time (NULL));
      (*function) (argument);
      exit (0);
    }
  if (pid < 0)
    log_write ("Error : could not fork ! Error : %s", strerror (errno));
  return pid;
}
