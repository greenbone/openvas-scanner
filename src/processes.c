/* Portions Copyright (C) 2009-2021 Greenbone Networks GmbH
 * Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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
 * @file processes.c
 * @brief Creates new threads.
 */

#include "processes.h"

#include "sighand.h"

#include <errno.h>            /* for errno() */
#include <glib.h>             /* for g_error */
#include <gvm/base/logging.h> /* for gvm_log_lock/unlock() */
#include <setjmp.h>
#include <signal.h>   /* for kill() */
#include <stdlib.h>   /* for exit() */
#include <string.h>   /* for strerror() */
#include <sys/wait.h> /* for waitpid() */
#include <time.h>     /* for time() */
#include <unistd.h>   /* for fork() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Send SIGTERM to the pid process. Try to wait the
 * the process. In case of the process has still not change
   the state, it sends SIGKILL to the process and must be waited
   later to avoid leaving a zombie process

   @param[in] pid Process id to terminate.

   @return 0 on success, -1 if the process was waited but not changed
   the state
 */
int
terminate_process (pid_t pid)
{
  int ret;

  if (pid == 0)
    return 0;

  ret = kill (pid, SIGTERM);

  if (ret == 0)
    {
      usleep (1000);

      if (waitpid (pid, NULL, WNOHANG) >= 0)
        {
          kill (pid, SIGKILL);
          return -1;
        }
    }

  return 0;
}

static void
init_child_signal_handlers (void)
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

  gvm_log_lock ();
  pid = fork ();
  gvm_log_unlock ();

  if (pid == 0)
    {
      init_child_signal_handlers ();
      srand48 (getpid () + getppid () + (long) time (NULL));
      (*function) (argument);
      exit (0);
    }
  if (pid < 0)
    g_error ("Error : could not fork ! Error : %s", strerror (errno));
  return pid;
}
