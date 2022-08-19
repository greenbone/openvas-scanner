/* Portions Copyright (C) 2009-2022 Greenbone Networks GmbH
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

#include "debug_utils.h" /* for init_sentry() */
#include "sighand.h"

#include <errno.h>            /* for errno() */
#include <glib.h>             /* for g_error */
#include <gvm/base/logging.h> /* for gvm_log_lock/unlock() */
#include <gvm/util/mqtt.h>    /* for mqtt_reset() */
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

typedef struct proc_entry
{
  pid_t pid;
  int terminated;
} proc_entry;

static proc_entry *procs = NULL;
static int initialized = 0;
static int max_procs;
static int num_procs;

/**
 * @brief Function for handling SIGCHLD to clear procs
 *
 */
static void
clear_child ()
{
  if (!initialized)
    return;

  pid_t pid;
  // In case we receive multiple SIGCHLD at once
  while ((pid = waitpid (-1, NULL, WNOHANG)) > 0)
    {
      g_message ("Ending child with pid %d", pid);
      for (int i = 0; i < max_procs; i++)
        {
          if (procs[i].pid != pid)
            continue;
          procs[i].terminated = 1;
          num_procs--;
          break;
        }
    }
}

/**
 * @brief checks for empty space in process list
 *
 * @return int 1 if full, 0 when empty
 */
static int
max_procs_reached ()
{
  return num_procs == max_procs;
}

/**
 * @brief Cleans the process list and frees memory. This will not terminate
 * child processes. Is primarily used after fork.
 *
 */
static void
clean_procs ()
{
  initialized = 0;
  g_free (procs);
  procs = NULL;
}

/**
 * @brief Terminates a given process. If termination does not work, the process
 * will get killed. In case init_procs was called, only direct child processes
 * can be terminated
 *
 * @param pid id of the child process
 * @return int 0 on success, NOCHILD if child does not exist, NOINIT if not
 * initialized
 */
int
terminate_process (pid_t pid)
{
  if (initialized)
    {
      for (int i = 0; i < max_procs; i++)
        {
          if (procs[i].pid == pid)
            {
              kill (pid, SIGTERM);
              usleep (10000);
              if (!procs[i].terminated)
                kill (pid, SIGKILL);
              return 0;
            }
        }
      return NOCHILD;
    }
  else
    {
      kill (pid, SIGTERM);
      usleep (10000);
      if (waitpid (pid, NULL, WNOHANG))
        kill (pid, SIGKILL);
      return 0;
    }
}

/**
 * @brief This function terminates all processes spawned with create_process.
 * Calls terminate_child for each process active. In case init_procs was not
 * called this function does nothing.
 *
 */
void
procs_terminate_childs ()
{
  if (!initialized)
    return;

  for (int i = 0; i < max_procs; i++)
    {
      if (!procs[i].terminated)
        terminate_process (procs[i].pid);
    }
}

/**
 * @brief Handler for a termination signal. This will terminate all childs and
 * calls SIGTERM for itself afterwards.
 *
 */
static void
terminate ()
{
  if (!initialized)
    return;

  int tries = 5;
  procs_terminate_childs ();

  while (num_procs && tries--)
    {
      sleep (1);
    }

  clean_procs ();
  openvas_signal (SIGTERM, SIG_DFL);
  raise (SIGTERM);
}

/**
 * @brief Init procs, must be called once per process
 *
 * @param max
 */
void
procs_init (int max)
{
  procs = g_malloc (max * sizeof (proc_entry));
  for (int i = 0; i < max; i++)
    {
      procs[i].terminated = 1;
    }
  max_procs = max;
  num_procs = 0;
  openvas_signal (SIGCHLD, clear_child);
  openvas_signal (SIGTERM, terminate);
  initialized = 1;
}

static void
init_child_signal_handlers (void)
{
  /* SIGHUP is only for reloading main scanner process. */
  openvas_signal (SIGHUP, SIG_IGN);
  openvas_signal (SIGSEGV, sighand_segv);
  openvas_signal (SIGPIPE, SIG_IGN);
}

/**
 * @brief Calls a function with a new process
 *
 * @param func Function to call
 * @param args arguments
 * @return pid of spawned process on success or one of the following errors:
 * FORKFAILED, NOINIT, PROCSFULL
 */
pid_t
create_process (process_func_t func, void *args)
{
  int pos = -1;
  if (initialized)
    {
      if (max_procs_reached ())
        return PROCSFULL;

      while (!procs[++pos].terminated)
        ;
    }
  pid_t pid = fork ();
  if (!pid)
    {
      initialized = 0;
      usleep (1000);
      init_child_signal_handlers ();
      clean_procs ();
      mqtt_reset ();
      init_sentry ();
      srand48 (getpid () + getppid () + (long) time (NULL));
      (*func) (args);
      gvm_close_sentry ();
      _exit (0);
    }

  if (pid < 0)
    {
      return FORKFAILED;
    }
  if (initialized)
    {
      procs[pos].pid = pid;
      procs[pos].terminated = 0;
      num_procs++;
    }
  return pid;
}
