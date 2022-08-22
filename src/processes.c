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

static struct ipc_contexts *ipcc = NULL;

/**
 * @brief Function for handling SIGCHLD to clear procs
 *
 */
static void
clear_child ()
{
  if (ipcc == NULL)
    return;

  pid_t pid;
  // In case we receive multiple SIGCHLD at once
  while ((pid = waitpid (-1, NULL, WNOHANG)) > 0)
    {
      g_message ("Ending child with pid %d", pid);
      for (int i = 0; i < ipcc->len; i++)
        {
          // skip when it is set to NULL or not the wanted pid
          if (ipcc->ctxs[i].pid != pid)
            continue;
          if (ipcc->ctxs[i].closed == 0)
            ipc_close (&ipcc->ctxs[i]);
          break;
        }
    }
}

/**
 * @brief Cleans the process list and frees memory. This will not terminate
 * child processes. Is primarily used after fork.
 *
 */
static void
clean_procs ()
{
  ipc_destroy_contexts (ipcc);
  ipcc = NULL;
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
  if (ipcc != NULL)
    {
      for (int i = 0; i < ipcc->len; i++)
        {
          if (ipcc->ctxs[i].pid == pid)
            {
              kill (pid, SIGTERM);
              usleep (10000);
              if (!ipcc->ctxs[i].closed)
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
  if (ipcc != NULL)
    return;

  for (int i = 0; i < ipcc->len; i++)
    {
      if (!ipcc->ctxs[i].closed)
        terminate_process (ipcc->ctxs[i].pid);
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
  procs_terminate_childs ();

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
  ipcc = ipc_contexts_init (max);
  openvas_signal (SIGCHLD, clear_child);
  openvas_signal (SIGTERM, terminate);
  openvas_signal (SIGINT, terminate);
  openvas_signal (SIGQUIT, terminate);
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

static void
pre_fork_fun_call (struct ipc_context *ctx, void *args)
{
  (void) ctx;
  (void) args;
  // in a chuld we clean up every preexisting context
  ipc_destroy_contexts (ipcc);
  ipcc = ipc_contexts_init (0);
  g_debug ("%s: called", __func__);
  usleep (1000);
  init_child_signal_handlers ();
  clean_procs ();
  mqtt_reset ();
  init_sentry ();
  srand48 (getpid () + getppid () + (long) time (NULL));
  g_debug ("%s: exit", __func__);
}

static void
post_fork_fun_call (struct ipc_context *ctx, void *args)
{
  (void) ctx;
  (void) args;
  g_debug ("%s: called", __func__);
  gvm_close_sentry ();
}

/**
 * @brief initializes a communication channels and calls a function with a new
 * process
 *
 * @param func Function to call
 * @param args arguments
 * @return pid of spawned process on success or one of the following errors:
 * FORKFAILED
 */
pid_t
create_ipc_process (ipc_process_func func, void *args)
{
  struct ipc_context *pctx = NULL;
  struct ipc_exec_context ec;
  // previously init call, we want to store the contexts without making
  // assumptions about signal handlung
  if (ipcc == NULL)
    ipcc = ipc_contexts_init (0);

  ec.pre_func = (ipc_process_func) &pre_fork_fun_call;
  ec.post_func = (ipc_process_func) &post_fork_fun_call;
  ec.func = (ipc_process_func) func;
  ec.func_arg = args;
  if ((pctx = ipc_exec_as_process (IPC_PIPE, &ec)) == NULL)
    {
      g_warning ("Error : could not fork ! Error : %s", strerror (errno));
      return FORKFAILED;
    }
  ipc_add_context (ipcc, pctx);
  return pctx->pid;
}

const struct ipc_contexts *
procs_get_ipc_contexts (void)
{
  return ipcc;
}
