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

// holds all used ipc_contexts; it will be initialized and managed by
// create_ipc_process.
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
 * @brief iterates through ipcc and verify if a child is stopped or killed to
 * free the file handler.
 * @return the amount of freed file handler or -1 on ipcc not initialized
 */
static int
close_ipc_fd_on_unnoticed_exit ()
{
  int freed = 0, i, status;
  pid_t pid;
  if (ipcc == NULL)
    return -1;
  g_debug ("%s: checking %d ipc.", __func__, ipcc->len);
  for (i = 0; i < ipcc->len; i++)
    {
      if (ipcc->ctxs[i].closed)
        {
          continue;
        }
      pid = waitpid (ipcc->ctxs[i].pid, &status, WNOHANG);
      if ((pid < 0)
          || ((pid == ipcc->ctxs[i].pid)
              && (WIFEXITED (status) || WIFSTOPPED (status)
                  || WIFSIGNALED (status))))
        {
          freed++;
          ipc_close (&ipcc->ctxs[i]);
        }
    }
  return freed;
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

static void
reuse_or_add_context (struct ipc_context *ctx)
{
  if (ipcc == NULL)
    return;
  for (int i = 0; i < ipcc->len; i++)
    {
      if (ipcc->ctxs[i].closed == 1)
        {
          ipcc->ctxs[i].context = ctx->context;
          ipcc->ctxs[i].pid = ctx->pid;
          ipcc->ctxs[i].relation = ctx->relation;
          ipcc->ctxs[i].type = ctx->type;
          ipcc->ctxs[i].closed = 0;
          return;
        }
    }
  ipc_add_context (ipcc, ctx);
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
  pid_t child_pid;
  // previously init call, we want to store the contexts without making
  // assumptions about signal handlung
  if (ipcc == NULL)
    ipcc = ipc_contexts_init (0);

  ec.pre_func = (ipc_process_func) &pre_fork_fun_call;
  ec.post_func = (ipc_process_func) &post_fork_fun_call;
  ec.func = (ipc_process_func) func;
  ec.func_arg = args;
  ec.parent = getpid ();
  // check for exited processes and clean file descriptor
  // we do it twice, before forking and when forking fails with EMFILE or EAGAIN
  g_debug ("%s: closed %d fd due to premature exit.", __func__,
           close_ipc_fd_on_unnoticed_exit ());
retry:
  if ((pctx = ipc_exec_as_process (IPC_PIPE, ec)) == NULL)
    {
      if (errno == EMFILE || errno == EAGAIN)
        {
          g_debug (
            "%s: could not fork: %s (%d) retrying after trying to close fd.",
            __func__, strerror (errno), errno);
          g_debug ("%s: closed %d fd due to premature exit.", __func__,
                   close_ipc_fd_on_unnoticed_exit ());
          goto retry;
        }
      g_warning ("%s: could not fork: %s (%d)", __func__, strerror (errno),
                 errno);
      return FORKFAILED;
    }
  reuse_or_add_context (pctx);
  child_pid = pctx->pid;
  // ipcc works uses copies of pctx therefore we free it
  free (pctx);
  return child_pid;
}

/**
 * @brief returns ipc_contexts.
 *
 * @return the globally hold array of all ipc_context; do not manipulate them.
 */
const struct ipc_contexts *
procs_get_ipc_contexts (void)
{
  return ipcc;
}
