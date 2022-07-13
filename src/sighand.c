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
 * @file sighand.c
 * @brief Provides a specialized signal handling.
 *
 * Expands standard signal handling by adding the possibility to chain handlers
 * for signals. This will allow to call several handlers for a single signal.
 * Additionally data can be provided for the handler to be called with. Some
 * keywords also allows to controll the flow of handlers and how many times a
 * handler will be called. When no handlers are added, each singlan will have
 * the default handler, except for SIGSEGV.
 */

#include "sighand.h"

#include "debug_utils.h"

#include <execinfo.h> /* for backtrace() */
#include <glib.h>     /* for G_LOG_DOMAIN, for g_critical() */
#include <signal.h>   /* for kill() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for getpid() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief struct to save information about a handler.
 *
 */
typedef struct handler_entry
{
  void (*handler) ();
  void *data;
  int stop;
  int n;
  struct handler_entry *next;
} handler_entry;

/**
 * @brief list of available signals and their handling chains
 *
 */
static handler_entry *signals[31];

/**
 * @brief
 *
 * @param signum
 * @param handler
 *
 *  Replacement for the signal() function, written
 *  by Sagi Zeevi <sagiz@yahoo.com>
 */
static void (*openvas_signal (int signum, void (*handler) (int))) (int)
{
  struct sigaction saNew, saOld;

  /* Init new handler */
  sigfillset (&saNew.sa_mask);

  saNew.sa_flags = 0;
  saNew.sa_handler = handler;

  sigaction (signum, &saNew, &saOld);
  return saOld.sa_handler;
}

/**
 * @brief Handles all signals by calling the specified handler chain.
 *
 * @param sig Incoming signal
 */
static void
signal_handler (int sig)
{
  handler_entry *current, *last = NULL, *buf;
  int stop;

  g_message ("Signal %d occurred", sig);
  current = signals[sig];

  while (current)
    {
      current->handler (current->data);
      stop = current->stop;
      if (current->n > 0)
        current->n--;
      buf = current;
      current = current->next;
      if (!buf->n)
        {
          if (last)
            {
              last->next = current;
            }
          else
            {
              signals[sig] = current;
            }
          free (buf);
        }
      else
        {
          last = buf;
        }
      if (stop)
        break;
    }

  if (!signals[sig])
    openvas_signal (sig, SIG_DFL);
}

/**
 * @brief Used to print backtrace in case of a SIGSEGV.
 *
 */
static void
print_trace ()
{
  void *array[10];
  int ret = 0, left;
  char *message = "SIGSEGV occurred!\n";
  char **strings;

  /*It used log_get_fd() in log.h to know where to log the backtrace.*/
  ret = backtrace (array, 10);
  strings = backtrace_symbols (array, ret);
  g_warning ("%s", message);

  for (left = 0; left < ret; left++)
    g_warning ("%s\n", strings[left]);

  g_free (strings);
}

/**
 * @brief handler for SIGSEGV
 *
 */
static void
sighand_segv ()
{
  print_trace ();
  gvm_close_sentry ();
}

/**
 * @brief Frees all handlers of a single signal
 *
 * @param sig signal
 */
static void
free_single_signal_handler (int sig)
{
  handler_entry *current, *next;
  current = signals[sig];
  signals[sig] = NULL;
  while (current)
    {
      next = current->next;
      free (current);
      current = next;
    }
  openvas_signal (sig, SIG_DFL);
}

/**
 * @brief Frees all handlers for all signals
 *
 */
static void
free_all_signal_handlers ()
{
  int i;

  for (i = 0; i < 31; i++)
    {
      free_single_signal_handler (i);
    }
  openvas_signal (SIGSEGV, sighand_segv);
}

/**
 * @brief Initializes signal handling. free_signal_handler must be called to
 * free resources again
 *
 */
void
init_signal_handlers ()
{
  int i;
  static int init = 0;

  if (init)
    return;

  init = 1;

  for (i = 0; i < 31; i++)
    {
      signals[i] = NULL;
    }
  openvas_signal (SIGSEGV, sighand_segv);
}

/**
 * @brief Resets a handler for a given Signal and frees resources. SIG_ALL will
 * reset all signal handler. Must be called in order to free resources.
 *
 * @param sig
 */
void
free_signal_handler (int sig)
{
  if (sig == OVAS_SIG_ALL)
    free_all_signal_handlers ();
  else
    free_single_signal_handler (sig);
}

/**
 * @brief Adds a handler to react to specified signal. Behavior can be modified.
 *
 * @param sig Specifies on which signal handler will be called
 * @param handler Will be called when specified Signal arrives
 * @param data Additional data with which the handler will be called
 * @param stop modifies behavior
 * @param n max number handler will be called
 *
 * This will add a handler for the specified signal. The added handler is added
 * at the beginning of the handler chain. This means the provided handler will
 * be called first when a signal arrives. In order for the handler to be able to
 * tidy up or process data, such can be provided. Each handler also consinst of
 * a behavior which determines the flow of action. If set to SIG_STOP no other
 * handler will be called after that. In order to prevent the default handler to
 * be called at least one handler must have this set. A handler with behavior
 * SIG_NONE will just call the next handler in chain.
 * All signals have the default handler by default.
 */
void
add_handler (int sig, void (*handler) (), void *data, int stop, int n)
{
  if (handler == SIG_IGN || handler == SIG_DFL)
    {
      free_single_signal_handler (sig);
      openvas_signal (sig, handler);
      return;
    }

  handler_entry *new;
  new = malloc (sizeof (handler_entry));
  new->data = data;
  new->handler = handler;
  new->stop = stop;
  new->n = n;
  new->next = signals[sig];

  signals[sig] = new;
  openvas_signal (sig, signal_handler);
}
