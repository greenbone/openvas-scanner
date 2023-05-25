/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file sighand.c
 * @brief Provides signal handling functions.
 */

#include "sighand.h"

#include "debug_utils.h"
#include "processes.h"

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
  sigdelset (&saNew.sa_mask, SIGALRM); /* make sleep() work */

  saNew.sa_flags = 0;
  saNew.sa_handler = handler;

  sigaction (signum, &saNew, &saOld);
  return saOld.sa_handler;
}

void
sighand_chld (int sig)
{
  (void) sig;
  // if we call multiple times waitpid it will disturb the attack loop.
  // therefore we cannot cleanup multiple ipc here
  waitpid (-1, NULL, WNOHANG);
}

static void
print_trace (void)
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

void
sighand_segv (int given_signal)
{
  print_trace ();
  make_em_die (SIGTERM);
  gvm_close_sentry ();
  /* Raise signal again, to exit with the correct return value,
   * and to enable core dumping. */
  openvas_signal (given_signal, SIG_DFL);
  raise (given_signal);
}
