/* OpenVAS
* $Id$
* Description: Manages the launching of plugins within processes.
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

#include <stdio.h>    /* for perror() */
#include <unistd.h>   /* for close() */
#include <sys/wait.h> /* for waitpid() */
#include <strings.h>  /* for bzero() */
#include <errno.h>    /* for errno() */
#include <sys/time.h> /* for gettimeofday() */

#include "config.h"

#include <openvas/misc/network.h>    /* for internal_send */
#include <openvas/nvt_categories.h>  /* for ACT_SCANNER */
#include <openvas/misc/plugutils.h>  /* for INTERNAL_COMM_MSG_SHARED_SOCKET */
#include <openvas/misc/system.h>     /* for efree */

#include "pluginload.h"
#include "piic.h"
#include "utils.h"
#include "preferences.h"
#include "log.h"
#include "sighand.h"
#include "processes.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "shared_socket.h"

/**
 * @brief 'Hard' limit of the max. number of concurrent plugins per host.
 */
#define MAX_PROCESSES 32

#undef VERBOSE_LOGGING          /* This really fills your openvassd.messages */

#undef DEBUG_CONFLICTS

/**
 * @brief Structure to represent a process in the sense of a running NVT.
 */
struct running
{
  int pid;             /**< Process ID. */
  struct arglist *globals;   /**< 'Global' arglist. */
  struct kb_item **kb;       /**< Knowledge base for the currently tested host.*/
  char *name;
  struct scheduler_plugin *plugin;
  plugins_scheduler_t sched;
  struct timeval start;
  int timeout;               /**< Timeout after which to kill process
                              * (NVT preference). If -1, never kill. it*/
  int launch_status;
  int upstream_soc;
  int internal_soc;          /**< 'Input' socket for this process */
  int alive;                 /**< 0 if dead. */
};

static void read_running_processes ();
static void update_running_processes ();

static struct running processes[MAX_PROCESSES];
static int num_running_processes;
static int max_running_processes;
static int old_max_running_processes;
static struct arglist *non_simult_ports_list;


/**
 *
 * @param p  Process index in processes array (function refers to processes[p]).
 *
 * @return -1 if plugin died
 */
static int
process_internal_msg (int p)
{
  int e = 0;
  static char *buffer = NULL;
  static int bufsz = 0;
  int type = 0;

  e = internal_recv (processes[p].internal_soc, &buffer, &bufsz, &type);
  if (e < 0)
    {
      log_write ("Process %d seems to have died too early\n", processes[p].pid);
      processes[p].alive = 0;
      return -1;
    }

  if (type & INTERNAL_COMM_MSG_SHARED_SOCKET)
    e =
      shared_socket_process (processes[p].internal_soc, processes[p].pid,
                             buffer, type);
  else if (type & INTERNAL_COMM_MSG_TYPE_DATA)
    {
      if (processes[p].launch_status != LAUNCH_SILENT)
        e = internal_send (processes[p].upstream_soc, buffer, type);
      else
        e = 0;
    }
  else if (type & INTERNAL_COMM_MSG_TYPE_KB)
    {
      e = 0;
      kb_parse (processes[p].internal_soc, processes[p].globals,
                processes[p].kb, buffer, type);
    }
  else if (type & INTERNAL_COMM_MSG_TYPE_CTRL)
    {
      if (type & INTERNAL_COMM_CTRL_FINISHED)
        {
          kill (processes[p].pid, SIGTERM);
          processes[p].alive = 0;
        }
    }
  else
    log_write ("Received unknown message type %d\n", type);

  if (bufsz > 65535)
    efree (&buffer);

  return e;
}


/**
 * @param sig ignored.
 */
void
wait_for_children (int sig)
{
  int i;
  for (i = 0; i < MAX_PROCESSES; i++)
    {
      int ret;
      if (processes[i].pid != 0)
        {
          do
            {
              ret = waitpid (-1, NULL, WNOHANG);
            }
          while (ret < 0 && errno == EINTR);
        }
    }
}

/*
 * Signal management
 */
void
process_mgr_sighand_term (int sig)
{
  int i;

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          kill (processes[i].pid, SIGTERM);
          num_running_processes--;
          plugin_set_running_state (processes[i].sched, processes[i].plugin,
                                    PLUGIN_STATUS_DONE);
          close (processes[i].internal_soc);
          shared_socket_cleanup_process (processes[i].pid);
          bzero (&(processes[i]), sizeof (struct running));
        }
    }
  _exit (0);
}

/**
 *
 */
static void
update_running_processes ()
{
  int i;
  struct timeval now;
  int log_whole = 1;

  // Set i to first non-NULL process
  for (i = 0; (processes[i].globals == NULL) && i < MAX_PROCESSES; i++)
    ;

  if (i < MAX_PROCESSES)
    {
      struct arglist *prefs =
        arg_get_value (processes[i].globals, "preferences");
      log_whole = preferences_log_whole_attack (prefs);
    }

  gettimeofday (&now, NULL);

  if (num_running_processes == 0)
    return;

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          // If process dead or timed out
      /** @todo communicate, e.g. send log message. Stub:
       * internal_send (processes[i].upstream_soc, "SERVER <|> LOG <|> hostname <|> general/tcp <|> NVT was killed due to timeout (of %d seconds). <|> OID <|> SERVER\n", INTERNAL_COMM_MSG_TYPE_DATA);
       */
          if (processes[i].alive == 0
              || (processes[i].timeout > 0
                  && ((now.tv_sec - processes[i].start.tv_sec) >
                      processes[i].timeout)))
            {
              if (processes[i].alive)
                {
                  if (log_whole)
                    log_write ("%s (pid %d) is slow to finish - killing it\n",
                               processes[i].name, processes[i].pid);
                  terminate_process (processes[i].pid);
                  processes[i].alive = 0;
                }
              else
                {
                  struct timeval old_now = now;
                  int e;
                  if (now.tv_usec < processes[i].start.tv_usec)
                    {
                      processes[i].start.tv_sec++;
                      now.tv_usec += 1000000;
                    }
                  if (log_whole)
                    log_write
                      ("%s (process %d) finished its job in %ld.%.3ld seconds\n",
                       processes[i].name, processes[i].pid,
                       (long) (now.tv_sec - processes[i].start.tv_sec),
                       (long) ((now.tv_usec -
                                processes[i].start.tv_usec) / 1000));
                  now = old_now;
                  do
                    {
                      e = waitpid (processes[i].pid, NULL, 0);
                    }
                  while (e < 0 && errno == EINTR);

                }
              num_running_processes--;
              plugin_set_running_state (processes[i].sched, processes[i].plugin,
                                        PLUGIN_STATUS_DONE);

              close (processes[i].internal_soc);
              shared_socket_cleanup_process (processes[i].pid);
              bzero (&(processes[i]), sizeof (processes[i]));
            }
        }
    }
}

/**
 * If another NVT with same port requirements is running, wait.
 *
 * @return -1 if MAX_PROCESSES are running, the index of the first free "slot"
 *          in the processes array otherwise.
 */
static int
next_free_process (struct scheduler_plugin *upcoming)
{
  int r;

  wait_for_children (0);
  for (r = 0; r < MAX_PROCESSES; r++)
    {
      if (processes[r].pid > 0)
        {
          struct arglist *common_ports;
          if ((common_ports =
               requirements_common_ports (processes[r].plugin, upcoming)))
            {
              int do_wait = -1;
              if (common (common_ports, non_simult_ports_list))
                do_wait = r;
              arg_free (common_ports);
              if (do_wait >= 0)
                {
#ifdef DEBUG_CONFLICT
                  printf ("Waiting has been initiated...\n");
                  log_write ("Ports in common - waiting...\n");
#endif
                  while (process_alive (processes[r].pid))
                    {
                      read_running_processes ();
                      update_running_processes ();
                      wait_for_children (0);
                    }
#ifdef DEBUG_CONFLICT
                  printf ("End of the wait - was that long ?\n");
#endif
                }
            }
        }
    }

  // Find the last "living" process.
  r = 0;
  while ((r < MAX_PROCESSES) && (processes[r].pid > 0))
    r++;

  if (r >= MAX_PROCESSES)
    return -1;
  else
    return r;
}

/**
 *
 */
static void
read_running_processes ()
{
  int i;
  int flag = 0;
  struct timeval tv;
  fd_set rd;
  int max = 0;
  int e;

  if (num_running_processes == 0)
    return;

  FD_ZERO (&rd);
  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          FD_SET (processes[i].internal_soc, &rd);
          if (processes[i].internal_soc > max)
            max = processes[i].internal_soc;
        }
    }

  do
    {
      tv.tv_sec = 0;
      tv.tv_usec = 500000;
      e = select (max + 1, &rd, NULL, NULL, &tv);
    }
  while (e < 0 && errno == EINTR);

  if (e == 0)
    return;

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          flag++;
          if (FD_ISSET (processes[i].internal_soc, &rd) != 0)
            {
              int result = process_internal_msg (i);
              if (result)
                {
#ifdef DEBUG
                  log_write ("process_internal_msg for %s returned %d\n",
                             processes[i].name, result);
#endif
                }
            }
        }
    }

  if (flag == 0 && num_running_processes != 0)
    num_running_processes = 0;
}


void
pluginlaunch_init (struct arglist *globals)
{
  struct arglist *preferences = arg_get_value (globals, "preferences");
  non_simult_ports_list = arg_get_value (preferences, "non_simult_ports_list");
  max_running_processes = get_max_checks_number (globals, preferences);
  old_max_running_processes = max_running_processes;

  signal (SIGCHLD, wait_for_children);

  if (max_running_processes >= MAX_PROCESSES)
    {
      log_write
        ("max_checks (%d) > MAX_PROCESSES (%d) - modify openvas-scanner/openvassd/pluginlaunch.c\n",
         max_running_processes, MAX_PROCESSES);
      max_running_processes = MAX_PROCESSES - 1;
    }


  num_running_processes = 0;
  bzero (&(processes), sizeof (processes));
  openvas_signal (SIGTERM, process_mgr_sighand_term);
}

void
pluginlaunch_disable_parrallel_checks ()
{
  max_running_processes = 1;
}

void
pluginlaunch_enable_parrallel_checks ()
{
  max_running_processes = old_max_running_processes;
}


void
pluginlaunch_stop ()
{
  int i;
  read_running_processes ();

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        kill (processes[i].pid, SIGTERM);
    }

  usleep (20000);
  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          kill (processes[i].pid, SIGKILL);
          num_running_processes--;
          plugin_set_running_state (processes[i].sched, processes[i].plugin,
                                    PLUGIN_STATUS_DONE);
          close (processes[i].internal_soc);
          shared_socket_cleanup_process (processes[i].pid);
          bzero (&(processes[i]), sizeof (struct running));
        }
    }
  shared_socket_close ();
  openvas_signal (SIGTERM, _exit);
}


/**
 * @return PID of process that is connected to the plugin as returned by plugin
 *         classes pl_launch function (<=0 means there was a problem).
 */
int
plugin_launch (struct arglist *globals, plugins_scheduler_t * sched,
               struct scheduler_plugin *plugin, struct arglist *hostinfos,
               struct arglist *preferences, struct kb_item **kb, char *name,
               pl_class_t * launcher)
{
  int p;
  int dsoc[2];

  /* Wait for a free slot while reading the input from the plugins  */
  while (num_running_processes >= max_running_processes)
    {
      read_running_processes ();
      update_running_processes ();
    }

  p = next_free_process (plugin);
  processes[p].kb = kb;
  processes[p].globals = globals;
  processes[p].plugin = plugin;
  processes[p].sched = sched;
  processes[p].name = plugin->arglist->name;
  processes[p].launch_status = plug_get_launch (plugin->arglist->value);
  processes[p].timeout =
    preferences_plugin_timeout (preferences,
                                plug_get_oid (plugin->arglist->value));
  if (processes[p].timeout == 0)
    processes[p].timeout = plugin->timeout;


  // Disable timeout if NVT is a scanner, set it to preferences otherwise
  if (processes[p].timeout == 0)
    {
      int category = plugin->category;
      if (category == ACT_SCANNER)
        processes[p].timeout = -1;
      else
        processes[p].timeout = preferences_plugins_timeout (preferences);
    }

  if (socketpair (AF_UNIX, SOCK_STREAM, 0, dsoc) < 0)
    {
      perror ("pluginlaunch.c:plugin_launch:socketpair(1) ");
    }
  gettimeofday (&(processes[p].start), NULL);

  processes[p].upstream_soc = plugin_get_socket (plugin->arglist->value);
  processes[p].internal_soc = dsoc[0];
  plugin_set_socket (plugin->arglist->value, dsoc[1]);

  processes[p].pid =
    (*launcher->pl_launch) (globals, plugin->arglist->value, hostinfos,
                            preferences, kb, name);

  processes[p].alive = 1;
  close (dsoc[1]);
  if (processes[p].pid > 0)
    num_running_processes++;
  else
    plugin_set_running_state (processes[p].sched, processes[p].plugin,
                              PLUGIN_STATUS_UNRUN);

  return processes[p].pid;
}


/**
 * @brief Waits and 'pushes' processes until num_running_processes is 0.
 */
void
pluginlaunch_wait ()
{
  do
    {
      wait_for_children (0);
      read_running_processes ();
      update_running_processes ();
    }
  while (num_running_processes != 0);
}


/**
 * @brief Waits and 'pushes' processes until the number of running processes has
 *        changed.
 */
void
pluginlaunch_wait_for_free_process ()
{
  int num = num_running_processes;
  do
    {
      wait_for_children (0);
      read_running_processes ();
      update_running_processes ();
    }
  while (num_running_processes == num);
}
