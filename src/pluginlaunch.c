/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @file pluginlaunch.c
 * @brief Manages the launching of plugins within processes.
 */

#include "pluginlaunch.h"

#include "../misc/network.h"
#include "../misc/nvt_categories.h" /* for ACT_SCANNER */
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"

#include <errno.h>          /* for errno() */
#include <gvm/base/prefs.h> /* for prefs_get_bool() */
#include <gvm/util/nvticache.h>
#include <stdio.h>  /* for perror() */
#include <stdlib.h> /* for atoi() */
#include <string.h>
#include <strings.h>  /* for bzero() */
#include <sys/time.h> /* for gettimeofday() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for close() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief 'Hard' limit of the max. number of concurrent plugins per host.
 */
#define MAX_PROCESSES 32

/**
 * @brief Structure to represent a process in the sense of a running NVT.
 */
struct running
{
  struct scheduler_plugin *plugin;
  struct timeval start;
  pid_t pid;   /**< Process ID. */
  int timeout; /**< Timeout after which to kill process
                * (NVT preference). If -1, never kill. it*/
};

static struct running processes[MAX_PROCESSES];
static int num_running_processes;
static int max_running_processes;
static int old_max_running_processes;
static GSList *non_simult_ports = NULL;
const char *hostname = NULL;

/**
 *
 */
static void
update_running_processes (kb_t kb)
{
  int i;
  struct timeval now;
  int log_whole = prefs_get_bool ("log_whole_attack");

  if (num_running_processes == 0)
    return;

  gettimeofday (&now, NULL);
  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          int is_alive = process_alive (processes[i].pid);
          int ret_terminate = 0;

          // If process dead or timed out
          if (!is_alive
              || (processes[i].timeout > 0
                  && ((now.tv_sec - processes[i].start.tv_sec)
                      > processes[i].timeout)))
            {
              char *oid = processes[i].plugin->oid;

              if (is_alive)
                {
                  char msg[2048];

                  if (log_whole)
                    g_message ("%s (pid %d) is slow to finish - killing it",
                               oid, processes[i].pid);

                  sprintf (msg,
                           "ERRMSG||| |||general/tcp|||%s|||"
                           "NVT timed out after %d seconds.",
                           oid ?: " ", processes[i].timeout);
                  kb_item_push_str (kb, "internal/results", msg);

                  ret_terminate = terminate_process (processes[i].pid);
                  if (ret_terminate == 0)
                    {
                      terminate_process (processes[i].pid * -1);
                      num_running_processes--;
                      processes[i].plugin->running_state = PLUGIN_STATUS_DONE;
                      bzero (&(processes[i]), sizeof (processes[i]));
                    }
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
                    {
                      char *name = nvticache_get_filename (oid);
                      g_message (
                        "%s (%s) [%d] finished its job in %ld.%.3ld seconds",
                        name, oid, processes[i].pid,
                        (long) (now.tv_sec - processes[i].start.tv_sec),
                        (long) ((now.tv_usec - processes[i].start.tv_usec)
                                / 1000));
                      g_free (name);
                    }
                  now = old_now;
                  do
                    {
                      e = waitpid (processes[i].pid, NULL, 0);
                    }
                  while (e < 0 && errno == EINTR);

                  terminate_process (processes[i].pid * -1);
                  num_running_processes--;
                  processes[i].plugin->running_state = PLUGIN_STATUS_DONE;
                  bzero (&(processes[i]), sizeof (processes[i]));
                }
            }
        }
    }
}

static int
common (GSList *list1, GSList *list2)
{
  if (!list1 || !list2)
    return 0;

  while (list1)
    {
      GSList *tmp = list2;
      while (tmp)
        {
          if (!strcmp (list1->data, tmp->data))
            return 1;
          tmp = tmp->next;
        }
      list1 = list1->next;
    }
  return 0;
}

static GSList *
required_ports_in_list (const char *oid, GSList *list)
{
  GSList *common_ports = NULL;
  char **array, *ports;
  int i;

  if (!oid || !list)
    return 0;
  ports = nvticache_get_required_ports (oid);
  if (!ports)
    return 0;
  array = g_strsplit (ports, ", ", 0);
  g_free (ports);
  if (!array)
    return 0;

  for (i = 0; array[i]; i++)
    {
      GSList *tmp = list;
      while (tmp)
        {
          if (!strcmp (tmp->data, array[i]))
            common_ports = g_slist_prepend (common_ports, g_strdup (tmp->data));
          tmp = tmp->next;
        }
    }

  g_strfreev (array);
  return common_ports;
}

static int
simult_ports (const char *oid, const char *next_oid)
{
  int ret = 0;
  GSList *common_ports1 = NULL, *common_ports2 = NULL;

  common_ports1 = required_ports_in_list (oid, non_simult_ports);
  if (common_ports1)
    common_ports2 = required_ports_in_list (next_oid, non_simult_ports);
  if (common_ports1 && common_ports2 && common (common_ports1, common_ports2))
    ret = 1;
  g_slist_free_full (common_ports1, g_free);
  g_slist_free_full (common_ports2, g_free);
  return ret;
}

/**
 * If another NVT with same port requirements is running, wait.
 *
 * @return -1 if MAX_PROCESSES are running, the index of the first free "slot"
 *          in the processes array otherwise.
 */
static int
next_free_process (kb_t kb, struct scheduler_plugin *upcoming)
{
  int r;

  for (r = 0; r < MAX_PROCESSES; r++)
    {
      if (processes[r].pid > 0
          && simult_ports (processes[r].plugin->oid, upcoming->oid))
        {
          while (process_alive (processes[r].pid))
            {
              update_running_processes (kb);
              usleep (250000);
            }
        }
    }
  for (r = 0; r < MAX_PROCESSES; r++)
    if (processes[r].pid <= 0)
      return r;
  return -1;
}

void
pluginlaunch_init (const char *host)
{
  int i;

  char **split = g_strsplit (prefs_get ("non_simult_ports"), ", ", 0);
  for (i = 0; split[i]; i++)
    non_simult_ports = g_slist_prepend (non_simult_ports, g_strdup (split[i]));
  g_strfreev (split);
  max_running_processes = get_max_checks_number ();
  old_max_running_processes = max_running_processes;
  hostname = host;

  if (max_running_processes >= MAX_PROCESSES)
    {
      g_debug ("max_checks (%d) > MAX_PROCESSES (%d) - modify "
               "openvas/openvas/pluginlaunch.c",
               max_running_processes, MAX_PROCESSES);
      max_running_processes = MAX_PROCESSES - 1;
    }

  num_running_processes = 0;
  bzero (&(processes), sizeof (processes));
}

void
pluginlaunch_disable_parallel_checks (void)
{
  max_running_processes = 1;
}

void
pluginlaunch_enable_parallel_checks (void)
{
  max_running_processes = old_max_running_processes;
}

void
pluginlaunch_stop (void)
{
  int i;

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid > 0)
        {
          terminate_process (processes[i].pid * -1);
          num_running_processes--;
          processes[i].plugin->running_state = PLUGIN_STATUS_DONE;
          bzero (&(processes[i]), sizeof (struct running));
        }
    }
}

static int
plugin_timeout (nvti_t *nvti)
{
  int timeout;

  assert (nvti);
  timeout = prefs_nvt_timeout (nvti_oid (nvti));
  if (timeout == 0)
    timeout = nvti_timeout (nvti);
  if (timeout == 0)
    {
      if (nvti_category (nvti) == ACT_SCANNER)
        timeout =
          atoi (prefs_get ("scanner_plugins_timeout")) ?: SCANNER_NVT_TIMEOUT;
      else
        timeout = atoi (prefs_get ("plugins_timeout")) ?: NVT_TIMEOUT;
    }
  return timeout;
}

/**
 * @return PID of process that is connected to the plugin as returned by plugin
 *         classes pl_launch function (<=0 means there was a problem).
 */
int
plugin_launch (struct scan_globals *globals, struct scheduler_plugin *plugin,
               struct in6_addr *ip, GSList *vhosts, kb_t kb, nvti_t *nvti)
{
  int p;

  /* Wait for a free slot */
  pluginlaunch_wait_for_free_process (kb);
  p = next_free_process (kb, plugin);
  if (p < 0)
    return -1;
  processes[p].plugin = plugin;
  processes[p].timeout = plugin_timeout (nvti);
  gettimeofday (&(processes[p].start), NULL);
  processes[p].pid = nasl_plugin_launch (globals, ip, vhosts, kb, plugin->oid);

  if (processes[p].pid > 0)
    num_running_processes++;
  else
    processes[p].plugin->running_state = PLUGIN_STATUS_UNRUN;

  return processes[p].pid;
}

/**
 * @brief Waits and 'pushes' processes until num_running_processes is 0.
 */
void
pluginlaunch_wait (kb_t kb)
{
  while (num_running_processes)
    {
      update_running_processes (kb);
      if (num_running_processes)
        waitpid (-1, NULL, 0);
    }
}

/**
 * @brief Return shortest timeout of the running processes.
 */
static int
timeout_running_processes (void)
{
  int i, timeout = 0;

  for (i = 0; i < MAX_PROCESSES; i++)
    {
      if (processes[i].pid <= 0)
        continue;
      if (!timeout || processes[i].timeout < timeout)
        timeout = processes[i].timeout;
    }
  return timeout;
}

/**
 * @brief Waits and 'pushes' processes until the number of running processes has
 *        changed.
 */
void
pluginlaunch_wait_for_free_process (kb_t kb)
{
  if (!num_running_processes)
    return;
  update_running_processes (kb);
  /* Max number of processes are still running, wait for a child to exit or
   * to timeout. */
  if (num_running_processes == max_running_processes)
    {
      sigset_t mask;
      struct timespec ts = {0, 0};

      ts.tv_sec = timeout_running_processes ();
      assert (ts.tv_sec);
      sigemptyset (&mask);
      sigaddset (&mask, SIGCHLD);
      if (sigtimedwait (&mask, NULL, &ts) < 0 && errno != EAGAIN)
        g_warning ("%s: %s", __func__, strerror (errno));
      update_running_processes (kb);
    }
}
