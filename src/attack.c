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
 * @file attack.c
 * @brief Launches the plugins, and manages multithreading.
 */

#include "attack.h"

#include "../misc/network.h"        /* for auth_printf */
#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "../misc/pcap_openvas.h"   /* for v6_is_local_ip */
#include "../nasl/nasl_debug.h"     /* for nasl_*_filename */
#include "hosts.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"

#include <arpa/inet.h> /* for inet_ntoa() */
#include <errno.h>     /* for errno() */
#include <fcntl.h>
#include <glib.h>
#include <gvm/base/hosts.h>
#include <gvm/base/networking.h>
#include <gvm/base/prefs.h> /* for prefs_get() */
#include <gvm/base/proctitle.h>
#include <gvm/boreas/alivedetection.h> /* for start_alive_detection() */
#include <gvm/boreas/boreas_io.h>      /* for get_host_from_queue() */
#include <gvm/util/mqtt.h>
#include <gvm/util/nvticache.h> /* for nvticache_t */
#include <pthread.h>
#include <stdlib.h>   /* for exit() */
#include <string.h>   /* for strlen() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for close() */

#define ERR_HOST_DEAD -1
#define ERR_CANT_FORK -2

#define MAX_FORK_RETRIES 10
/**
 * Wait KB_RETRY_DELAY seconds until trying again to get a new kb.
 */
#define KB_RETRY_DELAY 3 /*In sec*/
/**
 * It switches progress bar styles.
 * If set to 1, time oriented style and it take into account only alive host.
 * If set to 0, it not reflect progress adequately in case of dead host,
 * which will take into account with 0% processed, producing jumps in the
 * process bar.
 */
#define PROGRESS_BAR_STYLE 1
/**
 * Define value to be sent to the client for invalid target list.
 **/
#define INVALID_TARGET_LIST "-1"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * Bundles information about target(s), configuration (globals struct) and
 * scheduler.
 */
struct attack_start_args
{
  struct scan_globals *globals;
  plugins_scheduler_t sched;
  kb_t host_kb;
  kb_t main_kb;
  gvm_host_t *host;
};

/*******************************************************

               PRIVATE FUNCTIONS

********************************************************/
/**
 * @brief Connect to the main kb. Must be released with
 *        kb_lnk_reset() after use.
 *
 * @param[out] main_kb The connection to the kb.
 * @return 0 on success, -1 on failure.
 */
static int
connect_main_kb (kb_t *main_kb)
{
  int i = atoi (prefs_get ("ov_maindbid"));

  *main_kb = kb_direct_conn (prefs_get ("db_address"), i);
  if (main_kb)
    return 0;

  g_warning ("Not possible to get the main kb connection.");
  return -1;
}

/**
 * @brief Add the Host KB index to the list of readable KBs
 * used by ospd-openvas.
 */
static void
set_kb_readable (int host_kb_index)
{
  kb_t main_kb = NULL;

  connect_main_kb (&main_kb);
  kb_item_add_int_unique (main_kb, "internal/dbindex", host_kb_index);
  kb_lnk_reset (main_kb);
}

/**
 * @brief Set scan status. This helps ospd-openvas to
 * identify if a scan crashed or finished cleanly.
 *
 * @param[in] status Status to set.
 */
static void
set_scan_status (char *status)
{
  kb_t main_kb = NULL;
  char buffer[96];
  char *scan_id = NULL;

  connect_main_kb (&main_kb);
  scan_id = kb_item_get_str (main_kb, ("internal/scanid"));
  snprintf (buffer, sizeof (buffer), "internal/%s", scan_id);
  kb_item_set_str (main_kb, buffer, status, 0);
  kb_lnk_reset (main_kb);
  g_free (scan_id);
}

/**
 * @brief Sends the status of a host's scan.
 */
static int
comm_send_status (kb_t main_kb, char *hostname, int curr, int max)
{
  char buffer[2048];

  if (!hostname || !main_kb)
    return -1;

  if (strlen (hostname) > (sizeof (buffer) - 50))
    return -1;

  snprintf (buffer, sizeof (buffer), "%s/%d/%d", hostname, curr, max);
  kb_item_push_str (main_kb, "internal/status", buffer);
  kb_lnk_reset (main_kb);
  return 0;
}

static void
message_to_client (kb_t kb, const char *msg, const char *ip_str,
                   const char *port, const char *type)
{
  char *buf;

  buf = g_strdup_printf ("%s|||%s|||%s|||%s||| |||%s", type, ip_str ?: "",
                         ip_str ?: "", port ?: " ", msg ?: "No error.");
  kb_item_push_str (kb, "internal/results", buf);
  g_free (buf);
}

static void
report_kb_failure (int errcode)
{
  gchar *msg;

  errcode = abs (errcode);
  msg = g_strdup_printf ("WARNING: Cannot connect to KB at '%s': %s'",
                         prefs_get ("db_address"), strerror (errcode));
  g_warning ("%s", msg);
  g_free (msg);
}

static void
fork_sleep (int n)
{
  time_t then, now;

  now = then = time (NULL);
  while (now - then < n)
    {
      waitpid (-1, NULL, WNOHANG);
      usleep (10000);
      now = time (NULL);
    }
}

int global_scan_stop = 0;
static void
scan_stop_cleanup (void);

static int
scan_is_stopped (void)
{
  if (global_scan_stop == 1)
    scan_stop_cleanup ();
  return global_scan_stop;
}

/**
 * @brief Checks that an NVT category is safe.
 *
 * @param category  Category to check.
 *
 * @return 0 if category is unsafe, 1 otherwise.
 */
static int
nvti_category_is_safe (int category)
{
  /* XXX: Duplicated from openvas/nasl. */
  if (category == ACT_DESTRUCTIVE_ATTACK || category == ACT_KILL_HOST
      || category == ACT_FLOOD || category == ACT_DENIAL)
    return 0;
  return 1;
}

static kb_t host_kb = NULL;
static GSList *host_vhosts = NULL;
static int check_new_vhosts_flag = 0;

/**
 * @brief Return check_new_vhosts_flag. After reading must be clean with
 *        unset_check_new_vhosts_flag(), to avoid fetching unnecessarily.
 * @return 1 means new vhosts must be fetched. 0 nothing to do.
 */
static int
get_check_new_vhosts_flag (void)
{
  return check_new_vhosts_flag;
}

/**
 * @brief Set global check_new_vhosts_flag to indicate that new vhosts must be
 *        fetched.
 */
static void
set_check_new_vhosts_flag ()
{
  check_new_vhosts_flag = 1;
}

/**
 * @brief Unset global check_new_vhosts_flag. Must be called once the
 *        vhosts have been fetched.
 */
static void
unset_check_new_vhosts_flag (void)
{
  check_new_vhosts_flag = 0;
}

/**
 * @brief Check if a plugin process pushed a new vhost value.
 *
 * @param kb        Host scan KB.
 * @param vhosts    List of vhosts to add new vhosts to.
 *
 * @return New vhosts list.
 */
static void
check_new_vhosts (void)
{
  struct kb_item *current_vhosts = NULL;

  if (get_check_new_vhosts_flag () == 0)
    return;

  /* Check for duplicate vhost value already added by other forked child of the
   * same plugin. */
  current_vhosts = kb_item_get_all (host_kb, "internal/vhosts");
  if (!current_vhosts)
    {
      unset_check_new_vhosts_flag ();
      return;
    }
  while (current_vhosts)
    {
      GSList *vhosts = NULL;
      char buffer[4096], *source, *value;
      gvm_vhost_t *vhost;

      value = g_strdup (current_vhosts->v_str);

      /* Check for duplicate vhost value in args. */
      vhosts = host_vhosts;
      while (vhosts)
        {
          gvm_vhost_t *tmp = vhosts->data;

          if (!strcmp (tmp->value, value))
            {
              g_warning ("%s: Value '%s' exists already", __func__, value);
              unset_check_new_vhosts_flag ();
              kb_item_free (current_vhosts);
              return;
            }
          vhosts = vhosts->next;
        }

      /* Get sources*/
      g_snprintf (buffer, sizeof (buffer), "internal/source/%s", value);
      source = kb_item_get_str (host_kb, buffer);
      assert (source);
      vhost = gvm_vhost_new (value, source);
      host_vhosts = g_slist_append (host_vhosts, vhost);

      current_vhosts = current_vhosts->next;
    }

  kb_item_free (current_vhosts);
  unset_check_new_vhosts_flag ();
}

/**
 * @brief Launches a nvt. Respects safe check preference (i.e. does not try
 * @brief destructive nvt if save_checks is yes).
 *
 * Does not launch a plugin twice if !save_kb_replay.
 *
 * @return ERR_HOST_DEAD if host died, ERR_CANT_FORK if forking failed,
 *         0 otherwise.
 */
static int
launch_plugin (struct scan_globals *globals, struct scheduler_plugin *plugin,
               struct in6_addr *ip, GSList *vhosts, kb_t kb, kb_t main_kb)
{
  int optimize = prefs_get_bool ("optimize_test"), pid, ret = 0;
  char *oid, *name, *error = NULL, ip_str[INET6_ADDRSTRLEN];
  nvti_t *nvti;

  kb_lnk_reset (main_kb);
  addr6_to_str (ip, ip_str);
  oid = plugin->oid;
  nvti = nvticache_get_nvt (oid);

  /* eg. When NVT was moved/removed by a feed update during the scan. */
  if (!nvti)
    {
      g_message ("Plugin '%s' missing from nvticache.", oid);
      plugin->running_state = PLUGIN_STATUS_DONE;
      goto finish_launch_plugin;
    }
  if (scan_is_stopped ())
    {
      if (nvti_category (nvti) != ACT_END)
        {
          plugin->running_state = PLUGIN_STATUS_DONE;
          goto finish_launch_plugin;
        }
      else
        {
          name = nvticache_get_filename (oid);
          g_message ("Stopped scan wrap-up: Launching %s (%s)", name, oid);
          g_free (name);
        }
    }

  if (prefs_get_bool ("safe_checks")
      && !nvti_category_is_safe (nvti_category (nvti)))
    {
      if (prefs_get_bool ("log_whole_attack"))
        {
          name = nvticache_get_filename (oid);
          g_message ("Not launching %s (%s) against %s because safe checks are"
                     " enabled (this is not an error)",
                     name, oid, ip_str);
          g_free (name);
        }
      plugin->running_state = PLUGIN_STATUS_DONE;
      goto finish_launch_plugin;
    }

  /* Do not launch NVT if mandatory key is missing (e.g. an important tool
   * was not found). */
  if (!mandatory_requirements_met (kb, nvti))
    error = "because a mandatory key is missing";
  if (error || (optimize && (error = requirements_plugin (kb, nvti))))
    {
      plugin->running_state = PLUGIN_STATUS_DONE;
      if (prefs_get_bool ("log_whole_attack"))
        {
          name = nvticache_get_filename (oid);
          g_message (
            "Not launching %s (%s) against %s %s (this is not an error)", name,
            oid, ip_str, error);
          g_free (name);
        }
      goto finish_launch_plugin;
    }

  /* Stop the test if the host is 'dead' */
  if (kb_item_get_int (kb, "Host/dead") > 0)
    {
      g_message ("The remote host %s is dead", ip_str);
      pluginlaunch_stop ();
      plugin->running_state = PLUGIN_STATUS_DONE;
      ret = ERR_HOST_DEAD;
      goto finish_launch_plugin;
    }

  /* Update vhosts list and start the plugin */
  check_new_vhosts ();
  pid = plugin_launch (globals, plugin, ip, vhosts, kb, main_kb, nvti);
  if (pid < 0)
    {
      plugin->running_state = PLUGIN_STATUS_UNRUN;
      ret = ERR_CANT_FORK;
      goto finish_launch_plugin;
    }

  if (prefs_get_bool ("log_whole_attack"))
    {
      name = nvticache_get_filename (oid);
      g_message ("Launching %s (%s) against %s [%d]", name, oid, ip_str, pid);
      g_free (name);
    }

finish_launch_plugin:
  nvti_free (nvti);
  return ret;
}

/***
 * TODO: @mqtt
 */
/**
 * @brief Attack one host.
 */
static void
attack_host (struct scan_globals *globals, struct in6_addr *ip, GSList *vhosts,
             plugins_scheduler_t sched, kb_t kb, kb_t main_kb)
{
  /* Used for the status */
  int num_plugs, forks_retry = 0, all_plugs_launched = 0;
  char ip_str[INET6_ADDRSTRLEN];

  addr6_to_str (ip, ip_str);
  openvas_signal (SIGUSR2, set_check_new_vhosts_flag);
  host_kb = kb;
  host_vhosts = vhosts;
  kb_item_set_int (kb, "internal/hostpid", getpid ());
  host_set_time (main_kb, ip_str, "HOST_START");
  kb_lnk_reset (main_kb);
  proctitle_set ("openvas: testing %s", ip_str);
  kb_lnk_reset (kb);

  /* launch the plugins */
  pluginlaunch_init (ip_str);
  num_plugs = plugins_scheduler_count_active (sched);
  for (;;)
    {
      struct scheduler_plugin *plugin;
      pid_t parent;

      /* Check that our father is still alive */
      parent = getppid ();
      if (parent <= 1 || process_alive (parent) == 0)
        {
          pluginlaunch_stop ();
          return;
        }

      if (scan_is_stopped ())
        plugins_scheduler_stop (sched);
      plugin = plugins_scheduler_next (sched);
      if (plugin != NULL && plugin != PLUG_RUNNING)
        {
          int e;
          static int last_status = 0, cur_plug = 0;

        again:
          e = launch_plugin (globals, plugin, ip, host_vhosts, kb, main_kb);
          if (e < 0)
            {
              /*
               * Remote host died
               */
              if (e == ERR_HOST_DEAD)
                {
                  char buffer[2048];

                  snprintf (
                    buffer, sizeof (buffer),
                    "LOG|||%s||| |||general/Host_Details||| |||<host><detail>"
                    "<name>Host dead</name><value>1</value><source>"
                    "<description/><type/><name/></source></detail></host>",
                    ip_str);
#if (PROGRESS_BAR_STYLE == 1)
                  /* In case of a dead host, it sends max_ports = -1 to the
                     manager. The host will not be taken into account to
                     calculate the scan progress. */
                  comm_send_status (main_kb, ip_str, 0, -1);
#endif
                  kb_item_push_str (main_kb, "internal/results", buffer);
                  goto host_died;
                }
              else if (e == ERR_CANT_FORK)
                {
                  if (forks_retry < MAX_FORK_RETRIES)
                    {
                      forks_retry++;
                      g_debug ("fork() failed - sleeping %d seconds (%s)",
                               forks_retry, strerror (errno));
                      fork_sleep (forks_retry);
                      goto again;
                    }
                  else
                    {
                      g_debug ("fork() failed too many times - aborting");
                      goto host_died;
                    }
                }
            }

          if ((cur_plug * 100) / num_plugs >= last_status
              && !scan_is_stopped ())
            {
              last_status = (cur_plug * 100) / num_plugs + 2;
              if (comm_send_status (main_kb, ip_str, cur_plug, num_plugs) < 0)
                goto host_died;
            }
          cur_plug++;
        }
      else if (plugin == NULL)
        break;
      else if (plugin != NULL && plugin == PLUG_RUNNING)
        /* 50 milliseconds. */
        usleep (50000);
      pluginlaunch_wait_for_free_process (main_kb, kb);
    }

  pluginlaunch_wait (main_kb, kb);
  if (!scan_is_stopped ())
    {
      int ret;
      ret = comm_send_status (main_kb, ip_str, num_plugs, num_plugs);
      if (ret == 0)
        all_plugs_launched = 1;
    }

host_died:
  if (all_plugs_launched == 0 && !scan_is_stopped ())
    g_message ("Vulnerability scan %s for host %s: not all plugins "
               "were launched",
               globals->scan_id, ip_str);
  pluginlaunch_stop ();
  plugins_scheduler_free (sched);
  host_set_time (main_kb, ip_str, "HOST_END");
}

/*
 * Checks if a host is authorized to be scanned.
 *
 * @param[in]   host    Host to check access to.
 * @param[in]   addr    Pointer to address so a hostname isn't resolved multiple
 *                      times.
 * @param[in]   hosts_allow   Hosts whitelist.
 * @param[in]   hosts_deny    Hosts blacklist.
 *
 * @return 1 if host authorized, 0 otherwise.
 */
static int
host_authorized (const gvm_host_t *host, const struct in6_addr *addr,
                 const gvm_hosts_t *hosts_allow, const gvm_hosts_t *hosts_deny)
{
  /* Check Hosts Access. */
  if (host == NULL)
    return 0;

  if (hosts_deny && gvm_host_in_hosts (host, addr, hosts_deny))
    return 0;
  if (hosts_allow && !gvm_host_in_hosts (host, addr, hosts_allow))
    return 0;

  return 1;
}

/*
 * Converts the vhosts list to a comma-separated char string.
 *
 * @param[in]   list    Linked-list to convert.
 *
 * @return NULL if empty list, char string otherwise.
 */
static char *
vhosts_to_str (GSList *list)
{
  GString *string;

  if (!list)
    return NULL;
  string = g_string_new (((gvm_vhost_t *) list->data)->value);
  if (g_slist_length (list) == 1)
    return g_string_free (string, FALSE);
  list = list->next;
  while (list)
    {
      g_string_append (string, ", ");
      g_string_append (string, ((gvm_vhost_t *) list->data)->value);
      list = list->next;
    }
  return g_string_free (string, FALSE);
}

/**
 * @brief Check if any deprecated prefs are in pref table and print warning.
 */
static void
check_deprecated_prefs ()
{
  const gchar *source_iface = prefs_get ("source_iface");
  const gchar *ifaces_allow = prefs_get ("ifaces_allow");
  const gchar *ifaces_deny = prefs_get ("ifaces_deny");
  const gchar *sys_ifaces_allow = prefs_get ("sys_ifaces_allow");
  const gchar *sys_ifaces_deny = prefs_get ("sys_ifaces_deny");

  if (source_iface || ifaces_allow || ifaces_deny || sys_ifaces_allow
      || sys_ifaces_deny)
    {
      kb_t main_kb = NULL;
      gchar *msg = NULL;

      msg = g_strdup_printf (
        "The following provided settings are deprecated since the 21.10 "
        "release and will be ignored: %s%s%s%s%s",
        source_iface ? "source_iface (task setting) " : "",
        ifaces_allow ? "ifaces_allow (user setting) " : "",
        ifaces_deny ? "ifaces_deny (user setting) " : "",
        sys_ifaces_allow ? "sys_ifaces_allow (scanner only setting) " : "",
        sys_ifaces_deny ? "sys_ifaces_deny (scanner only setting)" : "");
      g_warning ("%s: %s", __func__, msg);

      connect_main_kb (&main_kb);
      message_to_client (main_kb, msg, NULL, NULL, "ERRMSG");
      kb_lnk_reset (main_kb);
      g_free (msg);
    }
}

/*
 * Check if a scan is authorized on a host.
 *
 * @param[in]   host    Host to check access to.
 * @param[in]   addr    Pointer to address so a hostname isn't resolved multiple
 *                      times.
 *
 * @return 0 if authorized, -1 denied, -2 system-wide denied.
 */
static int
check_host_authorization (gvm_host_t *host, const struct in6_addr *addr)
{
  gvm_hosts_t *hosts_allow, *hosts_deny;
  gvm_hosts_t *sys_hosts_allow, *sys_hosts_deny;

  /* Do we have the right to test this host ? */
  hosts_allow = gvm_hosts_new (prefs_get ("hosts_allow"));
  hosts_deny = gvm_hosts_new (prefs_get ("hosts_deny"));
  if (!host_authorized (host, addr, hosts_allow, hosts_deny))
    return -1;

  sys_hosts_allow = gvm_hosts_new (prefs_get ("sys_hosts_allow"));
  sys_hosts_deny = gvm_hosts_new (prefs_get ("sys_hosts_deny"));
  if (!host_authorized (host, addr, sys_hosts_allow, sys_hosts_deny))
    return -2;

  gvm_hosts_free (hosts_allow);
  gvm_hosts_free (hosts_deny);
  gvm_hosts_free (sys_hosts_allow);
  gvm_hosts_free (sys_hosts_deny);
  return 0;
}

/**
 * @brief Set up some data and jump into attack_host()
 */
static void
attack_start (struct attack_start_args *args)
{
  struct scan_globals *globals = args->globals;
  char ip_str[INET6_ADDRSTRLEN], *hostnames;
  struct in6_addr hostip;
  struct timeval then;
  kb_t kb = args->host_kb;
  kb_t main_kb = args->main_kb;
  int ret, ret_host_auth;

  nvticache_reset ();
  kb_lnk_reset (kb);
  kb_lnk_reset (main_kb);
  gettimeofday (&then, NULL);

  kb_item_set_str (kb, "internal/scan_id", globals->scan_id, 0);
  set_kb_readable (kb_get_kb_index (kb));

  /* The reverse lookup is delayed to this step in order to not slow down the
   * main scan process eg. case of target with big range of IP addresses. */
  if (prefs_get_bool ("expand_vhosts"))
    gvm_host_add_reverse_lookup (args->host);
  if ((ret = gvm_vhosts_exclude (args->host, prefs_get ("exclude_hosts"))) > 0)
    g_message ("exclude_hosts: Skipped %d vhost(s).", ret);
  gvm_host_get_addr6 (args->host, &hostip);
  addr6_to_str (&hostip, ip_str);

  ret_host_auth = check_host_authorization (args->host, &hostip);
  if (ret_host_auth < 0)
    {
      if (ret_host_auth == -1)
        message_to_client (kb, "Host access denied.", ip_str, NULL, "ERRMSG");
      else
        message_to_client (kb, "Host access denied (system-wide restriction.)",
                           ip_str, NULL, "ERRMSG");

      kb_item_set_str (kb, "internal/host_deny", "True", 0);
      g_warning ("Host %s access denied.", ip_str);
      return;
    }

  if (prefs_get_bool ("test_empty_vhost"))
    {
      gvm_vhost_t *vhost =
        gvm_vhost_new (g_strdup (ip_str), g_strdup ("IP-address"));
      args->host->vhosts = g_slist_prepend (args->host->vhosts, vhost);
    }
  hostnames = vhosts_to_str (args->host->vhosts);
  if (hostnames)
    g_message ("Vulnerability scan %s started for host: %s (Vhosts: %s)",
               globals->scan_id, ip_str, hostnames);
  else
    g_message ("Vulnerability scan %s started for host: %s", globals->scan_id,
               ip_str);
  g_free (hostnames);
  attack_host (globals, &hostip, args->host->vhosts, args->sched, kb, main_kb);
  kb_lnk_reset (main_kb);

  if (!scan_is_stopped ())
    {
      struct timeval now;

      gettimeofday (&now, NULL);
      if (now.tv_usec < then.tv_usec)
        {
          then.tv_sec++;
          now.tv_usec += 1000000;
        }
      g_message (
        "Vulnerability scan %s finished for host %s in %ld.%.2ld seconds",
        globals->scan_id, ip_str, (long) (now.tv_sec - then.tv_sec),
        (long) ((now.tv_usec - then.tv_usec) / 10000));
    }
}

static void
apply_hosts_excluded (gvm_hosts_t *hosts)
{
  const char *exclude_hosts = prefs_get ("exclude_hosts");

  /* Exclude hosts ? */
  if (exclude_hosts)
    {
      /* Exclude hosts, resolving hostnames. */
      int ret = gvm_hosts_exclude (hosts, exclude_hosts);

      if (ret > 0)
        g_message ("exclude_hosts: Skipped %d host(s).", ret);
      if (ret < 0)
        g_message ("exclude_hosts: Error.");
    }
}

static void
apply_hosts_preferences_ordering (gvm_hosts_t *hosts)
{
  const char *ordering = prefs_get ("hosts_ordering");

  /* Hosts ordering strategy: sequential, random, reversed... */
  if (ordering)
    {
      if (!strcmp (ordering, "random"))
        {
          gvm_hosts_shuffle (hosts);
          g_debug ("hosts_ordering: Random.");
        }
      else if (!strcmp (ordering, "reverse"))
        {
          gvm_hosts_reverse (hosts);
          g_debug ("hosts_ordering: Reverse.");
        }
    }
  else
    g_debug ("hosts_ordering: Sequential.");
}

static void
apply_hosts_reverse_lookup_preferences (gvm_hosts_t *hosts)
{
  /* Reverse-lookup unify ? */
  if (prefs_get_bool ("reverse_lookup_unify"))
    g_debug ("reverse_lookup_unify: Skipped %d host(s).",
             gvm_hosts_reverse_lookup_unify (hosts));

  /* Hosts that reverse-lookup only ? */
  if (prefs_get_bool ("reverse_lookup_only"))
    g_debug ("reverse_lookup_only: Skipped %d host(s).",
             gvm_hosts_reverse_lookup_only (hosts));
}

static int
check_kb_access (void)
{
  int rc;
  kb_t kb;

  rc = kb_new (&kb, prefs_get ("db_address"));
  if (rc)
    report_kb_failure (rc);
  else
    kb_delete (kb);

  return rc;
}

/* TODO: put in other file ?*/
static pthread_t alive_detection_tid;

static void
set_alive_detection_tid (pthread_t tid)
{
  alive_detection_tid = tid;
}
static pthread_t
get_alive_detection_tid ()
{
  return alive_detection_tid;
}

/**
 * @brief Set and get if alive detection thread was already joined
 * by main thread.
 *
 * The status can only be set to TRUE once in the lifetime of the program and
 * retrieved as often as needed. After it is set to TRUE it can not be unset.
 *
 * @param joined  TRUE to set status to joined and FALSE to retrieve status of
 * join.
 * @return Returns true if thread was already joined.
 */
static gboolean
ad_thread_joined (gboolean joined)
{
  static gboolean alive_detection_thread_already_joined = FALSE;
  if (joined)
    alive_detection_thread_already_joined = TRUE;
  return alive_detection_thread_already_joined;
}

static void
handle_scan_stop_signal ()
{
  global_scan_stop = 1;
}

static void
scan_stop_cleanup ()
{
  kb_t main_kb = NULL;
  char *pid;
  static int already_called = 0;

  if (already_called == 1)
    return;

  connect_main_kb (&main_kb);
  pid = kb_item_get_str (main_kb, ("internal/ovas_pid"));
  kb_lnk_reset (main_kb);

  /* Stop all hosts and alive detection (if enabled) if we are in main.
   * Else stop all running plugin processes for the current host fork. */
  if (atoi (pid) == getpid ())
    {
      already_called = 1;
      hosts_stop_all ();

      /* Stop (cancel) alive detection if enabled and not already joined. */
      if (prefs_get_bool ("test_alive_hosts_only"))
        {
          /* Alive detection thread was already joined by main thread. */
          if (TRUE == ad_thread_joined (FALSE))
            {
              g_warning (
                "Alive detection thread was already joined by other "
                "thread. Cancel operation not permitted or not needed.");
            }
          else
            {
              int err;
              err = pthread_cancel (get_alive_detection_tid ());
              if (err == ESRCH)
                g_warning (
                  "%s: pthread_cancel() returned ESRCH; No thread with the "
                  "supplied ID could be found.",
                  __func__);
            }
        }
    }
  else
    /* Current host process */
    pluginlaunch_stop ();

  g_free (pid);
}

/**
 * @brief Attack a whole network.
 */
void
attack_network (struct scan_globals *globals)
{
  int max_hosts = 0, max_checks;
  const char *hostlist;
  gvm_host_t *host;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  GHashTable *files;
  struct timeval then, now;
  gvm_hosts_t *hosts;
  const gchar *port_range;
  int allow_simultaneous_ips;
  kb_t host_kb, main_kb;
  GSList *unresolved;
  char buf[96];

  check_deprecated_prefs ();

  gboolean test_alive_hosts_only = prefs_get_bool ("test_alive_hosts_only");
  gvm_hosts_t *alive_hosts_list = NULL;
  kb_t alive_hosts_kb = NULL;
  if (test_alive_hosts_only)
    connect_main_kb (&alive_hosts_kb);

  gettimeofday (&then, NULL);

  if (check_kb_access ())
    return;

  /* Init and check Target List */
  hostlist = prefs_get ("TARGET");
  if (hostlist == NULL)
    {
      return;
    }

  /* Verify the port range is a valid one */
  port_range = prefs_get ("port_range");
  if (validate_port_range (port_range))
    {
      connect_main_kb (&main_kb);
      message_to_client (
        main_kb, "Invalid port list. Ports must be in the range [1-65535]",
        NULL, NULL, "ERRMSG");
      kb_lnk_reset (main_kb);
      g_warning ("Invalid port list. Ports must be in the range [1-65535]. "
                 "Scan terminated.");
      set_scan_status ("finished");

      return;
    }

  /* Initialize the attack. */
  int plugins_init_error = 0;
  sched = plugins_scheduler_init (prefs_get ("plugin_set"),
                                  prefs_get_bool ("auto_enable_dependencies"),
                                  &plugins_init_error);
  if (!sched)
    {
      g_message ("Couldn't initialize the plugin scheduler");
      return;
    }

  if (plugins_init_error > 0)
    {
      sprintf (buf,
               "%d errors were found during the plugin scheduling. "
               "Some plugins have not been launched.",
               plugins_init_error);

      connect_main_kb (&main_kb);
      message_to_client (main_kb, buf, NULL, NULL, "ERRMSG");
      kb_lnk_reset (main_kb);
    }

  max_hosts = get_max_hosts_number ();
  max_checks = get_max_checks_number ();

  hosts = gvm_hosts_new (hostlist);
  if (hosts == NULL)
    {
      char *buffer;
      buffer = g_strdup_printf ("Invalid target list: %s.", hostlist);
      connect_main_kb (&main_kb);
      message_to_client (main_kb, buffer, NULL, NULL, "ERRMSG");
      g_free (buffer);
      /* Send the hosts count to the client as -1,
       * because the invalid target list.*/
      message_to_client (main_kb, INVALID_TARGET_LIST, NULL, NULL,
                         "HOSTS_COUNT");
      kb_lnk_reset (main_kb);
      g_warning ("Invalid target list. Scan terminated.");
      goto stop;
    }

  unresolved = gvm_hosts_resolve (hosts);
  while (unresolved)
    {
      g_warning ("Couldn't resolve hostname '%s'", (char *) unresolved->data);
      unresolved = unresolved->next;
    }
  g_slist_free_full (unresolved, g_free);

  /* Apply Hosts preferences. */
  apply_hosts_preferences_ordering (hosts);
  apply_hosts_reverse_lookup_preferences (hosts);

  /* Send the hosts count to the client, after removing duplicated and
   * unresolved hosts.*/
  sprintf (buf, "%d", gvm_hosts_count (hosts));
  connect_main_kb (&main_kb);
  message_to_client (main_kb, buf, NULL, NULL, "HOSTS_COUNT");
  kb_lnk_reset (main_kb);

  apply_hosts_excluded (hosts);

  host = gvm_hosts_next (hosts);
  if (host == NULL)
    goto stop;
  hosts_init (max_hosts);

  g_message ("Vulnerability scan %s started: Target has %d hosts: "
             "%s, with max_hosts = %d and max_checks = %d",
             globals->scan_id, gvm_hosts_count (hosts), hostlist, max_hosts,
             max_checks);

  if (test_alive_hosts_only)
    {
      /* Boolean signalling if alive detection finished. */
      gboolean ad_finished = FALSE;
      int err;
      pthread_t tid;
      struct in6_addr tmpaddr;

      /* Reset the iterator. */
      hosts->current = 0;
      err = pthread_create (&tid, NULL, start_alive_detection, (void *) hosts);
      if (err == EAGAIN)
        g_warning (
          "%s: pthread_create() returned EAGAIN: Insufficient resources "
          "to create thread.",
          __func__);
      set_alive_detection_tid (tid);
      g_debug ("%s: started alive detection.", __func__);

      for (host = get_host_from_queue (alive_hosts_kb, &ad_finished);
           !host && !ad_finished && !scan_is_stopped ();
           host = get_host_from_queue (alive_hosts_kb, &ad_finished))
        {
          fork_sleep (1);
        }

      if (gvm_host_get_addr6 (host, &tmpaddr) == 0)
        host = gvm_host_find_in_hosts (host, &tmpaddr, hosts);
      if (host)
        {
          g_debug (
            "%s: Get first host to test from Queue. This host is used for "
            "initialising the alive_hosts_list.",
            __func__);
        }
      alive_hosts_list = gvm_hosts_new (gvm_host_value_str (host));
    }

  /*
   * Start the attack !
   */
  allow_simultaneous_ips = prefs_get_bool ("allow_simultaneous_ips");
  openvas_signal (SIGUSR1, handle_scan_stop_signal);
  while (host && !scan_is_stopped ())
    {
      int pid, rc;
      struct attack_start_args args;
      char *host_str;

      if (!test_alive_hosts_only
          && (!allow_simultaneous_ips && host_is_currently_scanned (host)))
        {
          sleep (1);
          // move the host at the end of the list and get the next host.
          gvm_hosts_move_current_host_to_end (hosts);
          host = gvm_hosts_next (hosts);
          continue;
        }

      do
        {
          rc = kb_new (&host_kb, prefs_get ("db_address"));
          if (rc < 0 && rc != -2)
            {
              report_kb_failure (rc);
              goto scan_stop;
            }
          else if (rc == -2)
            {
              sleep (KB_RETRY_DELAY);
              continue;
            }
          break;
        }
      while (1);

      host_str = gvm_host_value_str (host);
      connect_main_kb (&main_kb);
      if (hosts_new (host_str, host_kb, main_kb) < 0)
        {
          kb_delete (host_kb);
          g_free (host_str);
          goto scan_stop;
        }

      if (scan_is_stopped ())
        {
          kb_delete (host_kb);
          g_free (host_str);
          continue;
        }

      args.host = host;
      args.globals = globals;
      args.sched = sched;
      args.host_kb = host_kb;
      args.main_kb = main_kb;

    forkagain:
      pid = create_process ((process_func_t) attack_start, &args);
      /* Close child process' socket. */
      if (pid < 0)
        {
          fork_retries++;
          if (fork_retries > MAX_FORK_RETRIES)
            {
              /* Forking failed - we go to the wait queue. */
              g_warning ("fork() failed - %s. %s won't be tested",
                         strerror (errno), host_str);
              g_free (host_str);
              goto stop;
            }

          g_debug ("fork() failed - "
                   "sleeping %d seconds and trying again...",
                   fork_retries);
          fork_sleep (fork_retries);
          goto forkagain;
        }
      hosts_set_pid (host_str, pid);

      if (test_alive_hosts_only)
        {
          struct in6_addr tmpaddr;

          while (1)
            {
              /* Boolean signalling if alive detection finished. */
              gboolean ad_finished = FALSE;
              for (host = get_host_from_queue (alive_hosts_kb, &ad_finished);
                   !host && !ad_finished && !scan_is_stopped ();
                   host = get_host_from_queue (alive_hosts_kb, &ad_finished))
                {
                  fork_sleep (1);
                }

              if (host && !allow_simultaneous_ips
                  && host_is_currently_scanned (host))
                {
                  struct in6_addr hostip;
                  char ip_str[INET6_ADDRSTRLEN];
                  int flag_set;

                  gvm_host_get_addr6 (host, &hostip);
                  addr6_to_str (&hostip, ip_str);

                  // Re-add host at the end of the queue and reallocate the flag
                  // if it was already set.
                  flag_set = finish_signal_on_queue (alive_hosts_kb);

                  put_host_on_queue (alive_hosts_kb, ip_str);
                  g_debug ("Reallocating the host %s at the end of the queue",
                           ip_str);

                  gvm_host_free (host);
                  host = NULL;

                  if (flag_set)
                    {
                      g_debug ("Reallocating finish signal in the host queue");
                      realloc_finish_signal_on_queue (alive_hosts_kb);
                    }
                }
              else
                break;
            }

          if (gvm_host_get_addr6 (host, &tmpaddr) == 0)
            host = gvm_host_find_in_hosts (host, &tmpaddr, hosts);

          if (host)
            {
              gvm_hosts_add (alive_hosts_list, host);
            }
          else
            g_debug ("%s: got NULL host, stop/finish scan", __func__);
        }
      else
        {
          host = gvm_hosts_next (hosts);
        }
      g_free (host_str);
    }

  /* Every host is being tested... We have to wait for the processes
   * to terminate. */
  while (hosts_read () == 0)
    ;
  g_debug ("Test complete");

scan_stop:
  /* Free the memory used by the files uploaded by the user, if any. */
  files = globals->files_translation;
  if (files)
    g_hash_table_destroy (files);

stop:

  if (test_alive_hosts_only)
    {
      int err;
      void *retval;

      kb_lnk_reset (alive_hosts_kb);
      g_debug ("%s: free alive detection data ", __func__);

      /* need to wait for alive detection to finish */
      g_debug ("%s: waiting for alive detection thread to be finished...",
               __func__);
      /* Join alive detection thread. */
      err = pthread_join (get_alive_detection_tid (), &retval);
      if (err == EDEADLK)
        g_debug ("%s: pthread_join() returned EDEADLK.", __func__);
      if (err == EINVAL)
        g_debug ("%s: pthread_join() returned EINVAL.", __func__);
      if (err == ESRCH)
        g_debug ("%s: pthread_join() returned ESRCH.", __func__);
      if (retval == PTHREAD_CANCELED)
        g_debug ("%s: pthread_join() returned PTHREAD_CANCELED.", __func__);
      /* Set flag signaling that alive deteciton thread was joined. */
      if (err == 0)
        ad_thread_joined (TRUE);
      g_debug ("%s: Finished waiting for alive detection thread.", __func__);
    }

  plugins_scheduler_free (sched);

  gettimeofday (&now, NULL);
  if (test_alive_hosts_only)
    g_message ("Vulnerability scan %s finished in %ld seconds: "
               "%d alive hosts of %d",
               globals->scan_id, now.tv_sec - then.tv_sec,
               gvm_hosts_count (alive_hosts_list), gvm_hosts_count (hosts));
  else
    g_message ("Vulnerability scan %s finished in %ld seconds: %d hosts",
               globals->scan_id, now.tv_sec - then.tv_sec,
               gvm_hosts_count (hosts));

  gvm_hosts_free (hosts);
  if (test_alive_hosts_only)
    gvm_hosts_free (alive_hosts_list);

  set_scan_status ("finished");
}
