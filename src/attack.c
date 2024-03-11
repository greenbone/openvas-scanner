/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file attack.c
 * @brief Launches the plugins, and manages multithreading.
 */

#include "attack.h"

#include "../misc/ipc_openvas.h"
#include "../misc/kb_cache.h"
#include "../misc/network.h"        /* for auth_printf */
#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "../misc/pcap_openvas.h"   /* for v6_is_local_ip */
#include "../misc/plugutils.h"
#include "../misc/table_driven_lsc.h" /*for run_table_driven_lsc */
#include "../misc/user_agent.h"       /* for user_agent_set */
#include "../nasl/nasl_debug.h"       /* for nasl_*_filename */
#include "hosts.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"

#include <arpa/inet.h> /* for inet_ntoa() */
#include <bsd/unistd.h>
#include <errno.h> /* for errno() */
#include <fcntl.h>
#include <glib.h>
#include <gvm/base/hosts.h>
#include <gvm/base/networking.h>
#include <gvm/base/prefs.h>            /* for prefs_get() */
#include <gvm/boreas/alivedetection.h> /* for start_alive_detection() */
#include <gvm/boreas/boreas_io.h>      /* for get_host_from_queue() */
#include <gvm/util/mqtt.h>
#include <gvm/util/nvticache.h> /* for nvticache_t */
#include <pthread.h>
#include <signal.h>
#include <string.h>   /* for strlen() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for close() */

#define ERR_HOST_DEAD -1

#define MAX_FORK_RETRIES 10
/**
 * Wait KB_RETRY_DELAY seconds until trying again to get a new kb.
 */
#define KB_RETRY_DELAY 3 /*In sec*/
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
  kb_t host_kb;
  struct ipc_context *ipc_context; // use dto communicate with parent
  plugins_scheduler_t sched;
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
    {
      return 0;
    }

  g_warning ("Not possible to get the main kb connection.");
  return -1;
}

/**
 * @brief Add the Host KB index to the list of readable KBs
 * used by ospd-openvas.
 *
 * @param host_kb_index The Kb index used for the host, to be stored
 *        in a list key in the main_kb.
 */
static void
set_kb_readable (int host_kb_index)
{
  kb_t main_kb = NULL;

  connect_main_kb (&main_kb);
  kb_item_add_int_unique_with_main_kb_check (main_kb, "internal/dbindex",
                                             host_kb_index);
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

  if (check_kb_inconsistency (main_kb) != 0)
    {
      kb_lnk_reset (main_kb);
      return;
    }
  scan_id = kb_item_get_str (main_kb, ("internal/scanid"));
  snprintf (buffer, sizeof (buffer), "internal/%s", scan_id);
  kb_item_set_str_with_main_kb_check (main_kb, buffer, status, 0);
  kb_lnk_reset (main_kb);
  g_free (scan_id);
}

/**
 * @brief Send status to the client that the host is dead
 *
 * Originally the progress status is of the format
 * "current_host/launched/total". Current host is the ip_str of the current host
 * which is vulnerability tested. Launched is the number of plguins(VTs) which
 * got already started. Total is the total number of plugins which will be
 * started for the current host. But here we use the format "current_host/0/-1"
 * for implicit singalling that the host is dead.
 *
 * @param main_kb Kb to use
 * @param ip_str str representation of host ip
 *
 * @return 0 on success, -1 on failure.
 */
static int
comm_send_status_host_dead (kb_t main_kb, char *ip_str)
{
  // implicit status code. Originally launched/total plugins
  const gchar *host_dead_status_code = "0/-1";
  const gchar *topic = "internal/status";
  gchar *status;

  // exact same restriction as comm_send_status() just to make it consistent
  if (strlen (ip_str) > 1998)
    return -1;
  status = g_strjoin ("/", ip_str, host_dead_status_code, NULL);
  kb_item_push_str_with_main_kb_check (main_kb, topic, status);
  g_free (status);

  return 0;
}

/**
 * @brief Sends the progress status of of a host's scan.
 *
 * Status format "current_host/launched/total".
 * Current host is the ip_str of the current host which is vulnerability tested.
 * Launched is the number of plguins(VTs) which got already started.
 * Total is the total number of plugins which will be started for the current
 * host.
 *
 * @param main_kb Kb to use.
 * @param ip_str str representation of host ip
 * @param curr  Currently launched plugins (VTs) for the host
 * @param max   Maximum number of plugins which will be launched for the host
 *
 * @return 0 on success, -1 on error.
 */
static int
comm_send_status (kb_t main_kb, char *ip_str, int curr, int max)
{
  char status_buf[2048];

  if (!ip_str || !main_kb)
    return -1;

  if (strlen (ip_str) > (sizeof (status_buf) - 50))
    return -1;

  snprintf (status_buf, sizeof (status_buf), "%s/%d/%d", ip_str, curr, max);
  kb_item_push_str_with_main_kb_check (main_kb, "internal/status", status_buf);
  kb_lnk_reset (main_kb);

  return 0;
}

static void
message_to_client (kb_t kb, const char *msg, const char *ip_str,
                   const char *port, const char *type)
{
  char *buf;

  buf = g_strdup_printf ("%s|||%s|||%s|||%s||| |||%s", type,
                         ip_str ? ip_str : "", ip_str ? ip_str : "",
                         port ? port : " ", msg ? msg : "No error.");
  kb_item_push_str_with_main_kb_check (kb, "internal/results", buf);
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

static void
append_vhost (const char *vhost, const char *source)
{
  GSList *vhosts = NULL;
  vhosts = host_vhosts;
  assert (source);
  assert (vhost);
  while (vhosts)
    {
      gvm_vhost_t *tmp = vhosts->data;

      if (!strcmp (tmp->value, vhost))
        {
          g_info ("%s: vhost '%s' exists already", __func__, vhost);
          return;
        }
      vhosts = vhosts->next;
    }
  host_vhosts = g_slist_append (
    host_vhosts, gvm_vhost_new (g_strdup (vhost), g_strdup (source)));
  g_info ("%s: add vhost '%s' from '%s'", __func__, vhost, source);
}

static void
call_lsc (struct attack_start_args *args, const char *ip_str)
{
  char *package_list = NULL;
  char *os_release = NULL;
  kb_t hostkb = NULL;

  hostkb = args->host_kb;
  /* Get the OS release. TODO: have a list with
   * supported OS. */
  os_release = kb_item_get_str (hostkb, "ssh/login/release_notus");
  /* Get the package list. */
  package_list = kb_item_get_str (hostkb, "ssh/login/package_list_notus");

  if (run_table_driven_lsc (args->globals->scan_id, ip_str, NULL, package_list,
                            os_release)
      < 0)
    {
      char buffer[2048];
      snprintf (buffer, sizeof (buffer),
                "ERRMSG|||%s||| ||| ||| ||| Unable to "
                "launch table driven lsc",
                ip_str);
      kb_item_push_str_with_main_kb_check (get_main_kb (), "internal/results",
                                           buffer);
      g_warning ("%s: Unable to launch table driven LSC", __func__);
    }
  g_free (package_list);
  g_free (os_release);
}

static int
process_ipc_data (struct attack_start_args *args, const gchar *result)
{
  ipc_data_t *idata;
  int ipc_msg_flag = IPC_DT_NO_DATA;

  if ((idata = ipc_data_from_json (result, strlen (result))) != NULL)
    {
      switch (ipc_get_data_type_from_data (idata))
        {
        case IPC_DT_ERROR:
          ipc_msg_flag |= IPC_DT_ERROR;
          g_warning ("%s: Unknown data type.", __func__);
          break;
        case IPC_DT_NO_DATA:
          break;
        case IPC_DT_HOSTNAME:
          ipc_msg_flag |= IPC_DT_HOSTNAME;
          if (ipc_get_hostname_from_data (idata) == NULL)
            g_warning ("%s: ihost data is NULL ignoring new vhost", __func__);
          else
            append_vhost (ipc_get_hostname_from_data (idata),
                          ipc_get_hostname_source_from_data (idata));
          break;
        case IPC_DT_USER_AGENT:
          ipc_msg_flag |= IPC_DT_USER_AGENT;
          if (ipc_get_user_agent_from_data (idata) == NULL)
            g_warning ("%s: iuser_agent data is NULL, ignoring new user agent",
                       __func__);
          else
            {
              gchar *old_ua = NULL;
              old_ua = user_agent_set (ipc_get_user_agent_from_data (idata));
              g_debug ("%s: The User-Agent %s has been overwritten with %s",
                       __func__, old_ua, ipc_get_user_agent_from_data (idata));
              g_free (old_ua);
            }
          break;
        case IPC_DT_LSC:
          ipc_msg_flag |= IPC_DT_LSC;
          set_lsc_flag ();
          if (!scan_is_stopped () && prefs_get_bool ("table_driven_lsc")
              && (prefs_get_bool ("mqtt_enabled")
                  || prefs_get_bool ("openvasd_lsc_enabled")))
            {
              struct in6_addr hostip;
              gchar ip_str[INET6_ADDRSTRLEN];

              if (!ipc_get_lsc_data_ready_flag (idata))
                {
                  g_warning ("%s: Unknown data type.", __func__);
                  ipc_msg_flag |= IPC_DT_ERROR;
                  break;
                }

              gvm_host_get_addr6 (args->host, &hostip);
              addr6_to_str (&hostip, ip_str);

              call_lsc (args, ip_str);
            }
          break;
        }
      ipc_data_destroy (&idata);
    }
  return ipc_msg_flag;
}

static int
read_ipc (struct attack_start_args *args, struct ipc_context *ctx)
{
  char *results;
  int ipc_msg_flag = IPC_DT_NO_DATA;

  while ((results = ipc_retrieve (ctx, IPC_MAIN)) != NULL)
    {
      int len = 0;
      int pos = 0;
      for (int j = 0; results[j] != '\0'; j++)
        if (results[j] == '}')
          {
            gchar *message = NULL;
            len = j - pos + 1;
            message = g_malloc0 (sizeof (gchar) * (len + 1));
            memcpy (message, &results[pos], len);
            pos = j + 1;
            len = 0;
            ipc_msg_flag |= process_ipc_data (args, message);
            g_free (message);
          }
    }
  g_free (results);
  return ipc_msg_flag;
}

/**
 * @brief Launches a nvt. Respects safe check preference (i.e. does not try
 * @brief destructive nvt if save_checks is yes).
 *
 * Does not launch a plugin twice if !save_kb_replay.
 *
 * @return ERR_HOST_DEAD if host died, ERR_CANT_FORK if forking failed,
 *         ERR_NO_FREE_SLOT if the process table is full, 0 otherwise.
 */
static int
launch_plugin (struct scan_globals *globals, struct scheduler_plugin *plugin,
               struct in6_addr *ip, GSList *vhosts,
               struct attack_start_args *args)
{
  int optimize = prefs_get_bool ("optimize_test");
  int launch_error, pid, ret = 0;
  char *oid, *name, *error = NULL, ip_str[INET6_ADDRSTRLEN];
  nvti_t *nvti;

  kb_lnk_reset (get_main_kb ());
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
      plugin->running_state = PLUGIN_STATUS_DONE;
      goto finish_launch_plugin;
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
  if (!mandatory_requirements_met (args->host_kb, nvti))
    error = "because a mandatory key is missing";
  if (error
      || (optimize && (error = requirements_plugin (args->host_kb, nvti))))
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
  if (kb_item_get_int (args->host_kb, "Host/dead") > 0)
    {
      g_message ("The remote host %s is dead", ip_str);
      pluginlaunch_stop ();
      plugin->running_state = PLUGIN_STATUS_DONE;
      ret = ERR_HOST_DEAD;
      goto finish_launch_plugin;
    }

  /* Update vhosts list and start the plugin */
  if (procs_get_ipc_contexts () != NULL)
    {
      for (int i = 0; i < procs_get_ipc_contexts ()->len; i++)
        {
          read_ipc (args, &procs_get_ipc_contexts ()->ctxs[i]);
        }
    }

  /* Start the plugin */
  launch_error = 0;
  pid = plugin_launch (globals, plugin, ip, vhosts, args->host_kb,
                       get_main_kb (), nvti, &launch_error);
  if (launch_error == ERR_NO_FREE_SLOT || launch_error == ERR_CANT_FORK)
    {
      plugin->running_state = PLUGIN_STATUS_UNRUN;
      ret = launch_error;
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

/**
 * @brief Attack one host.
 */
static void
attack_host (struct scan_globals *globals, struct in6_addr *ip,
             struct attack_start_args *args)
{
  /* Used for the status */
  int num_plugs, forks_retry = 0, all_plugs_launched = 0;
  char ip_str[INET6_ADDRSTRLEN];
  struct scheduler_plugin *plugin;
  pid_t parent;

  addr6_to_str (ip, ip_str);
  host_kb = args->host_kb;
  host_vhosts = args->host->vhosts;
  globals->host_pid = getpid ();
  host_set_time (get_main_kb (), ip_str, "HOST_START");
  kb_lnk_reset (get_main_kb ());
  setproctitle ("openvas: testing %s", ip_str);
  kb_lnk_reset (args->host_kb);

  /* launch the plugins */
  pluginlaunch_init (ip_str);
  num_plugs = plugins_scheduler_count_active (args->sched);
  for (;;)
    {
      /* Check that our father is still alive */
      parent = getppid ();
      if (parent <= 1 || process_alive (parent) == 0)
        {
          pluginlaunch_stop ();
          return;
        }

      if (check_kb_inconsistency (get_main_kb ()) != 0)
        {
          // We send the stop scan signal to the current parent process
          // group, which is the main scan process and host processes.
          // This avoid to attack new hosts and force the running host
          // process to finish and spread the signal to the plugin processes
          // To prevent duplicate results we don't let ACT_END run.
          killpg (parent, SIGUSR1);
        }

      if (scan_is_stopped ())
        plugins_scheduler_stop (args->sched);

      plugin = plugins_scheduler_next (args->sched);
      if (plugin != NULL && plugin != PLUG_RUNNING)
        {
          int e;
          static int last_status = 0, cur_plug = 0;

        again:
          e = launch_plugin (globals, plugin, ip, host_vhosts, args);
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
                  kb_item_push_str_with_main_kb_check (
                    get_main_kb (), "internal/results", buffer);

                  comm_send_status_host_dead (get_main_kb (), ip_str);
                  goto host_died;
                }
              else if (e == ERR_NO_FREE_SLOT)
                {
                  if (forks_retry < MAX_FORK_RETRIES)
                    {
                      forks_retry++;
                      g_warning ("Launch failed for %s. No free slot available "
                                 "in the internal process table for starting a "
                                 "plugin.",
                                 plugin->oid);
                      fork_sleep (forks_retry);
                      goto again;
                    }
                }
              else if (e == ERR_CANT_FORK)
                {
                  if (forks_retry < MAX_FORK_RETRIES)
                    {
                      forks_retry++;
                      g_warning (
                        "fork() failed for %s - sleeping %d seconds (%s)",
                        plugin->oid, forks_retry, strerror (errno));
                      fork_sleep (forks_retry);
                      goto again;
                    }
                  else
                    {
                      g_warning ("fork() failed too many times - aborting");
                      goto host_died;
                    }
                }
            }

          if ((cur_plug * 100) / num_plugs >= last_status
              && !scan_is_stopped ())
            {
              last_status = (cur_plug * 100) / num_plugs + 2;
              if (comm_send_status (get_main_kb (), ip_str, cur_plug, num_plugs)
                  < 0)
                goto host_died;
            }
          cur_plug++;
        }
      else if (plugin == NULL)
        break;
      else if (plugin != NULL && plugin == PLUG_RUNNING)
        /* 50 milliseconds. */
        usleep (50000);
      pluginlaunch_wait_for_free_process (get_main_kb (), args->host_kb);
    }

  if (!scan_is_stopped () && prefs_get_bool ("table_driven_lsc")
      && !lsc_has_run ()
      && (prefs_get_bool ("mqtt_enabled")
          || prefs_get_bool ("openvasd_lsc_enabled")))
    {
      call_lsc (args, ip_str);
    }

  pluginlaunch_wait (get_main_kb (), args->host_kb);
  if (!scan_is_stopped ())
    {
      int ret;
      ret = comm_send_status (get_main_kb (), ip_str, num_plugs, num_plugs);
      if (ret == 0)
        all_plugs_launched = 1;
    }

host_died:
  if (all_plugs_launched == 0 && !scan_is_stopped ())
    g_message ("Vulnerability scan %s for host %s: not all plugins "
               "were launched",
               globals->scan_id, ip_str);
  pluginlaunch_stop ();
  plugins_scheduler_free (args->sched);
  host_set_time (get_main_kb (), ip_str, "HOST_END");
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
check_deprecated_prefs (void)
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
        "The following provided settings are deprecated since the 22.4 "
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

#ifndef FEATURE_HOSTS_ALLOWED_ONLY
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
#endif

/**
 * @brief Set up some data and jump into attack_host()
 */
// TODO change signature based on FT
static void
attack_start (struct ipc_context *ipcc, struct attack_start_args *args)
{
  struct scan_globals *globals = args->globals;
  char ip_str[INET6_ADDRSTRLEN], *hostnames;
  struct in6_addr hostip;
  struct timeval then;
  kb_t kb = args->host_kb;
  kb_t main_kb = get_main_kb ();
  int ret;
  args->ipc_context = ipcc;

  nvticache_reset ();
  kb_lnk_reset (kb);
  kb_lnk_reset (main_kb);
  gettimeofday (&then, NULL);

  kb_item_set_str_with_main_kb_check (kb, "internal/scan_id", globals->scan_id,
                                      0);
  set_kb_readable (kb_get_kb_index (kb));

  /* The reverse lookup is delayed to this step in order to not slow down the
   * main scan process eg. case of target with big range of IP addresses. */
  if (prefs_get_bool ("expand_vhosts"))
    gvm_host_add_reverse_lookup (args->host);
  if ((ret = gvm_vhosts_exclude (args->host, prefs_get ("exclude_hosts"))) > 0)
    g_message ("exclude_hosts: Skipped %d vhost(s).", ret);
  gvm_host_get_addr6 (args->host, &hostip);
  addr6_to_str (&hostip, ip_str);

#ifndef FEATURE_HOSTS_ALLOWED_ONLY
  int ret_host_auth = check_host_authorization (args->host, &hostip);
  if (ret_host_auth < 0)
    {
      if (ret_host_auth == -1)
        message_to_client (kb, "Host access denied.", ip_str, NULL, "ERRMSG");
      else
        message_to_client (kb, "Host access denied (system-wide restriction.)",
                           ip_str, NULL, "ERRMSG");

      kb_item_set_str_with_main_kb_check (kb, "internal/host_deny", "True", 0);
      g_warning ("Host %s access denied.", ip_str);
      return;
    }
#endif

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
  attack_host (globals, &hostip, args);
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

static int
apply_hosts_excluded (gvm_hosts_t *hosts)
{
  const char *exclude_hosts = prefs_get ("exclude_hosts");
  int ret = 0;
  /* Exclude hosts ? */
  if (exclude_hosts)
    {
      /* Exclude hosts, resolving hostnames. */
      ret = gvm_hosts_exclude (hosts, exclude_hosts);

      if (ret > 0)
        g_message ("exclude_hosts: Skipped %d host(s).", ret);
      if (ret < 0)
        g_message ("exclude_hosts: Error.");
    }
  return ret;
}

#ifdef FEATURE_HOSTS_ALLOWED_ONLY
static void
print_host_access_denied (gpointer data, gpointer systemwide)
{
  kb_t kb = NULL;
  int *sw = systemwide;
  connect_main_kb (&kb);
  if (*sw == 0)
    message_to_client ((kb_t) kb, "Host access denied.", (gchar *) data, NULL,
                       "ERRMSG");
  else if (*sw == 1)
    message_to_client ((kb_t) kb,
                       "Host access denied (system-wide restriction).",
                       (gchar *) data, NULL, "ERRMSG");
  kb_item_set_str_with_main_kb_check ((kb_t) kb, "internal/host_deny", "True",
                                      0);
  kb_lnk_reset (kb);
  g_warning ("Host %s access denied.", (gchar *) data);
}

static void
apply_hosts_allow_deny (gvm_hosts_t *hosts)
{
  GSList *removed = NULL;
  const char *allow_hosts = prefs_get ("hosts_allow");
  const char *deny_hosts = prefs_get ("hosts_deny");
  int systemwide;
  if (allow_hosts || deny_hosts)
    {
      systemwide = 0;
      removed = gvm_hosts_allowed_only (hosts, deny_hosts, allow_hosts);
      g_slist_foreach (removed, print_host_access_denied,
                       (gpointer) &systemwide);
      g_slist_free_full (removed, g_free);
    }

  const char *sys_allow_hosts = prefs_get ("sys_hosts_allow");
  const char *sys_deny_hosts = prefs_get ("sys_hosts_deny");
  if (sys_allow_hosts || sys_deny_hosts)
    {
      systemwide = 1;
      removed = gvm_hosts_allowed_only (hosts, sys_deny_hosts, sys_allow_hosts);
      g_slist_foreach (removed, print_host_access_denied,
                       (gpointer) &systemwide);
      g_slist_free_full (removed, g_free);
    }
}
#endif

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

static int
apply_hosts_reverse_lookup_preferences (gvm_hosts_t *hosts)
{
#ifdef FEATURE_REVERSE_LOOKUP_EXCLUDED
  const char *exclude_hosts = prefs_get ("exclude_hosts");
  int hosts_excluded = 0;

  if (prefs_get_bool ("reverse_lookup_unify"))
    {
      gvm_hosts_t *excluded;

      excluded = gvm_hosts_reverse_lookup_unify_excluded (hosts);
      g_debug ("reverse_lookup_unify: Skipped %zu host(s).", excluded->count);

      // Get the amount of hosts which are excluded now for this option,
      // but they are already in the exclude list.
      // This is to avoid issues with the scan progress calculation, since
      // the amount of excluded host could be duplicated.
      hosts_excluded += gvm_hosts_exclude (excluded, exclude_hosts);

      gvm_hosts_free (excluded);
    }

  if (prefs_get_bool ("reverse_lookup_only"))
    {
      gvm_hosts_t *excluded;

      excluded = gvm_hosts_reverse_lookup_only_excluded (hosts);
      g_debug ("reverse_lookup_unify: Skipped %zu host(s).", excluded->count);
      // Get the amount of hosts which are excluded now for this option,
      // but they are already in the exclude list.
      // This is to avoid issues with the scan progress calculation, since
      // the amount of excluded host could be duplicated.
      hosts_excluded += gvm_hosts_exclude (excluded, exclude_hosts);
      gvm_hosts_free (excluded);
    }
  return exclude_hosts ? hosts_excluded : 0;
#else
  /* Reverse-lookup unify ? */
  if (prefs_get_bool ("reverse_lookup_unify"))
    g_debug ("reverse_lookup_unify: Skipped %d host(s).",
             gvm_hosts_reverse_lookup_unify (hosts));

  /* Hosts that reverse-lookup only ? */
  if (prefs_get_bool ("reverse_lookup_only"))
    g_debug ("reverse_lookup_only: Skipped %d host(s).",
             gvm_hosts_reverse_lookup_only (hosts));

  return 0;
#endif
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
  if (pid && (atoi (pid) == getpid ()))
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
  kb_t arg_host_kb, main_kb;
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

  int already_excluded = 0;
  already_excluded = apply_hosts_reverse_lookup_preferences (hosts);

#ifdef FEATURE_HOSTS_ALLOWED_ONLY
  // Remove hosts which are denied and/or keep the ones in the allowed host
  // lists
  // for both, user and system wide settings.
  apply_hosts_allow_deny (hosts);
#endif

  // Remove the excluded hosts
  int exc = apply_hosts_excluded (hosts);

  /* Send the excluded hosts count to the client, after removing duplicated and
   * unresolved hosts.*/
  sprintf (buf, "%d", exc + already_excluded);
  connect_main_kb (&main_kb);
  message_to_client (main_kb, buf, NULL, NULL, "HOSTS_EXCLUDED");
  kb_lnk_reset (main_kb);

  /* Send the hosts count to the client, after removing duplicated and
   * unresolved hosts.*/
  sprintf (buf, "%d", gvm_hosts_count (hosts));
  connect_main_kb (&main_kb);
  message_to_client (main_kb, buf, NULL, NULL, "HOSTS_COUNT");
  kb_lnk_reset (main_kb);

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
          rc = kb_new (&arg_host_kb, prefs_get ("db_address"));
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
      if (hosts_new (host_str, arg_host_kb, main_kb) < 0)
        {
          kb_delete (arg_host_kb);
          g_free (host_str);
          goto scan_stop;
        }

      if (scan_is_stopped ())
        {
          kb_delete (arg_host_kb);
          g_free (host_str);
          continue;
        }

      args.host = host;
      args.globals = globals;
      args.sched = sched;
      args.host_kb = arg_host_kb;

    forkagain:
      pid = create_ipc_process ((ipc_process_func) attack_start, &args);
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
          gvm_host_t *alive_buf;

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

          if (host && gvm_host_get_addr6 (host, &tmpaddr) == 0)
            {
              alive_buf = host;
              host = gvm_host_find_in_hosts (host, &tmpaddr, hosts);
              gvm_host_free (alive_buf);
              alive_buf = NULL;
            }

          if (host)
            gvm_hosts_add (alive_hosts_list, gvm_duplicate_host (host));
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
    if (scan_is_stopped () == 1)
      killpg (getpid (), SIGUSR1);

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
  if (alive_hosts_list)
    gvm_hosts_free (alive_hosts_list);

  set_scan_status ("finished");
}
