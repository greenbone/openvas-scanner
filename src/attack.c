/* OpenVAS
* $Id$
* Description: Launches the plugins, and manages multithreading.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*	   - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*	   - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*	   - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*	   - Geoff Galitz <mailto:geoff@eifel-consulting.eu (Minor debug edits)
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

#include <string.h>    /* for strlen() */
#include <unistd.h>    /* for close() */
#include <errno.h>     /* for errno() */
#include <sys/wait.h>  /* for waitpid() */
#include <arpa/inet.h> /* for inet_ntoa() */
#include <stdlib.h>    /* for exit() */

#include <glib.h>
#include <fcntl.h>

#include <openvas/base/openvas_hosts.h>
#include <openvas/base/openvas_networking.h>
#include <openvas/misc/openvas_proctitle.h>
#include <openvas/base/kb.h>
#include <openvas/misc/network.h>        /* for auth_printf */
#include <openvas/misc/nvt_categories.h> /* for ACT_INIT */
#include <openvas/misc/pcap_openvas.h>   /* for v6_is_local_ip */
#include <openvas/misc/prefs.h>          /* for prefs_get() */
#include <openvas/misc/internal_com.h>

#include <openvas/base/nvticache.h>     /* for nvticache_t */

#include "attack.h"
#include "comm.h"
#include "hosts.h"
#include "log.h"
#include "ntp.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"


#define ERR_HOST_DEAD -1
#define ERR_CANT_FORK -2

#define MAX_FORK_RETRIES 10

/**
 * It switchs progress bar styles.
 * If set to 1, time oriented style and it take into account only alive host.
 * If set to 0, it not reflect progress adequately in case of dead host,
 * which will take into account with 0% processed, producing jumps in the
 * process bar.
 */
#define PROGRESS_BAR_STYLE 1

/**
 * Bundles information about target(s), configuration (globals arglist) and
 * scheduler.
 */
struct attack_start_args
{
  struct arglist *globals;
  plugins_scheduler_t sched;
  int thread_socket;
  int parent_socket;
  kb_t *net_kb;
  openvas_host_t *host;
};

enum net_scan_status {
  NSS_NONE = 0,
  NSS_BUSY,
  NSS_DONE,
};

/*******************************************************

		PRIVATE FUNCTIONS

********************************************************/

/**
 * @brief Sends the status of a host's scan.
 */
static int
comm_send_status (int soc, char *hostname, int curr, int max)
{
  char buffer[2048];

  if (soc < 0 || soc > 1024)
    return -1;

  if (strlen (hostname) > (sizeof (buffer) - 50))
    return -1;

  snprintf (buffer, sizeof (buffer),
            "SERVER <|> STATUS <|> %s <|> %d/%d <|> SERVER\n",
            hostname, curr, max);

  internal_send (soc, buffer, INTERNAL_COMM_MSG_TYPE_DATA);

  return 0;
}

static void
error_message_to_client (int soc, const char *msg, const char *hostname,
                         const char *port)
{
  send_printf (soc, "SERVER <|> ERRMSG <|> %s <|> %s <|> %s <|>  <|> SERVER\n",
               hostname ? hostname : "", port ? port : "",
               msg ? msg : "No error.");
}

static void
report_kb_failure (int soc, int errcode)
{
  gchar *msg;

  errcode = abs (errcode);
  msg = g_strdup_printf ("WARNING: Cannot connect to KB at '%s': %s'",
                         prefs_get ("kb_location"), strerror (errcode));
  log_write ("%s", msg);
  error_message_to_client (soc, msg, NULL, NULL);
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

static enum net_scan_status
network_scan_status (struct arglist *globals)
{
  gchar *nss;

  nss = arg_get_value (globals, "network_scan_status");
  if (nss == NULL)
    return NSS_NONE;

  if (g_ascii_strcasecmp (nss, "busy") == 0)
    return NSS_BUSY;
  else if (g_ascii_strcasecmp (nss, "done") == 0)
    return NSS_DONE;
  else
    return NSS_NONE;
}

int global_scan_stop = 0;

static int
scan_is_stopped ()
{
 return global_scan_stop;
}

int global_stop_all_scans = 0;

static int
all_scans_are_stopped ()
{
 return global_stop_all_scans;
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
  /* XXX: Duplicated from openvas-libraries. */
  if (category == ACT_DESTRUCTIVE_ATTACK || category == ACT_KILL_HOST
      || category == ACT_FLOOD || category == ACT_DENIAL)
    return 0;
  return 1;
}


/**
 * @brief Launches a nvt. Respects safe check preference (i.e. does not try
 * @brief destructive nvt if save_checks is yes).
 *
 * Does not launch a plugin twice if !save_kb_replay.
 *
 * @param new_kb  If TRUE, kb is new and shall be saved.
 *
 * @return ERR_HOST_DEAD if host died, ERR_CANT_FORK if forking failed,
 *         0 otherwise.
 */
static int
launch_plugin (struct arglist *globals, struct scheduler_plugin *plugin,
               char *hostname, struct host_info *hostinfos, kb_t kb)
{
  int optimize = prefs_get_bool ("optimize_test");
  int category;
  char *oid, *name;
  gboolean network_scan = FALSE;

  oid = plugin->oid;
  category = nvticache_get_category (oid);
  name = nvticache_get_filename (oid);
  if (scan_is_stopped () || all_scans_are_stopped())
    {
      if (category != ACT_LAST)
        {
          plugin->running_state = PLUGIN_STATUS_DONE;
          g_free (name);
          return 0;
        }
      else
        log_write ("Stopped scan wrap-up: Launching %s (%s)", name, oid);
    }

  if (network_scan_status (globals) == NSS_BUSY)
    network_scan = TRUE;

  /* can we launch it ? */
  if (plugin->enabled)
    {
      char *error;

      if (prefs_get_bool ("safe_checks") && !nvti_category_is_safe (category))
        {
          if (prefs_get_bool ("log_whole_attack"))
            log_write
              ("Not launching %s (%s) against %s because safe checks are"
               " enabled (this is not an error)", name, oid, hostname);
          plugin->running_state = PLUGIN_STATUS_DONE;
          g_free (name);
          return 0;
        }

      if (network_scan)
        {
          char asc_id[100];

          assert (oid);
          snprintf (asc_id, sizeof (asc_id), "Launched/%s", oid);

          if (kb_item_get_int (kb, asc_id) > 0)
            {
              if (prefs_get_bool ("log_whole_attack"))
                log_write ("Not launching %s against %s because it has already "
                           "been lanched in the past (this is not an error)",
                           oid, hostname);
              plugin->running_state = PLUGIN_STATUS_DONE;
              g_free (name);
              return 0;
            }
          else
            {
              kb_item_add_int (kb, asc_id, 1);
            }
        }

      /* Do not launch NVT if mandatory key is missing (e.g. an important tool
       * was not found). This is ignored during network wide scanning phases. */
      if (network_scan || mandatory_requirements_met (kb, plugin))
        error = NULL;
      else
        error = "because a mandatory key is missing";

      /* Stop the test if the host is 'dead' */
      if (kb_item_get_int (kb, "Host/dead") > 0)
        {
          log_write ("The remote host %s (%s) is dead", hostinfos->fqdn, hostname);
          pluginlaunch_stop (1);
          plugin->running_state = PLUGIN_STATUS_DONE;
          g_free (name);
          return ERR_HOST_DEAD;
        }

      if (!error
          && (!optimize
              || !(error = requirements_plugin (kb, plugin))))
        {
          int pid;
          char *src;

          src = nvticache_get_src (oid);
          /* Start the plugin */
          pid = plugin_launch (globals, plugin, hostinfos, kb, src);
          g_free (src);
          if (pid < 0)
            {
              plugin->running_state = PLUGIN_STATUS_UNRUN;
              g_free (name);
              return ERR_CANT_FORK;
            }

          if (prefs_get_bool ("log_whole_attack"))
            log_write ("Launching %s (%s) against %s [%d]", name, oid, hostname,
                       pid);
        }
      else                      /* requirements_plugin() failed */
        {
          plugin->running_state = PLUGIN_STATUS_DONE;
          if (prefs_get_bool ("log_whole_attack"))
            log_write
              ("Not launching %s (%s) against %s %s (this is not an error)",
               name, oid, hostname, error);
        }
    }                           /* if(plugins->launch) */
  else
    plugin->running_state = PLUGIN_STATUS_DONE;

  g_free (name);
  return 0;
}

static int
kb_duplicate(kb_t dst, kb_t src, const gchar *filter)
{
  struct kb_item *items, *p_itm;

  items = kb_item_get_pattern(src, filter ? filter : "*");
  for (p_itm = items; p_itm != NULL; p_itm = p_itm->next)
    {
      gchar *newname;

      newname = strstr(p_itm->name, "/");
      if (newname == NULL)
        newname = p_itm->name;
      else
        newname += 1; /* Skip the '/' */

      kb_item_add_str(dst, newname, p_itm->v_str);
    }
  return 0;
}

/**
 * @brief Inits or loads the knowledge base for a single host.
 *
 * Fills the knowledge base with host-specific login information for local
 * checks if defined.
 *
 * @param globals     Global preference arglist.
 * @param hostname    Name of the host.
 * @param new_kb[out] TRUE if the kb is new and shall be saved.
 *
 * @return A knowledge base.
 */
static kb_t
init_host_kb (struct arglist *globals, char *hostname,
              struct host_info *hostinfos, kb_t *network_kb)
{
  kb_t kb;
  gchar *vhosts, *hostname_pattern, *hoststr;
  enum net_scan_status nss;
  const gchar *kb_path = prefs_get ("kb_location");
  int rc, soc;
  struct in6_addr *hostip;

  nss = network_scan_status (globals);
  soc = arg_get_value_int (globals, "global_socket");
  switch (nss)
    {
      case NSS_DONE:
        rc = kb_new (&kb, kb_path);
        if (rc)
          {
            report_kb_failure (soc, rc);
            return NULL;
          }

        hostname_pattern = g_strdup_printf ("%s/*", hostname);
        kb_duplicate(kb, *network_kb, hostname_pattern);
        g_free(hostname_pattern);
        break;

      case NSS_BUSY:
        assert (network_kb != NULL);
        assert (*network_kb != NULL);
        kb = *network_kb;
        break;

      default:
        rc = kb_new (&kb, kb_path);
        if (rc)
          {
            report_kb_failure (soc, rc);
            return NULL;
          }
    }

  /* Add Hostname and Host-IP */
  hoststr = hostinfos->fqdn;
  if (hoststr)
    kb_item_add_str (kb, "Hostname", hoststr);
  hostip = hostinfos->ip;
  if (hostip)
    {
      char ipstr[INET6_ADDRSTRLEN];

      if (IN6_IS_ADDR_V4MAPPED (hostip))
        inet_ntop (AF_INET, ((char *) (hostip)) + 12, ipstr, sizeof (ipstr));
      else
        inet_ntop (AF_INET6, hostip, ipstr, sizeof (ipstr));
      kb_item_add_str (kb, "Host-IP", ipstr);
    }

  /* If vhosts is set, split it and put it in the KB. */
  vhosts = hostinfos->vhosts;
  if (vhosts)
    {
      gchar **vhosts_array = g_strsplit (vhosts, ",", 0);
      int i;

      for (i = 0; vhosts_array[i] != NULL; i++)
        kb_item_add_str (kb, "hostinfos/vhosts", vhosts_array[i]);

      g_strfreev (vhosts_array);
    }

  return kb;
}

/**
 * @brief Attack one host.
 */
static void
attack_host (struct arglist *globals, struct host_info *hostinfos,
             char *hostname, plugins_scheduler_t sched, kb_t *net_kb)
{
  /* Used for the status */
  int num_plugs, forks_retry = 0, global_socket;
  kb_t kb;

  proctitle_set ("openvassd: testing %s", hostinfos->name);

  global_socket = arg_get_value_int (globals, "global_socket");
  kb = init_host_kb (globals, hostname, hostinfos, net_kb);
  if (kb == NULL)
    return;

  kb_lnk_reset (kb);

  /* launch the plugins */
  pluginlaunch_init (hostinfos->name);
  num_plugs = plugins_scheduler_count_active (sched);
  for (;;)
    {
      struct scheduler_plugin *plugin;
      pid_t parent;

      /* Check that our father is still alive */
      parent = getppid ();
      if (parent <= 1 || process_alive (parent) == 0)
        {
          pluginlaunch_stop (1);
          return;
        }

      plugin = plugins_scheduler_next (sched);
      if (plugin != NULL && plugin != PLUG_RUNNING)
        {
          int e;
          static int last_status = 0, cur_plug = 0;

        again:
          e = launch_plugin (globals, plugin, hostname, hostinfos, kb);
          if (e < 0)
            {
              /*
               * Remote host died
               */
              if (e == ERR_HOST_DEAD)
                {
                  char buffer[2048];
                  snprintf
                   (buffer, sizeof (buffer),
                    "SERVER <|> LOG <|> %s <|> general/Host_Details"
                    " <|> <host><detail><name>Host dead</name>"
                    "<value>1</value><source><description/><type/>"
                    "<name/></source></detail></host> <|>  <|> SERVER\n",
                    hostname ?: "");
#if (PROGRESS_BAR_STYLE == 1)
                  /* In case of a dead host, it sends max_ports = -1 to the
                     manager. The host will not be taken into account to
                     calculate the scan progress. */
                  comm_send_status(global_socket, hostname, 0, -1);
#endif
                  internal_send (global_socket, buffer,
                                 INTERNAL_COMM_MSG_TYPE_DATA);
                  goto host_died;
                }
              else if (e == ERR_CANT_FORK)
                {
                  if (forks_retry < MAX_FORK_RETRIES)
                    {
                      forks_retry++;
                      log_write ("fork() failed - sleeping %d seconds (%s)",
                                 forks_retry, strerror (errno));
                      fork_sleep (forks_retry);
                      goto again;
                    }
                  else
                    {
                      log_write ("fork() failed too many times - aborting");
                      goto host_died;
                    }
                }
            }

          if ((cur_plug * 100) / num_plugs >= last_status
              && !scan_is_stopped () && !all_scans_are_stopped())
            {
              last_status = (cur_plug * 100) / num_plugs + 2;
              if (comm_send_status
                   (global_socket, hostname, cur_plug, num_plugs) < 0)
                {
                  pluginlaunch_stop (1);
                  goto host_died;
                }
            }
          cur_plug++;
        }
      else if (plugin == NULL)
        break;
      else
        pluginlaunch_wait_for_free_process ();
    }

  pluginlaunch_wait ();
  if (!scan_is_stopped () && !all_scans_are_stopped())
    comm_send_status (global_socket, hostname, num_plugs, num_plugs);

host_died:
  pluginlaunch_stop (1);
  plugins_scheduler_free (sched);

  if (net_kb == NULL || kb != *net_kb)
    kb_delete (kb);
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
host_authorized (const openvas_host_t *host, const struct in6_addr *addr,
                 const openvas_hosts_t *hosts_allow,
                 const openvas_hosts_t *hosts_deny)
{
  /* Check Hosts Access. */
  if (host == NULL)
    return 0;

  if (hosts_deny && openvas_host_in_hosts (host, addr, hosts_deny))
    return 0;
  if (hosts_allow && !openvas_host_in_hosts (host, addr, hosts_allow))
    return 0;

  return 1;
}

/**
 * @brief Set up some data and jump into attack_host()
 */
static void
attack_start (struct attack_start_args *args)
{
  struct arglist *globals = args->globals;
  char *host_str, *hostname;
  struct in6_addr hostip;
  struct host_info *hostinfos;
  const char *non_simult = prefs_get ("non_simult_ports");
  const char *vhosts = prefs_get ("vhosts");
  const char *vhosts_ip = prefs_get ("vhosts_ip");
  int thread_socket;
  struct timeval then;
  plugins_scheduler_t sched = args->sched;
  kb_t *net_kb = args->net_kb;
  openvas_hosts_t *hosts_allow, *hosts_deny;
  openvas_hosts_t *sys_hosts_allow, *sys_hosts_deny;


  nvticache_reset ();
  close (args->parent_socket);
  thread_socket = args->thread_socket;
  gettimeofday (&then, NULL);

  arg_add_value (preferences_get (), "non_simult_ports_list", ARG_ARGLIST,
                 (void *) list2arglist ((char *)non_simult));

  /* Options regarding the communication with our parent */
  close (arg_get_value_int (globals, "parent_socket"));
  arg_del_value (globals, "parent_socket");
  openvas_deregister_connection (arg_get_value_int (globals, "global_socket"));
  arg_set_value (globals, "global_socket", GSIZE_TO_POINTER (thread_socket));

  hostname = openvas_host_reverse_lookup (args->host);
  if (!hostname)
    hostname = openvas_host_value_str (args->host);
  if (openvas_host_get_addr6 (args->host, &hostip) == -1)
    {
      log_write ("Couldn't resolve target %s", hostname);
      error_message_to_client (thread_socket, "Couldn't resolve hostname.",
                               hostname, NULL);
      return;
    }

  /* Do we have the right to test this host ? */
  hosts_allow = openvas_hosts_new (prefs_get ("hosts_allow"));
  hosts_deny = openvas_hosts_new (prefs_get ("hosts_deny"));
  if (!host_authorized (args->host, &hostip, hosts_allow, hosts_deny))
    {
      error_message_to_client
       (thread_socket, "Host access denied.", hostname, NULL);
      log_write ("Host %s access denied.", hostname);
      return;
    }
  sys_hosts_allow = openvas_hosts_new (prefs_get ("sys_hosts_allow"));
  sys_hosts_deny = openvas_hosts_new (prefs_get ("sys_hosts_deny"));
  if (!host_authorized (args->host, &hostip, sys_hosts_allow, sys_hosts_deny))
    {
      error_message_to_client
       (thread_socket, "Host access denied (system-wide restriction.)",
        hostname, NULL);
      log_write ("Host %s access denied (sys_* preference restriction.)",
                 hostname);
      return;
    }
  openvas_hosts_free (hosts_allow);
  openvas_hosts_free (hosts_deny);
  openvas_hosts_free (sys_hosts_allow);
  openvas_hosts_free (sys_hosts_deny);

  host_str = addr6_as_str (&hostip);
  if (vhosts == NULL || vhosts_ip == NULL)
    hostinfos = host_info_init (host_str, &hostip, NULL, hostname);
  else
    {
      char *txt_ip;

      txt_ip = addr6_as_str (&hostip);
      if (strcmp (vhosts_ip, txt_ip) != 0)
        vhosts = NULL;
      g_free (txt_ip);
      hostinfos = host_info_init (host_str, &hostip, vhosts, hostname);
    }
  ntp_timestamp_host_scan_starts (thread_socket, host_str);
  log_write ("Testing %s (%s) [%d]", hostname, host_str, getpid ());

  // Start scan
  attack_host (globals, hostinfos, host_str, sched, net_kb);
  host_info_free (hostinfos);

  if (!scan_is_stopped () && !all_scans_are_stopped ())
    {
      struct timeval now;

      ntp_timestamp_host_scan_ends (thread_socket, host_str);
      gettimeofday (&now, NULL);
      if (now.tv_usec < then.tv_usec)
        {
          then.tv_sec++;
          now.tv_usec += 1000000;
        }
      log_write ("Finished testing %s (%s). Time : %ld.%.2ld secs",
		 hostname, host_str, (long) (now.tv_sec - then.tv_sec),
                 (long) ((now.tv_usec - then.tv_usec) / 10000));
    }
  shutdown (thread_socket, 2);
  close (thread_socket);
  g_free (hostname);
  g_free (host_str);
}

static void
apply_hosts_preferences (openvas_hosts_t *hosts)
{
  const char *ordering = prefs_get ("hosts_ordering"),
             *exclude_hosts = prefs_get ("exclude_hosts");

  if (hosts == NULL)
    return;

  /* Hosts ordering strategy: sequential, random, reversed... */
  if (ordering)
    {
      if (!strcmp (ordering, "random"))
        {
          openvas_hosts_shuffle (hosts);
          log_write ("hosts_ordering: Random.");
        }
      else if (!strcmp (ordering, "reverse"))
        {
          openvas_hosts_reverse (hosts);
          log_write ("hosts_ordering: Reverse.");
        }
    }
  else
    log_write ("hosts_ordering: Sequential.");

  /* Exclude hosts ? */
  if (exclude_hosts)
    {
      /* Exclude hosts, resolving hostnames. */
      int ret = openvas_hosts_exclude (hosts, exclude_hosts, 1);

      if (ret >= 0)
        log_write ("exclude_hosts: Skipped %d host(s).", ret);
      else
        log_write ("exclude_hosts: Error.");
    }

  /* Reverse-lookup unify ? */
  if (prefs_get_bool ("reverse_lookup_unify"))
    log_write ("reverse_lookup_unify: Skipped %d host(s).",
               openvas_hosts_reverse_lookup_unify (hosts));

  /* Hosts that reverse-lookup only ? */
  if (prefs_get_bool ("reverse_lookup_only"))
    log_write ("reverse_lookup_only: Skipped %d host(s).",
               openvas_hosts_reverse_lookup_only (hosts));
}

static int
str_in_comma_list (const char *str, const char *comma_list)
{
  gchar **element, **split;

  if (str == NULL || comma_list == NULL)
    return 0;

  split = g_strsplit (comma_list, ",", 0);
  element = split;
  while (*element)
    {
      gchar *stripped = g_strstrip (*element);

      if (stripped && strcmp (stripped, str) == 0)
        {
          g_strfreev (split);
          return 1;
        }

      element++;
    }

  g_strfreev (split);
  return 0;
}

/*
 * Checks if a network interface is authorized to be used as source interface.
 *
 * @return 0 if iface is NULL, -1 if unauthorized by ifaces_deny/ifaces_allow,
 * -2 if by sys_ifaces_deny/sys_ifaces_allow, 1 otherwise.
 */
static int
iface_authorized (const char *iface)
{
  const char *ifaces_list;

  if (iface == NULL)
    return 0;

  ifaces_list = prefs_get ("ifaces_deny");
  if (ifaces_list && str_in_comma_list (iface, ifaces_list))
    return -1;
  ifaces_list = prefs_get ("ifaces_allow");
  if (ifaces_list && !str_in_comma_list (iface, ifaces_list))
    return -1;
  /* sys_* preferences are similar, but can't be overriden by the client. */
  ifaces_list = prefs_get ("sys_ifaces_deny");
  if (ifaces_list && str_in_comma_list (iface, ifaces_list))
    return -2;
  ifaces_list = prefs_get ("sys_ifaces_allow");
  if (ifaces_list && !str_in_comma_list (iface, ifaces_list))
    return -2;

  return 1;
}

/*
 * Applies the source_iface scanner preference, if allowed by ifaces_allow and
 * ifaces_deny preferences.
 *
 * @return 0 if source_iface preference applied or not found, -1 if
 * unauthorized value, -2 if iface can't be used.
 */
static int
apply_source_iface_preference (int soc)
{
  const char *source_iface = prefs_get ("source_iface");
  int ret;

  if (source_iface == NULL)
    return 0;

  ret = iface_authorized (source_iface);
  if (ret == -1)
    {
      gchar *msg = g_strdup_printf ("Unauthorized source interface: %s",
                                    source_iface);
      log_write ("source_iface: Unauthorized source interface %s.",
                 source_iface);
      error_message_to_client (soc, msg, NULL, NULL);

      g_free (msg);
      return -1;
    }
  else if (ret == -2)
    {
      gchar *msg = g_strdup_printf ("Unauthorized source interface: %s"
                                    " (system-wide restriction.)",
                                    source_iface);
      log_write ("source_iface: Unauthorized source interface %s."
                 " (sys_* preference restriction.)",
                 source_iface);
      error_message_to_client (soc, msg, NULL, NULL);

      g_free (msg);
      return -1;
    }

  if (openvas_source_iface_init (source_iface))
    {
      gchar *msg = g_strdup_printf ("Erroneous source interface: %s",
                                    source_iface);
      log_write ("source_iface: Error with %s interface.", source_iface);
      error_message_to_client (soc, msg, NULL, NULL);

      g_free (msg);
      return -2;
    }
  else
    {
      char *ipstr, *ip6str;
      ipstr = openvas_source_addr_str ();
      ip6str = openvas_source_addr6_str ();
      log_write ("source_iface: Using %s (%s / %s).", source_iface,
                 ipstr, ip6str);

      g_free (ipstr);
      g_free (ip6str);
      return 0;
    }
}

static int
check_kb_access (int soc)
{
  int rc;
  kb_t kb;

  rc = kb_new (&kb, prefs_get ("kb_location"));
  if (rc)
      report_kb_failure (soc, rc);
  else
    kb_delete (kb);

  return rc;
}

static void
handle_scan_stop_signal ()
{
  pluginlaunch_stop (0);
  global_scan_stop = 1;
}

static void
handle_stop_all_scans_signal ()
{
  global_stop_all_scans = 1;
  hosts_stop_all ();
}

/**
 * @brief Attack a whole network.
 */
void
attack_network (struct arglist *globals, kb_t *network_kb)
{
  int max_hosts = 0, max_checks;
  const char *hostlist;
  openvas_host_t *host;
  int global_socket = -1;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  GHashTable *files;
  struct timeval then, now;
  openvas_hosts_t *hosts;

  const gchar *network_targets, *port_range;
  gboolean network_phase = FALSE;
  gboolean do_network_scan = FALSE;

  gettimeofday (&then, NULL);

  if (prefs_get_bool ("network_scan"))
    do_network_scan = TRUE;
  else
    do_network_scan = FALSE;

  network_targets = prefs_get ("network_targets");
  if (network_targets != NULL)
    arg_add_value (globals, "network_targets", ARG_STRING,
                   (char *) network_targets);

  if (do_network_scan)
    {
      enum net_scan_status nss;

      nss = network_scan_status (globals);
      switch (nss)
        {
          case NSS_DONE:
            network_phase = FALSE;
            break;

          case NSS_BUSY:
            network_phase = TRUE;
            break;

          default:
            arg_add_value (globals, "network_scan_status", ARG_STRING,
                           "busy");
            network_phase = TRUE;
            break;
        }
    }
  else
    network_kb = NULL;

  global_socket = arg_get_value_int (globals, "global_socket");
  if (check_kb_access(global_socket))
      return;

  /* Init and check Target List */
  hostlist = prefs_get ("TARGET");
  if (hostlist == NULL)
    {
      error_message_to_client (global_socket, "Missing target hosts", NULL,
                               NULL);
      return;
    }

  /* Verify the port range is a valid one */
  port_range = prefs_get ("port_range");
  if (validate_port_range (port_range))
    {
      error_message_to_client (global_socket, "Invalid port range", NULL,
                               port_range);
      return;
    }

  /* Initialize the attack. */
  sched = plugins_scheduler_init
           (prefs_get ("plugin_set"), prefs_get_bool ("auto_enable_dependencies"),
            network_phase);

  max_hosts = get_max_hosts_number ();
  max_checks = get_max_checks_number ();

  if (network_phase)
    {
      if (network_targets == NULL)
        {
          log_write ("WARNING: In network phase, but without targets! Stopping.");
          host = NULL;
        }
      else
        {
          int rc;

          log_write ("Start a new scan. Target(s) : %s, "
                     "in network phase with target %s",
                     hostlist, network_targets);

          rc = kb_new (network_kb, prefs_get ("kb_location"));
          if (rc)
            {
              report_kb_failure (global_socket, rc);
              host = NULL;
            }
          else
            kb_lnk_reset (*network_kb);
        }
    }
  else
    {
      log_write ("Starts a new scan. Target(s) : %s, with max_hosts = %d and "
                 "max_checks = %d", hostlist, max_hosts, max_checks);
    }

  hosts = openvas_hosts_new (hostlist);
  /* Apply Hosts preferences. */
  apply_hosts_preferences (hosts);

  /* Don't start if the provided interface is unauthorized. */
  if (apply_source_iface_preference (global_socket) != 0)
    {
      openvas_hosts_free (hosts);
      error_message_to_client
       (global_socket, "Interface not authorized for scanning", NULL, NULL);
      return;
    }
  host = openvas_hosts_next (hosts);
  if (host == NULL)
    goto stop;
  hosts_init (global_socket, max_hosts);
  /*
   * Start the attack !
   */
  openvas_signal (SIGUSR1, handle_scan_stop_signal);
  openvas_signal (SIGUSR2, handle_stop_all_scans_signal);
  while (host && !scan_is_stopped () && !all_scans_are_stopped())
    {
      int pid;
      struct attack_start_args args;
      char *host_str;
      int soc[2];

      host_str = openvas_host_value_str (host);
      if (socketpair (AF_UNIX, SOCK_STREAM, 0, soc) < 0
          || hosts_new (globals, host_str, soc[1]) < 0)
        {
          g_free (host_str);
          goto scan_stop;
        }

      if (scan_is_stopped () || all_scans_are_stopped ())
        {
          close (soc[0]);
          close (soc[1]);
          g_free (host_str);
          continue;
        }
      args.host = host;
      args.globals = globals;
      args.sched = sched;
      args.thread_socket = soc[0];
      args.parent_socket = soc[1];
      args.net_kb = network_kb;

    forkagain:
      pid = create_process ((process_func_t) attack_start, &args);
      /* Close child process' socket. */
      close (args.thread_socket);
      if (pid < 0)
        {
          fork_retries++;
          if (fork_retries > MAX_FORK_RETRIES)
            {
              /* Forking failed - we go to the wait queue. */
              log_write ("fork() failed - %s. %s won't be tested",
                         strerror (errno), host_str);
              g_free (host_str);
              goto stop;
            }

          log_write ("fork() failed - "
                     "sleeping %d seconds and trying again...",
                     fork_retries);
          fork_sleep (fork_retries);
          goto forkagain;
        }
      hosts_set_pid (host_str, pid);
      if (network_phase)
        log_write ("Testing %s (network level) [%d]",
                   network_targets, pid);

      if (network_phase)
        {
          host = NULL;
          arg_set_value (globals, "network_scan_status", "done");
        }
      else
          host = openvas_hosts_next (hosts);
      g_free (host_str);
    }

  /* Every host is being tested... We have to wait for the processes
   * to terminate. */
  while (hosts_read (globals) == 0)
    ;

  log_write ("Test complete");

scan_stop:
  /* Free the memory used by the files uploaded by the user, if any. */
  files = arg_get_value (globals, "files_translation");
  if (files)
    g_hash_table_destroy (files);

stop:
  if (all_scans_are_stopped ())
    {
      error_message_to_client
        (global_socket, "The whole scan was stopped. "
         "Fatal Redis connection error.", "", NULL);
    }
  plugins_scheduler_free (sched);

  gettimeofday (&now, NULL);
  log_write ("Total time to scan all hosts : %ld seconds",
             now.tv_sec - then.tv_sec);

  if (do_network_scan && network_phase &&
      !scan_is_stopped () && !all_scans_are_stopped ())
    attack_network (globals, network_kb);
}
