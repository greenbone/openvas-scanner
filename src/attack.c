/* OpenVAS
* $Id$
* Description: Launches the plugins, and manages multithreading.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*          - Geoff Galitz <mailto:geoff@eifel-consulting.eu (Minor debug edits)
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

#include <gvm/base/networking.h>
#include <gvm/base/hosts.h>
#include <gvm/base/proctitle.h>
#include <gvm/base/prefs.h>              /* for prefs_get() */
#include <gvm/util/kb.h>
#include <gvm/util/nvticache.h>          /* for nvticache_t */

#include "../misc/network.h"        /* for auth_printf */
#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "../misc/pcap_openvas.h"   /* for v6_is_local_ip */
#include "../misc/scanneraux.h"

#include "attack.h"
#include "comm.h"
#include "hosts.h"
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
  kb_t *net_kb;
  kb_t host_kb;
  gvm_host_t *host;
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
comm_send_status (kb_t kb, char *hostname, int curr, int max)
{
  char buffer[2048];

  if (!hostname || !kb)
    return -1;

  if (strlen (hostname) > (sizeof (buffer) - 50))
    return -1;

  snprintf (buffer, sizeof (buffer), "%d/%d", curr, max);
  kb_item_push_str (kb, "internal/status", buffer);

  return 0;
}

static void
error_message_to_client (int soc, const char *msg, const char *hostname,
                         const char *port)
{
  if (is_otp_scan ())
    send_printf
      (soc, "SERVER <|> ERRMSG <|> %s <|>  <|> %s <|> %s <|>  <|> SERVER\n",
       hostname ?: "", port ?: "", msg ?: "No error.");
}

static void
error_message_to_client2 (kb_t kb, const char *msg, const char *port)
{
  char buf[2048];

  sprintf (buf, "ERRMSG||| |||%s||| |||%s", port ?: " ", msg ?: "No error.");
  kb_item_push_str (kb, "internal/results", buf);
}

static void
report_kb_failure (int soc, int errcode)
{
  gchar *msg;

  errcode = abs (errcode);
  msg = g_strdup_printf ("WARNING: Cannot connect to KB at '%s': %s'",
                         prefs_get ("db_address"), strerror (errcode));
  g_warning ("%s", msg);
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
network_scan_status (struct scan_globals *globals)
{
  gchar *nss;

  nss = globals->network_scan_status;
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
  /* XXX: Duplicated from openvas-scanner/nasl. */
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
 * @return ERR_HOST_DEAD if host died, ERR_CANT_FORK if forking failed,
 *         0 otherwise.
 */
static int
launch_plugin (struct scan_globals *globals, struct scheduler_plugin *plugin,
               struct in6_addr *ip, GSList *vhosts, kb_t kb)
{
  int optimize = prefs_get_bool ("optimize_test"), pid;
  char *oid, *name, *error = NULL, ip_str[INET6_ADDRSTRLEN];
  gboolean network_scan = FALSE;
  nvti_t *nvti;

  addr6_to_str (ip, ip_str);
  oid = plugin->oid;
  nvti = nvticache_get_nvt (oid);
  name = nvticache_get_filename (oid);
  if (scan_is_stopped () || all_scans_are_stopped ())
    {
      if (nvti->category != ACT_LAST)
        {
          plugin->running_state = PLUGIN_STATUS_DONE;
          g_free (name);
          return 0;
        }
      else
        g_message ("Stopped scan wrap-up: Launching %s (%s)", name, oid);
    }

  if (network_scan_status (globals) == NSS_BUSY)
    network_scan = TRUE;

  if (prefs_get_bool ("safe_checks") && !nvti_category_is_safe (nvti->category))
    {
      if (prefs_get_bool ("log_whole_attack"))
        g_message ("Not launching %s (%s) against %s because safe checks are"
                   " enabled (this is not an error)", name, oid, ip_str);
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
            g_message ("Not launching %s against %s because it has already "
                       "been lanched in the past (this is not an error)",
                       oid, ip_str);
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
  if (!network_scan && !mandatory_requirements_met (kb, nvti))
    error = "because a mandatory key is missing";
  if (error || (optimize && (error = requirements_plugin (kb, nvti))))
    {
      plugin->running_state = PLUGIN_STATUS_DONE;
      if (prefs_get_bool ("log_whole_attack"))
        g_message ("Not launching %s (%s) against %s %s (this is not an error)",
          name, oid, ip_str, error);
      g_free (name);
      return 0;
    }

  /* Stop the test if the host is 'dead' */
  if (kb_item_get_int (kb, "Host/dead") > 0)
    {
      g_message ("The remote host %s is dead", ip_str);
      pluginlaunch_stop (1);
      plugin->running_state = PLUGIN_STATUS_DONE;
      g_free (name);
      return ERR_HOST_DEAD;
    }

  /* Start the plugin */
  pid = plugin_launch (globals, plugin, ip, vhosts, kb, nvti);
  nvti_free (nvti);
  if (pid < 0)
    {
      plugin->running_state = PLUGIN_STATUS_UNRUN;
      g_free (name);
      return ERR_CANT_FORK;
    }

  if (prefs_get_bool ("log_whole_attack"))
    g_message ("Launching %s (%s) against %s [%d]", name, oid, ip_str, pid);

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

      kb_item_add_str(dst, newname, p_itm->v_str, 0);
    }
  return 0;
}

/**
 * @brief Inits or loads the knowledge base for a single host.
 *
 * Fills the knowledge base with host-specific login information for local
 * checks if defined.
 *
 * @param globals     Global preference struct.
 * @param ip_str      IP string of target host.
 *
 * @return A knowledge base.
 */
static kb_t
init_host_kb (struct scan_globals *globals, char *ip_str, kb_t *network_kb)
{
  kb_t kb;
  gchar *hostname_pattern;
  enum net_scan_status nss;
  const gchar *kb_path = prefs_get ("db_address");
  int rc, soc;

  nss = network_scan_status (globals);
  soc = globals->global_socket;
  switch (nss)
    {
      case NSS_DONE:
        rc = kb_new (&kb, kb_path);
        if (rc)
          {
            report_kb_failure (soc, rc);
            return NULL;
          }

        hostname_pattern = g_strdup_printf ("%s/*", ip_str);
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

  return kb;
}

static kb_t host_kb = NULL;
static GSList *host_vhosts = NULL;

/**
 * @brief Check if a plugin process pushed a new vhost value.
 *
 * @param kb        Host scan KB.
 * @param vhosts    List of vhosts to add new vhosts to.
 *
 * @return New vhosts list.
 */
static void
check_new_vhosts ()
{
  char *value;

  while ((value = kb_item_pop_str (host_kb, "internal/vhosts")))
    {
      /* Get the source. */
      char buffer[4096], *source;
      gvm_vhost_t *vhost;

      g_snprintf (buffer, sizeof (buffer), "internal/source/%s", value);
      source = kb_item_pop_str (host_kb, buffer);
      assert (source);
      vhost = gvm_vhost_new (value, source);
      host_vhosts = g_slist_append (host_vhosts, vhost);
    }
}

/**
 * @brief Attack one host.
 */
static void
attack_host (struct scan_globals *globals, struct in6_addr *ip,
             GSList *vhosts, plugins_scheduler_t sched, kb_t kb, kb_t *net_kb)
{
  /* Used for the status */
  int num_plugs, forks_retry = 0;
  char ip_str[INET6_ADDRSTRLEN];

  addr6_to_str (ip, ip_str);
  openvas_signal (SIGUSR1, check_new_vhosts);
  host_kb = kb;
  host_vhosts = vhosts;
  kb_item_set_str (kb, "internal/ip", ip_str, 0);
  kb_item_set_int (kb, "internal/hostpid", getpid ());
  proctitle_set ("openvassd: testing %s", ip_str);
  if (net_kb && *net_kb)
    {
      kb_delete (kb);
      kb = init_host_kb (globals, ip_str, net_kb);
      if (kb == NULL)
        return;
    }
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
          pluginlaunch_stop (1);
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
          e = launch_plugin (globals, plugin, ip, vhosts, kb);
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
                    "LOG||| |||general/Host_Details||| |||<host><detail>"
                    "<name>Host dead</name><value>1</value><source>"
                    "<description/><type/><name/></source></detail></host>");
#if (PROGRESS_BAR_STYLE == 1)
                  /* In case of a dead host, it sends max_ports = -1 to the
                     manager. The host will not be taken into account to
                     calculate the scan progress. */
                  comm_send_status (kb, ip_str, 0, -1);
#endif
                  kb_item_push_str (kb, "internal/results", buffer);
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
              && !scan_is_stopped () && !all_scans_are_stopped ())
            {
              last_status = (cur_plug * 100) / num_plugs + 2;
              if (comm_send_status
                   (kb, ip_str, cur_plug, num_plugs) < 0)
                {
                  pluginlaunch_stop (1);
                  goto host_died;
                }
            }
          cur_plug++;
        }
      else if (plugin == NULL)
        break;
      pluginlaunch_wait_for_free_process (kb);
    }

  pluginlaunch_wait (kb);
  if (!scan_is_stopped () && !all_scans_are_stopped ())
    comm_send_status (kb, ip_str, num_plugs, num_plugs);

host_died:
  pluginlaunch_stop (1);
  plugins_scheduler_free (sched);
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
                 const gvm_hosts_t *hosts_allow,
                 const gvm_hosts_t *hosts_deny)
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
 * @brief Set up some data and jump into attack_host()
 */
static void
attack_start (struct attack_start_args *args)
{
  struct scan_globals *globals = args->globals;
  char ip_str[INET6_ADDRSTRLEN], *hostnames;
  struct in6_addr hostip;
  struct timeval then;
  plugins_scheduler_t sched = args->sched;
  kb_t *net_kb = args->net_kb;
  kb_t kb = args->host_kb;
  gvm_hosts_t *hosts_allow, *hosts_deny;
  gvm_hosts_t *sys_hosts_allow, *sys_hosts_deny;
  char key[1024];

  nvticache_reset ();
  kb_lnk_reset (kb);
  gettimeofday (&then, NULL);

  kb_item_add_str (kb, "internal/scan_id", globals->scan_id, 0);

  /* The reverse lookup is delayed to this step in order to not slow down the
   * main scan process eg. case of target with big range of IP addresses. */
  gvm_host_add_reverse_lookup (args->host);
  gvm_host_get_addr6 (args->host, &hostip);
  addr6_to_str (&hostip, ip_str);
  /* Do we have the right to test this host ? */
  hosts_allow = gvm_hosts_new (prefs_get ("hosts_allow"));
  hosts_deny = gvm_hosts_new (prefs_get ("hosts_deny"));
  if (!host_authorized (args->host, &hostip, hosts_allow, hosts_deny))
    {
      error_message_to_client2 (kb, "Host access denied.", NULL);
      g_warning ("Host %s access denied.", ip_str);
      return;
    }
  sys_hosts_allow = gvm_hosts_new (prefs_get ("sys_hosts_allow"));
  sys_hosts_deny = gvm_hosts_new (prefs_get ("sys_hosts_deny"));
  if (!host_authorized (args->host, &hostip, sys_hosts_allow, sys_hosts_deny))
    {
      error_message_to_client2
       (kb, "Host access denied (system-wide restriction.)", NULL);
      g_warning ("Host %s access denied (sys_* preference restriction.)",
                 ip_str);
      return;
    }
  gvm_hosts_free (hosts_allow);
  gvm_hosts_free (hosts_deny);
  gvm_hosts_free (sys_hosts_allow);
  gvm_hosts_free (sys_hosts_deny);

  if (prefs_get_bool ("test_empty_vhost"))
    {
      gvm_vhost_t *vhost = gvm_vhost_new
                            (g_strdup (ip_str), g_strdup ("IP-address"));
      args->host->vhosts = g_slist_prepend (args->host->vhosts, vhost);
    }
  hostnames = vhosts_to_str (args->host->vhosts);
  if (hostnames)
    g_message ("Testing %s (Vhosts: %s) [%d]", ip_str, hostnames, getpid ());
  else
    g_message ("Testing %s [%d]", ip_str, getpid ());
  g_free (hostnames);
  attack_host (globals, &hostip, args->host->vhosts, sched, kb, net_kb);

  snprintf (key, sizeof (key), "internal/%s", globals->scan_id);
  kb_item_add_str (kb, key, "finished", 0);

  if (!scan_is_stopped () && !all_scans_are_stopped ())
    {
      struct timeval now;

      gettimeofday (&now, NULL);
      if (now.tv_usec < then.tv_usec)
        {
          then.tv_sec++;
          now.tv_usec += 1000000;
        }
      g_message ("Finished testing %s. Time : %ld.%.2ld secs",
                 ip_str, (long) (now.tv_sec - then.tv_sec),
                 (long) ((now.tv_usec - then.tv_usec) / 10000));
    }
}

static void
apply_hosts_preferences (gvm_hosts_t *hosts)
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

  /* Exclude hosts ? */
  if (exclude_hosts)
    {
      /* Exclude hosts, resolving hostnames. */
      int ret = gvm_hosts_exclude (hosts, exclude_hosts, 1);

      if (ret >= 0)
        g_message ("exclude_hosts: Skipped %d host(s).", ret);
      else
        g_message ("exclude_hosts: Error.");
    }

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
      g_warning ("source_iface: Unauthorized source interface %s.",
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
      g_warning ("source_iface: Unauthorized source interface %s."
                 " (sys_* preference restriction.)",
                 source_iface);
      error_message_to_client (soc, msg, NULL, NULL);

      g_free (msg);
      return -1;
    }

  if (gvm_source_iface_init (source_iface))
    {
      gchar *msg = g_strdup_printf ("Erroneous source interface: %s",
                                    source_iface);
      g_debug ("source_iface: Error with %s interface.", source_iface);
      error_message_to_client (soc, msg, NULL, NULL);

      g_free (msg);
      return -2;
    }
  else
    {
      char *ipstr, *ip6str;
      ipstr = gvm_source_addr_str ();
      ip6str = gvm_source_addr6_str ();
      g_debug ("source_iface: Using %s (%s / %s).", source_iface,
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

  rc = kb_new (&kb, prefs_get ("db_address"));
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
attack_network (struct scan_globals *globals, kb_t *network_kb)
{
  int max_hosts = 0, max_checks;
  const char *hostlist;
  gvm_host_t *host;
  int global_socket = -1;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  GHashTable *files;
  struct timeval then, now;
  gvm_hosts_t *hosts;
  const gchar *network_targets, *port_range;
  gboolean network_phase = FALSE;
  gboolean do_network_scan = FALSE;
  kb_t host_kb;

  gettimeofday (&then, NULL);

  if (prefs_get_bool ("network_scan"))
    do_network_scan = TRUE;
  else
    do_network_scan = FALSE;

  network_targets = prefs_get ("network_targets");
  if (network_targets != NULL)
    globals->network_targets = g_strdup (network_targets);

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
            globals->network_scan_status = g_strdup ("busy");
            network_phase = TRUE;
            break;
        }
    }
  else
    network_kb = NULL;

  global_socket = globals->global_socket;
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
  if (!sched)
    {
      g_message ("Couldn't initialize the plugin scheduler");
      return;
    }

  max_hosts = get_max_hosts_number ();
  max_checks = get_max_checks_number ();

  if (network_phase)
    {
      if (network_targets == NULL)
        {
          g_warning ("WARNING: In network phase, but without targets! Stopping.");
          host = NULL;
        }
      else
        {
          int rc;

          g_message ("Start a new scan. Target(s) : %s, "
                     "in network phase with target %s",
                     hostlist, network_targets);

          rc = kb_new (network_kb, prefs_get ("db_address"));
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
    g_message ("Starts a new scan. Target(s) : %s, with max_hosts = %d and "
               "max_checks = %d", hostlist, max_hosts, max_checks);

  hosts = gvm_hosts_new (hostlist);
  gvm_hosts_resolve (hosts);
  /* Apply Hosts preferences. */
  apply_hosts_preferences (hosts);

  /* Don't start if the provided interface is unauthorized. */
  if (apply_source_iface_preference (global_socket) != 0)
    {
      gvm_hosts_free (hosts);
      error_message_to_client
       (global_socket, "Interface not authorized for scanning", NULL, NULL);
      return;
    }
  host = gvm_hosts_next (hosts);
  if (host == NULL)
    goto stop;
  hosts_init (global_socket, max_hosts);
  /*
   * Start the attack !
   */
  openvas_signal (SIGUSR1, handle_scan_stop_signal);
  openvas_signal (SIGUSR2, handle_stop_all_scans_signal);
  while (host && !scan_is_stopped () && !all_scans_are_stopped ())
    {
      int pid, rc;
      struct attack_start_args args;
      char *host_str;

      rc = kb_new (&host_kb, prefs_get ("db_address"));
      if (rc)
        {
          report_kb_failure (global_socket, rc);
          goto scan_stop;
        }
      host_str = gvm_host_value_str (host);
      if (hosts_new (globals, host_str, host_kb) < 0)
        {
          g_free (host_str);
          goto scan_stop;
        }

      if (scan_is_stopped () || all_scans_are_stopped ())
        {
          g_free (host_str);
          continue;
        }
      args.host = host;
      args.globals = globals;
      args.sched = sched;
      args.net_kb = network_kb;
      args.host_kb = host_kb;

    forkagain:
      pid = create_process ((process_func_t) attack_start, &args);
      /* Close child process' socket. */
      if (pid < 0)
        {
          fork_retries++;
          if (fork_retries > MAX_FORK_RETRIES)
            {
              /* Forking failed - we go to the wait queue. */
              g_debug ("fork() failed - %s. %s won't be tested",
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
      if (network_phase)
        g_message ("Testing %s (network level) [%d]",
                   network_targets, pid);

      if (network_phase)
        {
          host = NULL;
          globals->network_scan_status = g_strdup ("done");
        }
      else
        host = gvm_hosts_next (hosts);
      g_free (host_str);
    }

  /* Every host is being tested... We have to wait for the processes
   * to terminate. */
  while (hosts_read (globals) == 0)
    ;
  g_message ("Test complete");


scan_stop:
  /* Free the memory used by the files uploaded by the user, if any. */
  files = globals->files_translation;
  if (files)
    g_hash_table_destroy (files);

stop:

 if (all_scans_are_stopped ())
   {
     error_message_to_client
       (global_socket, "The whole scan was stopped. "
        "Fatal Redis connection error.", "", NULL);
   }

  gvm_hosts_free (hosts);
  g_free (globals->network_scan_status);
  g_free (globals->network_targets);

  plugins_scheduler_free (sched);

  gettimeofday (&now, NULL);
  g_message ("Total time to scan all hosts : %ld seconds",
             now.tv_sec - then.tv_sec);

  if (do_network_scan && network_phase &&
      !scan_is_stopped () && !all_scans_are_stopped ())
    attack_network (globals, network_kb);
}
