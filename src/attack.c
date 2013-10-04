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

#include <openvas/base/openvas_hosts.h>
#include <openvas/misc/kb.h>             /* for kb_new */
#include <openvas/misc/network.h>        /* for auth_printf */
#include <openvas/misc/nvt_categories.h> /* for ACT_INIT */
#include <openvas/misc/pcap_openvas.h>   /* for v6_is_local_ip */
#include <openvas/misc/plugutils.h>      /* for plug_get_launch */
#include <openvas/misc/proctitle.h>      /* for setproctitle */
#include <openvas/misc/system.h>         /* for emalloc */
#include <openvas/misc/scanners_utils.h> /* for comm_send_status */
#include <openvas/misc/openvas_ssh_login.h>

#include <openvas/base/nvticache.h>     /* for nvticache_t */

#include "attack.h"
#include "comm.h"
#include "hosts.h"
#include "log.h"
#include "ntp_11.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "preferences.h"
#include "processes.h"
#include "rules.h"
#include "save_kb.h"
#include "sighand.h"
#include "utils.h"


#define ERR_HOST_DEAD -1
#define ERR_CANT_FORK -2

#define MAX_FORK_RETRIES 10

extern u_short *getpts (char *, int *);

/**
 * Bundles information about target(s), configuration (globals arglist) and
 * scheduler.
 */
struct attack_start_args
{
  struct arglist *globals;
  struct in6_addr hostip;
  char *host_mac_addr;
  plugins_scheduler_t sched;
  int thread_socket;
  char hostname[1024];
};

/**
 * @brief Flag for pausing and resuming.
 */
static int pause_whole_test = 0;

/*******************************************************

		PRIVATE FUNCTIONS

********************************************************/


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

/**
 * @brief Set the pause_whole_test flag to pause the scan.
 */
static void
attack_handle_sigusr1 ()
{
  pause_whole_test = 1;
}

/**
 * @brief Set the pause_whole_test flag to resume the scan.
 */
static void
attack_handle_sigusr2 ()
{
  pause_whole_test = 0;
}

/**
 * @brief Inits an arglist which can be used by the plugins.
 *
 * The arglist will have following keys and (type, value):
 *  - NAME (string, The hostname parameter)
 *  - MAC  (string, The mac parameter if non-NULL)
 *  - IP   (*in_adrr, The ip parameter)
 *  - VHOSTS (string, comma separated list of vhosts for this IP)
 *
 * @param mac      MAC- adress of host or NULL.
 * @param hostname Hostname to be set.
 * @param ip       in_adress struct to be set.
 * @param vhosts   vhosts list to be set
 *
 * @return A 'hostinfo' arglist.
 */
static struct arglist *
attack_init_hostinfos_vhosts (char *mac, char *hostname, struct in6_addr *ip, char *vhosts)
{
  struct arglist *hostinfos;

  hostinfos = emalloc (sizeof (struct arglist));
  if (mac)
    {
      arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (mac), mac);
      arg_add_value (hostinfos, "MAC", ARG_STRING, strlen (mac), mac);
    }
  else
    arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (hostname),
                   estrdup (hostname));

  arg_add_value (hostinfos, "IP", ARG_PTR, sizeof (struct in6_addr), ip);
  if (vhosts)
    arg_add_value (hostinfos, "VHOSTS", ARG_STRING, strlen (vhosts),
                   estrdup (vhosts));
  return (hostinfos);
}

/**
 * @brief Inits an arglist which can be used by the plugins.
 *
 * The arglist will have following keys and (type, value):
 *  - NAME (string, The hostname parameter)
 *  - MAC  (string, The mac parameter if non-NULL)
 *  - IP   (*in_adrr, The ip parameter)
 *
 * @param mac      MAC- adress of host or NULL.
 * @param hostname Hostname to be set.
 * @param ip       in_adress struct to be set.
 *
 * @return A 'hostinfo' arglist.
 */
static struct arglist *
attack_init_hostinfos (char *mac, char *hostname, struct in6_addr *ip)
{
  struct arglist *hostinfos;

  hostinfos = emalloc (sizeof (struct arglist));
  if (mac)
    {
      arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (mac), mac);
      arg_add_value (hostinfos, "MAC", ARG_STRING, strlen (mac), mac);
    }
  else
    arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (hostname),
                   estrdup (hostname));

  arg_add_value (hostinfos, "IP", ARG_PTR, sizeof (struct in6_addr), ip);
  return (hostinfos);
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
launch_plugin (struct arglist *globals, plugins_scheduler_t * sched,
               struct scheduler_plugin *plugin, char *hostname, int *cur_plug,
               int num_plugs, struct arglist *hostinfos, struct kb_item **kb,
               gboolean new_kb)
{
  struct arglist *preferences = arg_get_value (globals, "preferences");
  struct arglist *args = plugin->arglist->value;
  char *oid = (char *)arg_get_value (args, "OID");
  nvticache_t *nvticache = (nvticache_t *)arg_get_value (
    arg_get_value (args, "preferences"), "nvticache");
  gchar *src = (oid == NULL ? NULL : nvticache_get_src_by_oid (nvticache, oid));
  char name[1024], oid_[100];
  int optimize = preferences_optimize_test (preferences);
  int category = plugin->category;
  static int last_status = 0;
  gchar *network_scan_status;
  gboolean network_scan = FALSE;

  strncpy (name, src, sizeof (name) - 1);
  name[sizeof (name) - 1] = '\0';
  g_free (src);

  // we need the oid later on and have many exits, so better
  // store it locally without need to free it.
  strncpy (oid_, oid, sizeof (oid_) - 1);
  oid_[sizeof (oid_) - 1] = '\0';

  network_scan_status = arg_get_value (globals, "network_scan_status");
  if (network_scan_status != NULL)
    if (g_ascii_strcasecmp (network_scan_status, "busy") == 0)
      network_scan = TRUE;

  if (plug_get_launch (args) != LAUNCH_DISABLED || category == ACT_SETTINGS)    /* can we launch it ? */
    {
      char *error;

      pl_class_t *cl_ptr = arg_get_value (args, "PLUGIN_CLASS");

      if (preferences_safe_checks_enabled (preferences)
          && (category == ACT_DESTRUCTIVE_ATTACK || category == ACT_KILL_HOST
              || category == ACT_FLOOD || category == ACT_DENIAL))
        {
          if (preferences_log_whole_attack (preferences))
            log_write
              ("Not launching %s against %s %s (this is not an error)\n",
               plugin->arglist->name, hostname,
               "because safe checks are enabled");
          plugin_set_running_state (plugin, PLUGIN_STATUS_DONE);
          return 0;
        }

      (*cur_plug)++;
      if ((*cur_plug * 100) / num_plugs >= last_status)
        {
          last_status = (*cur_plug * 100) / num_plugs + 2;
          if (comm_send_status
              (globals, hostname, "attack", *cur_plug, num_plugs) < 0)
            {
              /* Could not send our status back to our father -> exit */
              pluginlaunch_stop ();
              return ERR_HOST_DEAD;
            }
        }

      if (network_scan)
        {
          char asc_id[100];

          snprintf (asc_id, sizeof (asc_id), "Launched/%s", oid);

          if (kb_item_get_int (kb, asc_id) > 0)
            {
              if (preferences_log_whole_attack (preferences))
                log_write
                  ("Not launching %s against %s %s (this is not an error)\n",
                   plugin->arglist->name, hostname,
                   "because it has already been launched in the past");
              plugin_set_running_state (plugin, PLUGIN_STATUS_DONE);
              return 0;
            }
          else
            {
              kb_item_add_int (kb, asc_id, 1);
              save_kb_write_int (globals, "network", asc_id, 1);
            }
        }

      /* Do not launch NVT if mandatory key is missing (e.g. an important tool
       * was not found). This is ignored during network wide scanning phases. */
      if (network_scan || mandatory_requirements_met (kb, plugin))
        error = NULL;
      else
        error = "because a mandatory key is missing";

      if (!error
          && (!optimize
              || !(error = requirements_plugin (kb, plugin, preferences))))
        {
          int pid;

          /* Start the plugin */
          pid =
            plugin_launch (globals, sched, plugin, hostinfos, preferences, kb,
                           name, cl_ptr);
          if (pid < 0)
            {
              plugin_set_running_state (plugin, PLUGIN_STATUS_UNRUN);
              return ERR_CANT_FORK;
            }

          if (preferences_log_whole_attack (preferences))
            log_write ("Launching %s against %s [%d]\n",
                       plugin->arglist->name, hostname, pid);

          /* Stop the test if the host is 'dead' */
          if (kb_item_get_int (kb, "Host/dead") > 0
              || kb_item_get_int (kb, "Host/ping_failed") > 0)
            {
              log_write ("The remote host (%s) is dead\n", hostname);
              pluginlaunch_stop ();

              if (new_kb == TRUE)
                save_kb_close (globals, hostname);

              if (kb_item_get_int (kb, "Host/ping_failed") > 0)
                save_kb_restore_backup (hostname);

              plugin_set_running_state (plugin, PLUGIN_STATUS_DONE);
              return ERR_HOST_DEAD;
            }
        }
      else                      /* requirements_plugin() failed */
        {
          plugin_set_running_state (plugin, PLUGIN_STATUS_DONE);
          if (preferences_log_whole_attack (preferences))
            log_write
              ("Not launching %s against %s %s (this is not an error)\n",
               plugin->arglist->name, hostname,
               error);
        }
    }                           /* if(plugins->launch) */
  else
    plugin_set_running_state (plugin, PLUGIN_STATUS_DONE);

  return 0;
}

/**
 * @brief Returns true if str contains at least one '*' or '?'.
 *
 * @param str String that is understood to be a hostname or pattern.
 *
 * @return TRUE if str is understood to be a pattern (contains at least one '?'
 *         or '*').
 */
static gboolean
is_pattern (const char *str)
{
  // NOTE This function was copied from openvas-client/nvt_pref_sshlogin.c
  return (str != NULL
          && (strchr (str, '*') != NULL || strchr (str, '?') != NULL));
}

/**
 * @brief Predicate for a g_hash_table_find, true if pattern [key] matches
 * @brief hostname [userdata].
 *
 * @param key_pattern Key of a hashtable (callback), interpreted to be a pattern
 *                    to match hostname against.
 * @param value_login Value of a hashtable (callback).
 * @param hostname    Userdata, hostname to match pattern against.
 *
 * @return TRUE if key_pattern (glob-style, ? and * allowed) matches hostname.
 */
static gboolean
pattern_matches (char *key_pattern, char *value_login, char *hostname)
{
#ifndef NDEBUG
  printf ("SSH-DEBUG: Testing if %s is pattern\n", key_pattern);
#endif
  if (is_pattern (key_pattern) == FALSE)
    return FALSE;

#ifndef NDEBUG
  printf ("SSH-DEBUG: Testing Pattern %s against %s\n", key_pattern, hostname);
#endif
  if (g_pattern_match_simple (key_pattern, hostname) == TRUE)
    return TRUE;

  return FALSE;
}

/**
 * @brief Insert ssh login information for one host in its kb.
 *
 * If a map hosts --> sshlogins is defined, searches for an entry of the
 * hostname. If none is found, tries if any user-defined pattern matches.
 * If no pattern matches, falls back to the Default definition. If that
 * fails, too, nothing is done.
 *
 * @param kb       hostname's knowledge base to insert SSH credentials to.
 * @param globals  Global arglist where the mapping can be found.
 * @param hostname Name of the host of interest.
 */
static void
fill_host_kb_ssh_credentials (struct kb_item **kb, struct arglist *globals,
                              char *hostname)
{
  GHashTable *map_host_login_names = NULL;
  GHashTable *map_loginname_login = NULL;
  GHashTable *file_translation = NULL;
  char *accountname = NULL;
  openvas_ssh_login *login = NULL;

  map_host_login_names = arg_get_value (globals, "MAP_HOST_SSHLOGIN_NAME");
  map_loginname_login = arg_get_value (globals, "MAP_NAME_SSHLOGIN");

  if (map_host_login_names == NULL || map_loginname_login == NULL)
    {
#ifndef NDEBUG
      printf
        ("SSH-DEBUG: Host %s: no extended credentials configuration.\n",
         hostname);
#endif
      return;
    }

  // Look up the user assigned name for the login assigned explicitely to this host.
  accountname = g_hash_table_lookup (map_host_login_names, hostname);

  // Try to fetch login struct
  if (accountname != NULL)
    login = g_hash_table_lookup (map_loginname_login, accountname);

  // No login- account name for this host found? Seach if any pattern matches.
  if (accountname == NULL || login == NULL)
    {
#ifndef NDEBUG
      printf ("SSH-DEBUG: Trying to match patterns for login at %s\n",
              hostname);
#endif
      accountname =
        g_hash_table_find (map_host_login_names, (GHRFunc) pattern_matches,
                           hostname);
      // Try to fetch login struct
      if (accountname != NULL)
        login = g_hash_table_lookup (map_loginname_login, accountname);
    }

  // No pattern matching this host found? Try "Default".
  if (accountname == NULL || login == NULL)
    {
#ifndef NDEBUG
      printf ("SSH-DEBUG: Trying Default- account for local checks at %s\n",
              hostname);
#endif
      accountname = g_hash_table_lookup (map_host_login_names, "Default");

      // If none under 'Default' either, done.
      if (accountname == NULL)
        {
#ifndef NDEBUG
          printf
            ("SSH-DEBUG: Not setting login information for local checks at %s: No even Default account found.\n",
             hostname);
#endif
          return;
        }
      else
        {
          login = g_hash_table_lookup (map_loginname_login, accountname);
          // No login information for this login-account found? Strange, but so be it.
          if (login == NULL)
            {
#ifndef NDEBUG
              printf
                ("SSH-DEBUG: Could not find info for accountname '%s' for local checks at %s.\n",
                 accountname, hostname);
#endif
              return;
            }
        }
    }

#ifndef NDEBUG
  printf
    ("SSH-DEBUG: Resolving infos of account '%s' for local checks at %s.\n",
     accountname, hostname);
#endif

  // Get the translation table (remotefilepath -> localfilepath)
  file_translation = arg_get_value (globals, "files_translation");
  if (file_translation == NULL)
    return;

  // Fill knowledge base with host specific login information
  if (login->username)
    kb_item_set_str (kb, "Secret/SSH/login", login->username);

  if (login->userpassword)
    kb_item_set_str (kb, "Secret/SSH/password", login->userpassword);

  if (login->ssh_key_passphrase)
    kb_item_set_str (kb, "Secret/SSH/passphrase", login->ssh_key_passphrase);

  // For the key-files: look up content uploaded by client and set in kb
  if (login->public_key_path)
    {
      char *contents = g_hash_table_lookup (file_translation,
                                            login->public_key_path);
      if (contents)
        {
          kb_item_set_str (kb, "Secret/SSH/publickey", contents);
        }
    }
  if (login->private_key_path)
    {
      char *contents = g_hash_table_lookup (file_translation,
                                            login->private_key_path);
      if (contents)
        {
          kb_item_set_str (kb, "Secret/SSH/privatekey", contents);
        }
    }

#ifndef NDEBUG
  printf ("SSH-DEBUG: Resolved account name %s for local tests at %s\n",
          accountname, hostname);
#endif
}

// TODO eventually to be moved to libopenvas kb.c
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
 *
 * @see fill_host_kb_ssh_credentials
 */
static struct kb_item **
init_host_kb (struct arglist *globals, char *hostname, struct arglist *hostinfos, gboolean * new_kb)
{
  struct kb_item **kb;
  (*new_kb) = FALSE;
  char *vhosts = (char *) arg_get_value (hostinfos, "VHOSTS");
  struct kb_item **network_kb;
  struct kb_item *host_network_results = NULL;
  struct kb_item *result_iter;

  gchar *network_scan_status = (gchar *) arg_get_value (globals, "network_scan_status");
  if (network_scan_status != NULL)
    {
      if (g_ascii_strcasecmp (network_scan_status, "done") == 0)
        {
          gchar *hostname_pattern = g_strdup_printf ("%s/*", hostname);
          network_kb = save_kb_load_kb (globals, "network");
          host_network_results = kb_item_get_pattern (network_kb, hostname_pattern);
        }
      if (g_ascii_strcasecmp (network_scan_status, "busy") == 0)
        {
          arg_add_value (globals, "CURRENTLY_TESTED_HOST", ARG_STRING,
                         strlen ("network"), "network");
          save_kb_new (globals, "network");
          kb = kb_new ();
          (*new_kb) = TRUE;
          return kb;
        }
    }

  // Check if kb should be saved.
  if (save_kb (globals))
    {
      // Check if a saved kb exists and we shall restore it.
      if (save_kb_exists (hostname) != 0)
        {
          save_kb_backup (hostname);
          kb = save_kb_load_kb (globals, hostname);
        }
      else
        {
          // We shall not or cannot restore.
          save_kb_new (globals, hostname);
          kb = kb_new ();
          (*new_kb) = TRUE;
        }
 
      arg_add_value (globals, "CURRENTLY_TESTED_HOST", ARG_STRING,
                     strlen (hostname), hostname);
    }
  else                          /* save_kb(globals) */
    {
      kb = kb_new ();
    }

  // Add local check (SSH)- related knowledge base items
  fill_host_kb_ssh_credentials (kb, globals, hostname);
  // If vhosts is set, split it and put it in the KB
  if (vhosts)
    {
      gchar **vhosts_array = g_strsplit (vhosts, ",", 0);
      guint i = 0;
      while (vhosts_array[i] != NULL)
        {
          kb_item_add_str (kb, "hostinfos/vhosts", vhosts_array[i]);
          save_kb_write_str (globals, hostname, "hostinfos/vhosts", vhosts_array[i]);
          i++;
        }
      g_strfreev (vhosts_array);
    }

  result_iter = host_network_results;
  while (result_iter != NULL)
    {
      char *newname = strstr (result_iter->name, "/") + 1;
      if (result_iter->type == KB_TYPE_STR)
        {
          kb_item_add_str (kb, newname, result_iter->v.v_str);
          save_kb_write_str (globals, hostname, newname, result_iter->v.v_str);
        }
      else if (result_iter->type == KB_TYPE_INT)
        {
          kb_item_add_int (kb, newname, result_iter->v.v_int);
          save_kb_write_int (globals, hostname, newname, result_iter->v.v_int);
        }
      result_iter = result_iter->next;
    }

  return kb;
}

/**
 * @brief Attack one host.
 */
static void
attack_host (struct arglist *globals, struct arglist *hostinfos, char *hostname,
             plugins_scheduler_t sched)
{
  /* Used for the status */
  int num_plugs = 0;
  int cur_plug = 1;

  struct kb_item **kb;
  gboolean new_kb = FALSE;
  int forks_retry = 0;
  struct arglist *plugins = arg_get_value (globals, "plugins");
  struct arglist *tmp;

  setproctitle ("openvassd: testing %s",
                (char *) arg_get_value (hostinfos, "NAME"));

  kb = init_host_kb (globals, hostname, hostinfos, &new_kb);

  num_plugs = get_active_plugins_number (plugins);

  tmp = emalloc (sizeof (struct arglist));
  arg_add_value (tmp, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);

  /* launch the plugins */
  pluginlaunch_init (globals);

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

      /* Idle if the scan has been paused. */
      if (pause_whole_test)
        {
          /* Let the running NVTs complete. */
          pluginlaunch_wait ();

          /* Send the PAUSE status to the client. */
          if (comm_send_status (globals, hostname, "pause", cur_plug, num_plugs)
              < 0)
            {
              pluginlaunch_stop ();
              goto host_died;
            }

          /* Wait for resume. */
          while (pause_whole_test)
            {
              struct timeval timeout;
              timeout.tv_usec = 0;
              timeout.tv_sec = 1;
              select (0, NULL, NULL, NULL, &timeout);
            }

          /* Send the RESUME status to the client. */
          if (comm_send_status (globals, hostname, "resume", cur_plug,
                                num_plugs)
              < 0)
            {
              pluginlaunch_stop ();
              goto host_died;
            }
        }

      plugin = plugins_scheduler_next (sched);
      if (plugin != NULL && plugin != PLUG_RUNNING)
        {
          int e;

        again:
          if ((e =
               launch_plugin (globals, sched, plugin, hostname, &cur_plug,
                              num_plugs, hostinfos, kb, new_kb)) < 0)
            {
              /*
               * Remote host died
               */
              if (e == ERR_HOST_DEAD)
                goto host_died;
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
        }
      else if (plugin == NULL)
        break;
      else
        pluginlaunch_wait_for_free_process ();
    }

  pluginlaunch_wait ();

host_died:
  arg_free (tmp);
  pluginlaunch_stop ();
  plugins_scheduler_free (sched);

  gchar *network_scan_status = arg_get_value (globals, "network_scan_status");
  if (network_scan_status != NULL)
    {
      if (g_ascii_strcasecmp (network_scan_status, "busy") == 0)
        {
          save_kb_close (globals, "network");
        }
    }
  else
    if (new_kb == TRUE)
      save_kb_close (globals, hostname);

}

/**
 * @brief Set up some data and jump into attack_host()
 */
static void
attack_start (struct attack_start_args *args)
{
  struct arglist *globals = args->globals;
  char *hostname = args->hostname;
  char *mac = args->host_mac_addr;
  struct arglist *plugs = arg_get_value (globals, "plugins");
  struct in6_addr *hostip = &(args->hostip);
  struct arglist *hostinfos;

  struct arglist *preferences = arg_get_value (globals, "preferences");
  char *non_simult = arg_get_value (preferences, "non_simult_ports");
  char *vhosts = arg_get_value (preferences, "vhosts");
  char *vhosts_ip = arg_get_value (preferences, "vhosts_ip");
  int thread_socket = args->thread_socket;
  int soc;
  struct timeval then, now;
  plugins_scheduler_t sched = args->sched;
  int i;

  openvas_signal (SIGUSR1, attack_handle_sigusr1);
  openvas_signal (SIGUSR2, attack_handle_sigusr2);

  thread_socket = dup2 (thread_socket, 4);

  // Close all file descriptors >= 5
  for (i = 5; i < getdtablesize (); i++)
    {
      close (i);
    }

  gettimeofday (&then, NULL);

  if (non_simult == NULL)
    {
      non_simult = estrdup ("139, 445");
      arg_add_value (preferences, "non_simult_ports", ARG_STRING,
                     strlen (non_simult), non_simult);
    }
  arg_add_value (preferences, "non_simult_ports_list", ARG_ARGLIST, -1,
                 (void *) list2arglist (non_simult));

  /* Options regarding the communication with our parent */
  openvas_deregister_connection (GPOINTER_TO_SIZE
                                 (arg_get_value (globals, "global_socket")));
  arg_set_value (globals, "global_socket", -1,
                 GSIZE_TO_POINTER (thread_socket));

  /* Wait for the server to confirm it read our data (prevents client desynch) */
  arg_add_value (globals, "confirm", ARG_INT, sizeof (int), (void *) 1);

  soc = thread_socket;
  if (vhosts == NULL || vhosts_ip == NULL)
    hostinfos = attack_init_hostinfos (mac, hostname, hostip);
  else
    {
      char *txt_ip;
      struct in_addr inaddr;
      char name[512];
      inaddr.s_addr = hostip->s6_addr32[3];

      if (IN6_IS_ADDR_V4MAPPED (hostip))
        txt_ip = estrdup (inet_ntoa (inaddr));
      else
        txt_ip = estrdup (inet_ntop (AF_INET6, hostip, name, sizeof (name)));
      if (strcmp (vhosts_ip, txt_ip) != 0)
        vhosts = NULL;
      hostinfos = attack_init_hostinfos_vhosts (mac, hostname, hostip, vhosts);
    }

  if (mac)
    hostname = mac;

  plugins_set_socket (plugs, soc);
  ntp_1x_timestamp_host_scan_starts (globals, hostname);

  // Start scan
  attack_host (globals, hostinfos, hostname, sched);

  // Calculate duration, clean up
  ntp_1x_timestamp_host_scan_ends (globals, hostname);
  gettimeofday (&now, NULL);
  if (now.tv_usec < then.tv_usec)
    {
      then.tv_sec++;
      now.tv_usec += 1000000;
    }

  log_write ("Finished testing %s. Time : %ld.%.2ld secs\n", hostname,
             (long) (now.tv_sec - then.tv_sec),
             (long) ((now.tv_usec - then.tv_usec) / 10000));
  shutdown (soc, 2);
  close (soc);
}

/**
 * @brief Frees memory used by uploaded, as callback for
 * @brief g_hash_table_foreach.
 *
 * @param key     Key of the hashtable (ignored).
 * @param value   Value of the hashtable (ignored).
 * @param ignored data-pointer (ignored).
 *
 * @return Currently always returns TRUE, indicating that every entry in the
 * @return hash table can be freed by the time this function is called.
 */
gboolean
free_uploaded_file (gchar * key, gchar * value, gpointer ignored)
{
  return TRUE;
}

/*******************************************************

		PUBLIC FUNCTIONS

********************************************************/


/**
 * @brief Attack a whole network.
 *
 * @return 0 if success, -1 on error.
 */
int
attack_network (struct arglist *globals)
{
  int max_hosts = 0, max_checks;
  int num_tested = 0;
  char *hostlist, *ordering, *exclude_hosts;
  openvas_hosts_t *hosts;
  openvas_host_t *host;
  int global_socket = -1;
  struct arglist *preferences = NULL;
  struct arglist *plugins = NULL;
  struct openvas_rules *rules = NULL;
  struct arglist *rejected_hosts = NULL;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  GHashTable *files;
  struct timeval then, now;
  inaddrs_t addrs;
  char buffer[INET6_ADDRSTRLEN];

  int network_phase = 0;
  gchar *network_targets;
  int do_network_scan = 0;
  int scan_stopped;

  gettimeofday (&then, NULL);

  preferences = arg_get_value (globals, "preferences");

  if ((do_network_scan = preferences_get_bool (preferences, "network_scan")) == -1)
    do_network_scan = 0;
  network_targets = arg_get_value (preferences, "network_targets");
  if (network_targets != NULL)
    arg_add_value (globals, "network_targets", ARG_STRING,
                   strlen (network_targets), network_targets);
  if (do_network_scan)
    {
      gchar *network_scan_status = arg_get_value (globals, "network_scan_status");
      if (network_scan_status != NULL)
        if (g_ascii_strcasecmp (network_scan_status, "done") == 0)
          network_phase = 0;
        else
          network_phase = 1;
      else
        {
          arg_add_value (globals, "network_scan_status", ARG_STRING,
                         strlen ("busy"), "busy");
          network_phase = 1;
        }
    }

  num_tested = 0;

  global_socket = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));

  plugins = arg_get_value (globals, "plugins");
  rules = arg_get_value (globals, "rules");
  rejected_hosts = emalloc (sizeof (struct arglist));

  /* Init and check Target List */
  hostlist = arg_get_value (preferences, "TARGET");
  if (hostlist == NULL)
    {
      log_write ("TARGET not set ?!");
      exit (1);
    }

  if ((unsigned short *) getpts (arg_get_value (preferences, "port_range"), NULL) == NULL)
    {
      auth_printf (globals,
                   "SERVER <|> ERROR <|> E001 - Invalid port range <|> SERVER\n");
      return -1;
    }

  /* Initialize the attack. */
  sched = plugins_scheduler_init (plugins,
    preferences_get_bool (preferences, "auto_enable_dependencies") == 1 ? 1 : 0,
    network_phase);

  max_hosts = get_max_hosts_number (preferences);
  max_checks = get_max_checks_number (preferences);

  if (network_phase)
    {
      network_targets = arg_get_value (preferences, "network_targets");
      if (network_targets == NULL)
        {
          log_write ("WARNING: In network phase, but without targets! Stopping.\n");
          host = NULL;
        }
      else
        {
          log_write
            ("Start a new scan. Target(s) : %s, in network phase with target %s\n",
             hostlist, network_targets);
        }
    }
  else
    {
      log_write ("Starts a new scan. Target(s) : %s, with max_hosts = %d and"
                 " max_checks = %d\n", hostlist, max_hosts, max_checks);
    }

  hosts = openvas_hosts_new (hostlist);

  /* Hosts ordering strategy: sequential, random, reversed... */
  ordering = preferences_get_string (preferences, "hosts_ordering");
  if (ordering)
    {
      if (!strcmp (ordering, "random"))
        openvas_hosts_shuffle (hosts);
      else if (!strcmp (ordering, "reversed"))
        openvas_hosts_reverse (hosts);
    }

  /* Exclude hosts ? */
  exclude_hosts = preferences_get_string (preferences, "exclude_hosts");
  if (exclude_hosts)
    {
      /* Exclude hosts, resolving hostnames. */
      int ret = openvas_hosts_exclude (hosts, exclude_hosts, 1);

      if (ret >= 0)
        log_write ("exclude_hosts: Skipped %d host(s).\n", ret);
      else
        log_write ("exclude_hosts: Error.\n");
    }

  /* Reverse-lookup unify ? */
  if (preferences_get_bool (preferences, "reverse_lookup_unify") == 1)
    log_write ("reverse_lookup_unify: Skipped %d host(s).\n",
               openvas_hosts_reverse_lookup_unify (hosts));

  /* Hosts that reverse-lookup only ? */
  if (preferences_get_bool (preferences, "reverse_lookup_only") == 1)
    log_write ("reverse_lookup_only: Skipped %d host(s).\n",
               openvas_hosts_reverse_lookup_only (hosts));

  host = openvas_hosts_next (hosts);
  if (host == NULL)
    goto stop;
  hosts_init (global_socket, max_hosts);
  /*
   * Start the attack !
   */
  while (host)
    {
      int pid;
      char *hostname;
      struct in6_addr host_ip;

      hostname = openvas_host_value_str (host);
      if (openvas_host_get_addr6 (host, &host_ip) == -1)
        {
          log_write ("Couldn't resolve target %s\n", hostname);
          auth_printf (globals,
                       "SERVER <|> ERRMSG <|> %s <|> general/HOST <|>"
                       " Couldn't resolve hostname. <|>  <|> SERVER\n", hostname);

          g_free (hostname);
          host = openvas_hosts_next (hosts);
          continue;
        }
      memcpy (&addrs.ip6, &host_ip, sizeof (struct in6_addr));

      /* Do we have the right to test this host ? */
      if (CAN_TEST (get_host_rules (rules, addrs)) == 0)
        {
          log_write ("Rejected attempt to scan %s", hostname);
          arg_add_value (rejected_hosts, hostname, ARG_INT, sizeof (int),
                         (void *) 1);
        }
      else
        {                       // We have the right to test this host
          struct attack_start_args args;
          int s;
          char *MAC = NULL;
          int mac_err = -1;

          if (preferences_get_bool (preferences, "use_mac_addr") > 0
              && v6_is_local_ip (&host_ip))
            {
              mac_err = v6_get_mac_addr (&host_ip, &MAC);
              if (mac_err > 0)
                {
                  /* remote host is down */
                  g_free (hostname);
                  host = openvas_hosts_next (hosts);
                  continue;
                }
            }

          s = hosts_new (globals, hostname);
          if (s < 0)
            goto scan_stop;

          args.globals = globals;
          if (IN6_IS_ADDR_V4MAPPED (&host_ip))
            inet_ntop (AF_INET, ((char *)(&host_ip))+12, args.hostname,
                       sizeof (args.hostname));
          else
            inet_ntop (AF_INET6, &host_ip, args.hostname,
                       sizeof (args.hostname));
          memcpy (&args.hostip, &host_ip, sizeof (struct in6_addr));
          args.host_mac_addr = MAC;
          args.sched = sched;
          args.thread_socket = s;

        forkagain:
          pid = create_process ((process_func_t) attack_start, &args);
          if (pid < 0)
            {
              fork_retries++;
              if (fork_retries > MAX_FORK_RETRIES)
                {
                  /* Forking failed - we go to the wait queue. */
                  log_write ("fork() failed - %s. %s won't be tested\n",
                             strerror (errno), hostname);
                  efree (&MAC);
                  goto stop;
                }

              log_write
                ("fork() failed - sleeping %d seconds and trying again...\n",
                 fork_retries);
              fork_sleep (fork_retries);
              goto forkagain;
            }

          hosts_set_pid (hostname, pid);
          if (network_phase)
            log_write ("Testing %s (network level) [%d]\n",
                       network_targets, pid);
          else
            log_write ("Testing %s (%s) [%d]\n",
                       hostname, inet_ntop (AF_INET6,
                                            &args.
                                            hostip,
                                            buffer,
                                            sizeof
                                            (buffer)),
                       pid);
          if (MAC != NULL)
            efree (&MAC);
        }

      num_tested++;

      if (network_phase)
        {
          host = NULL;
          arg_set_value (globals, "network_scan_status", strlen ("done"), "done");
        }
      else
        {
          g_free (hostname);
          host = openvas_hosts_next (hosts);
        }
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
    g_hash_table_foreach_remove (files, (GHRFunc) free_uploaded_file, NULL);

  if (rejected_hosts && rejected_hosts->next)
    {
      char *banner = emalloc (4001);
      int length = 0;

      sprintf (banner,
               "SERVER <|> ERROR <|> E002 - These hosts could not be tested because you are not allowed to do so :;");
      length = strlen (banner);

      while (rejected_hosts->next && (length < (4000 - 3)))
        {
          int n;
          n = strlen (rejected_hosts->name);
          if (length + n + 1 >= 4000)
            {
              n = 4000 - length - 2;
            }

          strncat (banner, rejected_hosts->name, n);
          strncat (banner, ";", 1);
          length += n + 1;
          rejected_hosts = rejected_hosts->next;
        }

      if (rejected_hosts->next != NULL)
        strcat (banner, "...");

      auth_printf (globals, "%s\n", banner);
    }

stop:
  scan_stopped = GPOINTER_TO_SIZE(arg_get_value (globals, "stop_required"));

  openvas_hosts_free (hosts);

  arg_free_all (rejected_hosts);
  plugins_scheduler_free (sched);

  gettimeofday (&now, NULL);
  log_write ("Total time to scan all hosts : %ld seconds\n",
             now.tv_sec - then.tv_sec);

  if (do_network_scan && network_phase && !scan_stopped)
    return attack_network (globals);

  return 0;
}
