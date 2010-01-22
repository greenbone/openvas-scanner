/* OpenVAS
* $Id$
* Description: Launches the plugins, and manages multithreading.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*	   - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*	   - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*	   - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
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

#include <includes.h>

#include <glib.h>

#include <openvas/hg/hosts_gatherer.h>
#include <openvas/hg/hg_utils.h>
#include <openvas/kb.h> /* for kb_new */
#include <openvas/network.h> /* for auth_printf */
#include <openvas/nvt_categories.h> /* for ACT_INIT */
#include <openvas/pcap_openvas.h> /* for v6_is_local_ip */
#include <openvas/plugutils.h> /* for plug_get_path */
#include <openvas/proctitle.h> /* for setproctitle */
#include <openvas/system.h> /* for emalloc */
#include <openvas/scanners_utils.h> /* for comm_send_status */

#include "attack.h"
#include "auth.h"
#include "comm.h"
#include "hosts.h"
#include "log.h"
#include "ntp_11.h"
#include "openvas_ssh_login.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "plugs_req.h"
#include "preferences.h"
#include "processes.h"
#include "rules.h"
#include "save_tests.h"
#include "save_kb.h"
#include "sighand.h"
#include "utils.h"


#define ERR_HOST_DEAD -1
#define ERR_CANT_FORK -2

#define MAX_FORK_RETRIES 10

extern u_short * getpts(char *, int *);

/**
 * Bundles information about target(s), configuration (globals arglist) and 
 * scheduler.
 */
struct attack_start_args {
        struct arglist * globals;
        struct in6_addr hostip;
        char * host_mac_addr;
        plugins_scheduler_t sched;
        int thread_socket;
        struct hg_globals * hg_globals;
        char hostname[1024];
};

/*******************************************************

		PRIVATE FUNCTIONS
		
********************************************************/


static void
fork_sleep (int n)
{
 time_t then, now;

 now = then = time(NULL);
 while(now - then < n )
 {
   waitpid(-1, NULL, WNOHANG);
   usleep(10000);
   now = time(NULL);
 }
}


/**
 * @brief Inits an arglist which can be used by the plugins.
 *
 * The arglist will have following keys and (type, value):
 *  - FQDN (string, Fully qualified domain name, e.g. host.domain.net)
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
attack_init_hostinfos (char * mac, char * hostname, struct in6_addr * ip)
{
  struct arglist * hostinfos;

  hostinfos = emalloc (sizeof (struct arglist));
  if (!hg_valid_ip_addr (hostname))
    {
      char f[1024];
      hg_get_name_from_ip (ip, f, sizeof(f));
      arg_add_value (hostinfos, "FQDN", ARG_STRING, strlen(f), estrdup(f));
    }
  else
    arg_add_value (hostinfos, "FQDN", ARG_STRING, strlen (hostname), estrdup (hostname));

  if(mac)
    {
      arg_add_value (hostinfos, "NAME", ARG_STRING, strlen(mac), mac);
      arg_add_value (hostinfos, "MAC", ARG_STRING, strlen(mac), mac);
    }
  else
    arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (hostname), estrdup (hostname));

  arg_add_value (hostinfos, "IP", ARG_PTR, sizeof (struct in6_addr), ip);
  return (hostinfos);
}

/**
 * @brief Return our user name.
 *
 * @return Our user name.
 */
static char *
attack_user_name (struct arglist * globals)
{
 static char * user;
 if(!user)
   user = (char*)arg_get_value(globals, "user");

 return user;
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
launch_plugin (struct arglist * globals, plugins_scheduler_t * sched,
               struct scheduler_plugin * plugin, char * hostname,
               int * cur_plug, int num_plugs, struct arglist * hostinfos, 
               struct kb_item ** kb, gboolean new_kb)
{
  struct arglist * preferences = arg_get_value(globals,"preferences");
  struct arglist * args = plugin->arglist->value;
  char name[1024];
  int optimize = preferences_optimize_test(preferences);
  int category = plugin->category;
  static int last_status = 0;

  strncpy(name, plug_get_path(args), sizeof(name) - 1);
  name[sizeof(name) - 1 ] = '\0';

  if (plug_get_launch(args) != LAUNCH_DISABLED
      || category == ACT_INIT
      || category == ACT_SETTINGS) /* can we launch it ? */
    {
      char * error;

      pl_class_t * cl_ptr = arg_get_value(args, "PLUGIN_CLASS");

      if(preferences_safe_checks_enabled(preferences) && 
         (category == ACT_DESTRUCTIVE_ATTACK ||
          category == ACT_KILL_HOST ||
          category == ACT_FLOOD ||
          category == ACT_DENIAL))
        {
          if (preferences_log_whole_attack(preferences))
            log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
                      attack_user_name(globals), plugin->arglist->name,  hostname, 
                      "because safe checks are enabled");
          plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
          return 0;
        }

      (*cur_plug) ++;
      if ( ( *cur_plug * 100 ) / num_plugs  >= last_status )
        {
          last_status = (*cur_plug * 100 ) / num_plugs  + 2;
          if ( comm_send_status(globals, hostname, "attack", *cur_plug, num_plugs) < 0 )
            {
            /* Could not send our status back to our father -> exit */
            pluginlaunch_stop();
            return ERR_HOST_DEAD;
            }
        }

      if(save_kb(globals))
        {
          char * oid = plug_get_oid(args);
          char asc_id[100];

          snprintf(asc_id, sizeof(asc_id), "Launched/%s", oid);

          if(kb_item_get_int(kb, asc_id) > 0 &&
             !save_kb_replay_check(globals, category))
            {
              /* XXX determine here if we should skip ACT_SCANNER, ACT_GATHER_INFO,
                ACT_ATTACK and ACT_DENIAL */
              if(preferences_log_whole_attack(preferences))
                log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
                          attack_user_name(globals), plugin->arglist->name, hostname,
                          "because it has already been launched in the past");
              plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
              return 0;
            }
          else
            {
              kb_item_add_int(kb, asc_id, 1);
              save_kb_write_int(globals, hostname, asc_id,  1);
            }
          }

      // Do not launch NVT if mandatory key is missing (e.g. an important tool
      // was not found)
      if (mandatory_requirements_met(kb, plugin))
        error = NULL;
      else
        error = "because a mandatory key is missing";

      if (!error
          && (!optimize || !(error = requirements_plugin (kb, plugin, preferences))))
        {
          int pid;

          /* Start the plugin */
          pid = plugin_launch(globals, sched, plugin, hostinfos, preferences, kb,
                              name, cl_ptr);
          if(pid  < 0)
            {
              plugin_set_running_state(sched, plugin, PLUGIN_STATUS_UNRUN);
              return ERR_CANT_FORK;
            }

          if(preferences_log_whole_attack(preferences))
            log_write("user %s : launching %s against %s [%d]\n",
                      attack_user_name(globals), plugin->arglist->name, hostname,
                      pid);

          /* Stop the test if the host is 'dead' */
          if(kb_item_get_int(kb, "Host/dead") > 0 ||
            kb_item_get_int(kb, "Host/ping_failed") > 0)
            {
              log_write("user %s : The remote host (%s) is dead\n",
                        attack_user_name(globals), hostname);
              pluginlaunch_stop();

              if(new_kb == TRUE)
                save_kb_close(globals, hostname);

              if(kb_item_get_int(kb, "Host/ping_failed") > 0)
                save_kb_restore_backup(globals, hostname);

              plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
              return ERR_HOST_DEAD;
            }
        }
      else /* requirements_plugin() failed */
        {
          plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
          if(preferences_log_whole_attack(preferences))
            log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
                      attack_user_name(globals), plugin->arglist->name,
                      hostname, error);
        }
    } /* if(plugins->launch) */
  else
    plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);

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
is_pattern (const char* str)
{
  // NOTE This function was copied from openvas-client/nvt_pref_sshlogin.c
  return ( str != NULL
           &&  (strchr (str, '*') != NULL || strchr (str, '?') != NULL)
         );
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
pattern_matches (char* key_pattern, char* value_login, char* hostname)
{
  printf ("SSH-DEBUG: Testing if %s is pattern\n", key_pattern);
  if (is_pattern (key_pattern) == FALSE)
    return FALSE;

  printf ("SSH-DEBUG: Testing Pattern %s against %s\n", key_pattern, hostname);
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
fill_host_kb_ssh_credentials (struct kb_item** kb, struct arglist* globals,
                              char* hostname)
{
  GHashTable* map_host_login_names = NULL;
  GHashTable* map_loginname_login  = NULL;
  GHashTable* file_translation     = NULL;
  char* accountname        = NULL;
  openvas_ssh_login* login = NULL;

  map_host_login_names = arg_get_value (globals, "MAP_HOST_SSHLOGIN_NAME");
  map_loginname_login  = arg_get_value (globals, "MAP_NAME_SSHLOGIN");

  if (map_host_login_names == NULL || map_loginname_login == NULL)
    {
      printf("SSH-DEBUG: Not setting login information for local checks at %s : No mapping found.\n", hostname);
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
      printf ("SSH-DEBUG: Trying to match patterns for login at %s\n", hostname);
      accountname = g_hash_table_find (map_host_login_names,
                                       (GHRFunc) pattern_matches, hostname);
      // Try to fetch login struct
      if (accountname != NULL)
        login = g_hash_table_lookup (map_loginname_login, accountname);
    }

  // No pattern matching this host found? Try "Default".
  if (accountname == NULL || login == NULL)
    {
      printf ("SSH-DEBUG: Trying Default- account for local checks at %s\n", hostname);
      accountname = g_hash_table_lookup (map_host_login_names, "Default");

      // If none under 'Default' either, done.
      if (accountname == NULL)
        {
          printf("SSH-DEBUG: Not setting login information for local checks at %s: No even Default account found.\n", hostname);
          return;
        }
      else
        {
          login = g_hash_table_lookup (map_loginname_login, accountname);
            // No login information for this login-account found? Strange, but so be it.
          if (login == NULL)
            {
              printf("SSH-DEBUG: Could not find info for accountname '%s' for local checks at %s.\n", accountname, hostname);
              return;
            }
        }
    }

  printf("SSH-DEBUG: Resolving infos of account '%s' for local checks at %s.\n", accountname, hostname);

  // Get the translation table (remotefilepath -> localfilepath)
  file_translation = arg_get_value(globals, "files_translation");
  if (file_translation == NULL)
    return;

  // Fill knowledge base with host specific login information
  if (login->username)
    kb_item_set_str (kb, "Secret/SSH/login", login->username);

  if (login->userpassword)
    kb_item_set_str (kb, "Secret/SSH/password", login->userpassword);

  if (login->ssh_key_passphrase)
    kb_item_set_str (kb, "Secret/SSH/passphrase", login->ssh_key_passphrase);

  // For the key-files: translate the path and set file content to kb
  if (login->public_key_path)
    {
      const char* translated_path = g_hash_table_lookup (file_translation,
                                                        login->public_key_path);
      gchar* contents;
      GError* error = NULL;
      if (translated_path && 
          g_file_get_contents (translated_path, &contents, NULL, &error))
        {
          kb_item_set_str (kb, "Secret/SSH/publickey", contents);
        }
      if (error != NULL) g_error_free(error);
    }
  if (login->private_key_path)
    {
      const char* translated_path = g_hash_table_lookup (file_translation,
                                                       login->private_key_path);
      gchar* contents;
      GError* error = NULL;
      if (translated_path && 
          g_file_get_contents (translated_path, &contents, NULL, &error))
        {
          kb_item_set_str (kb, "Secret/SSH/privatekey", contents);
        }
      if (error != NULL) g_error_free(error);
    }

  printf("SSH-DEBUG: Resolved account name %s for local tests at %s\n", accountname, hostname);
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
static struct kb_item**
init_host_kb (struct arglist* globals, char* hostname, gboolean* new_kb)
{
  struct kb_item** kb;
  (*new_kb) = FALSE;

  // Check if kb should be saved.
  if (save_kb (globals))
    {
      // Check if a saved kb exists and we shall restore it.
      if (save_kb_exists (globals, hostname) != 0 && 
          save_kb_pref_restore (globals) != 0 )
        {
          save_kb_backup (globals, hostname);
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
  else /* save_kb(globals) */
    {
      kb = kb_new ();
    }

  // Add local check (SSH)- related knowledge base items
  fill_host_kb_ssh_credentials (kb, globals, hostname);

  return kb;
}

/**
 * @brief Attack one host.
 */
static void
attack_host (struct arglist * globals, struct arglist * hostinfos,
             char * hostname, plugins_scheduler_t sched)
{
  /* Used for the status */
  int num_plugs = 0;
  int cur_plug = 1;

  struct kb_item ** kb;
  gboolean new_kb = FALSE;
  int forks_retry = 0;
  struct arglist * plugins = arg_get_value(globals, "plugins");
  struct arglist * tmp;

  setproctitle("testing %s", (char*)arg_get_value(hostinfos, "NAME"));

  kb = init_host_kb (globals, hostname, &new_kb);

  num_plugs = get_active_plugins_number(plugins);

  tmp = emalloc(sizeof(struct arglist));
  arg_add_value(tmp, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);

  /* launch the plugins */
  pluginlaunch_init(globals);

  for(;;)
    {
      struct scheduler_plugin * plugin;
      pid_t parent;

      /* Check that our father is still alive */
      parent = getppid();
      if (parent <= 1 || process_alive(parent) == 0 )
        {
          pluginlaunch_stop();
          return;
        }

      plugin = plugins_scheduler_next(sched);
      if (plugin != NULL && plugin != PLUG_RUNNING)
        {
          int e;

again:
          if((e = launch_plugin( globals, sched, plugin, hostname, &cur_plug, num_plugs, hostinfos, kb, new_kb))  < 0)
            {
              /*
               * Remote host died
               */
              if(e == ERR_HOST_DEAD)
                  goto host_died;
              else if (e == ERR_CANT_FORK )
                {
                  if (forks_retry < MAX_FORK_RETRIES)
                    {
                      forks_retry++;
                      log_write("fork() failed - sleeping %d seconds (%s)", forks_retry, strerror(errno));
                      fork_sleep(forks_retry);
                      goto again;
                    }
                  else
                    {
                      log_write("fork() failed too many times - aborting");
                      goto host_died;
                    }
                }
            }
        }
      else if(plugin == NULL) break;
      else pluginlaunch_wait_for_free_process();
      }

  pluginlaunch_wait();

host_died:
  arg_free(tmp);
  pluginlaunch_stop();
  plugins_scheduler_free(sched);

  if (new_kb == TRUE)
    save_kb_close(globals, hostname);
}

/**
 * @brief Set up some data and jump into attack_host()
 */
static void
attack_start (struct attack_start_args * args)
{
  struct arglist * globals = args->globals;
  char * hostname = args->hostname;
  char * mac = args->host_mac_addr;
  struct arglist * plugs = arg_get_value(globals, "plugins");
  struct in6_addr * hostip = &(args->hostip);
  struct arglist * hostinfos;

  struct arglist * preferences = arg_get_value (globals,"preferences");
  char * non_simult = arg_get_value (preferences, "non_simult_ports");
  int thread_socket = args->thread_socket;
  int soc;
  struct timeval then, now;
  plugins_scheduler_t sched = args->sched;
  int i;

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
      arg_add_value (preferences, "non_simult_ports", ARG_STRING, strlen (non_simult), non_simult);
    }
  arg_add_value (preferences, "non_simult_ports_list", ARG_ARGLIST, -1, (void*) list2arglist (non_simult));

  /* Options regarding the communication with our parent */
  openvas_deregister_connection (GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket")));
  arg_set_value (globals, "global_socket", -1, GSIZE_TO_POINTER (thread_socket));

  /* Wait for the server to confirm it read our data (prevents client desynch) */
  arg_add_value (globals, "confirm", ARG_INT, sizeof(int), (void*)1);

  soc = thread_socket;
  hostinfos = attack_init_hostinfos (mac, hostname, hostip);
  if (mac)
    hostname = mac;

  plugins_set_socket (plugs, soc);
  ntp_1x_timestamp_host_scan_starts (globals, hostname);

  // Start scan
  attack_host (globals, hostinfos, hostname, sched);

  // Calculate duration, clean up
  if (preferences_ntp_show_end (preferences))
    ntp_11_show_end (globals, hostname, 1);

  ntp_1x_timestamp_host_scan_ends (globals, hostname);
  gettimeofday (&now, NULL);
  if (now.tv_usec < then.tv_usec)
    {
      then.tv_sec ++;
      now.tv_usec += 1000000;
    }

  log_write ("Finished testing %s. Time : %ld.%.2ld secs\n",
             hostname,
             (long)(now.tv_sec - then.tv_sec),
             (long)((now.tv_usec - then.tv_usec) / 10000));
  shutdown (soc, 2);
  close (soc);
}

/**
 * @brief Remove a file that was uploaded by the user, as callback for
 * @brief g_hash_table_foreach.
 *
 * @param key     Key of the hashtable.
 * @param value   Value of the hashtable (will attempt to unlink file at this
 *                path).
 * @param ignored data-pointer (ignored).
 */
static void
unlink_name_mapped_file (gchar* key, gchar* value, gpointer ignored)
{
  unlink (value);
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
attack_network (struct arglist * globals)
{
  int max_hosts                 = 0;
  int num_tested                = 0;
  int host_pending              = 0;
  char hostname[1024];
  char * hostlist;
  struct in6_addr host_ip;
  int hg_flags                  = 0;
  int hg_res;
  struct hg_globals * hg_globals = NULL;
  int global_socket             = -1;
  struct arglist * preferences  = NULL;
  struct arglist * plugins      = NULL;
  struct openvas_rules *rules   = NULL;
  struct arglist * rejected_hosts =  NULL;
  int restoring    = 0;
  GHashTable * tested = NULL;
  int  save_session= 0;
  char * port_range;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  GHashTable* files;
  struct timeval then, now;
  inaddrs_t addrs;
  char buffer[INET6_ADDRSTRLEN];

  gettimeofday (&then, NULL);

  host_ip = in6addr_any;
  preferences    = arg_get_value(globals, "preferences");

  num_tested = 0;

  global_socket  = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));

  plugins        = arg_get_value (globals, "plugins");
  rules          = arg_get_value (globals, "rules");
  rejected_hosts = emalloc (sizeof(struct arglist));

  save_session = preferences_save_session (preferences);
  restoring = (GPOINTER_TO_SIZE (arg_get_value (globals, "RESTORE-SESSION")) == 1);

  if (restoring) tested = arg_get_value (globals, "TESTED_HOSTS");
  if (save_session) save_tests_init(globals);


  /* Init and check Target List */
  hostlist = arg_get_value (preferences, "TARGET");
  if (hostlist == NULL)
    {
      log_write ("%s : TARGET not set ?!", attack_user_name (globals));
      EXIT (1);
    }

  /* Init and check Port Range. */
  port_range = arg_get_value (preferences, "port_range");
  if (port_range == NULL || port_range[0] == '\0')
    port_range = "1-15000";

  if (strcmp (port_range, "-1") != 0)
    {
      unsigned short * ports;
      ports = (unsigned short*) getpts (port_range, NULL);
      if (ports == NULL)
        {
          auth_printf (globals, "SERVER <|> ERROR <|> E001 - Invalid port range <|> SERVER\n");
          return -1;
        }
    }

  /* Initialize the attack. */
  sched  = plugins_scheduler_init (plugins,
                                   preferences_autoload_dependencies (preferences),
                                   preferences_silent_dependencies (preferences) );

  hg_flags = preferences_get_host_expansion (preferences);
  max_hosts = get_max_hosts_number (globals, preferences);

  if (restoring == 0)
    {
      int max_checks = get_max_checks_number (globals, preferences);
      log_write ("user %s starts a new scan. Target(s) : %s, with max_hosts = %d and max_checks = %d\n",
                 attack_user_name (globals), hostlist, max_hosts, max_checks);
    }
  else
    {
      int max_checks  = get_max_checks_number (globals, preferences);
      log_write ("user %s restores session %s, with max_hosts = %d and max_checks = %d\n",
                 attack_user_name (globals),
                 (char*) arg_get_value (globals, "RESTORE-SESSION-KEY"),
                 max_hosts, max_checks);

      save_tests_playback (globals,
                           arg_get_value (globals, "RESTORE-SESSION-KEY"),
                           tested);
    }

  /* Initialize the hosts_gatherer library. */
  if (preferences_get_slice_network_addresses (preferences) != 0)
    hg_flags |= HG_DISTRIBUTE;

  hg_globals = hg_init (hostlist, hg_flags);
  hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
  if (tested != NULL)
    {
      while (hg_res >= 0 && g_hash_table_lookup (tested, hostname) != 0)
        {
          hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
        }
    }

  if (hg_res < 0)
    goto stop;

  hosts_init (global_socket, max_hosts);

  /*
   * Start the attack !
   */
  while (hg_res >= 0)
    {
      nthread_t pid;

     /* openvassd offers the ability to either test
      * only the hosts we tested in the past, or only
      * the hosts we never tested (or both, of course) */
      if (save_kb (globals))
        {
          if (save_kb_pref_tested_hosts_only (globals))
            {
              if (!save_kb_exists (globals, hostname))
                {
                  log_write ("user %s : not testing %s because it has never been tested before\n",
                             attack_user_name(globals), hostname);
                  hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));

                  if (tested != NULL)
                    {
                      while (hg_res >= 0 && g_hash_table_lookup (tested, hostname) != 0 )
                        hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
                    }
                  continue;
                }
            }
          else if (save_kb_pref_untested_hosts_only (globals))
            {
              /* XXX */
              if (save_kb_exists (globals, hostname))
                {
                  log_write ("user %s : not testing %s because it has already been tested before\n",
                             attack_user_name (globals), hostname);
                  hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
                  // If some hosts were tested already, jump over them.
                  if (tested != NULL)
                    {
                      while (hg_res >= 0 && g_hash_table_lookup (tested, hostname) != 0 )
                        hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
                    }
                  continue;
                }
            }
        }

      host_pending = 0 ;
      memcpy (&addrs.ip6, &host_ip, sizeof (struct in6_addr));

      /* Do we have the right to test this host ? */
      if (CAN_TEST (get_host_rules (rules, addrs)) == 0)
        {
          log_write ("user %s : rejected attempt to scan %s",
                     attack_user_name (globals), hostname);
          arg_add_value (rejected_hosts, hostname, ARG_INT, sizeof (int), (void*)1);
        }
      else
        { // We have the right to test this host
          struct attack_start_args args;
          int s;
          char * MAC = NULL;
          int mac_err = -1;
          struct in_addr addr;

          addr.s_addr = host_ip.s6_addr32[3];
          if (preferences_use_mac_addr (preferences) && v6_is_local_ip (&host_ip))
            {
              mac_err = v6_get_mac_addr (&host_ip, &MAC);
              if(mac_err > 0)
                {
                /* remote host is down */
                  hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
                  if (tested != NULL)
                    {
                      while (hg_res >= 0 && g_hash_table_lookup (tested, hostname) != 0 )
                        hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof (hostname));
                    }
                  continue;
                }
            }

          s = hosts_new (globals, hostname);
          if (s < 0) goto scan_stop;

          args.globals = globals;
          strncpy (args.hostname, hostname, sizeof (args.hostname) - 1);
          args.hostname[sizeof (args.hostname) - 1] = '\0';
          memcpy (&args.hostip, &host_ip, sizeof (struct in6_addr));
          args.host_mac_addr = MAC;
          args.sched = sched;
          args.thread_socket = s;

forkagain:
          pid = create_process ((process_func_t) attack_start, &args);
          if (pid < 0)
            {
              fork_retries ++;
              if (fork_retries > MAX_FORK_RETRIES)
                {
                  /* Forking failed - we go to the wait queue. */
                  log_write("fork() failed - %s. %s won't be tested\n",
                            strerror(errno), hostname);
                  efree (&MAC);
                  goto stop;
                }

              log_write ("fork() failed - sleeping %d seconds and trying again...\n", fork_retries);
              fork_sleep (fork_retries);
              goto forkagain;
            }

          hosts_set_pid (hostname, pid);
          log_write ("user %s : testing %s (%s) [%d]\n", attack_user_name (globals), hostname, inet_ntop (AF_INET6, &args.hostip, buffer, sizeof (buffer)), pid);
          if (MAC != NULL)
            efree(&MAC);
        }

      num_tested++;
      hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof(hostname));
      if (tested != NULL)
        {
          while (hg_res >= 0 && g_hash_table_lookup (tested, hostname))
            {
              hg_res = hg_next_host (hg_globals, &host_ip, hostname, sizeof(hostname));
            }
        }
    }

  /* Every host is being tested... We have to wait for the processes
   * to terminate. */
  while (hosts_read (globals) == 0)
    ;

  log_write("user %s : test complete", attack_user_name(globals));

scan_stop:
    /* Delete the files uploaded by the user, if any. */
    files = arg_get_value (globals, "files_translation");
    if (files)
      g_hash_table_foreach (files, (GHFunc) unlink_name_mapped_file, NULL);

    if (rejected_hosts && rejected_hosts->next)
      {
        char * banner = emalloc (4001);
        int length = 0;

        sprintf (banner, "SERVER <|> ERROR <|> E002 - These hosts could not be tested because you are not allowed to do so :;");
        length = strlen(banner);

        while (rejected_hosts->next && (length < (4000-3)))
          {
            int n;
            n = strlen(rejected_hosts->name);
            if (length + n + 1 >= 4000)
              {
                n = 4000 - length  - 2;
              }

            strncat (banner, rejected_hosts->name, n);
            strncat (banner, ";", 1);
            length += n + 1;
            rejected_hosts = rejected_hosts->next;
          }

        if (rejected_hosts->next != NULL)
          strcat(banner, "...");

        auth_printf (globals, "%s\n", banner);
      }

stop:
  if (save_session)
    {
      save_tests_close (globals);
      if (!preferences_save_empty_sessions (preferences))
        {
          if (save_tests_empty (globals))
            {
              log_write ("user %s : Nothing interesting found - deleting the session\n",
                        (char*) arg_get_value (globals, "user"));
              save_tests_delete_current (globals);
            }
        }
    }

  hg_cleanup (hg_globals);

  arg_free_all (rejected_hosts);
  plugins_scheduler_free (sched);

  gettimeofday (&now, NULL);
  log_write ("Total time to scan all hosts : %ld seconds\n", now.tv_sec - then.tv_sec);

  return 0;
}
