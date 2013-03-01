/* OpenVAS
* $Id$
* Description: Loads the preferences set in openvassd.conf into the memory.
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

/** @file
 * 'Server' Preference related functions (some of them scan-related).
 *
 * All the preference getter- functions for pseudo boolean values work in the
 * same fashion.
 * The static 'yes' value is initialized only the first time the function is
 * called. If then preferences != NULL, the arglist is queried, otherwise the
 * value keeps being or is resetted to -1.
 * On subsequent calls where preferences != NULL, the arglist does not have
 * to be queried anymore.
 * Resetting this "cache"s is possible by calling preferences_reset_cache.
 */

#include <unistd.h> /* for close() */
#include <stdio.h>  /* for printf() */
#include <string.h> /* for strstr() */
#include <errno.h>  /* for errno() */
#include <stdlib.h> /* for atoi() */
#include <fcntl.h>  /* for open() */
#include <glib.h>

#include <openvas/hg/hosts_gatherer.h>
#include <openvas/misc/system.h>     /* for efree */
#include <openvas/base/settings.h>   /* for init_settings_iterator_from_file */

#include "comm.h"
#include "preferences.h"
#include "log.h"
#include "utils.h"


#define inited(x) ((x) >= 0)

typedef struct
{
  char *option;
  char *value;
} openvassd_option;

/**
 * @brief Default values for scanner options. Must be NULL terminated.
 */
static openvassd_option openvassd_defaults[] = {
  {"plugins_folder", OPENVAS_NVT_DIR},
  {"cache_folder", OPENVAS_CACHE_DIR},
  {"include_folders", OPENVAS_NVT_DIR},
  {"max_hosts", "30"},
  {"max_checks", "10"},
  {"be_nice", "no"},
  {"logfile", OPENVASSD_MESSAGES},
  {"log_whole_attack", "no"},
  {"log_plugins_name_at_load", "no"},
  {"dumpfile", OPENVASSD_DEBUGMSG},
  {"rules", OPENVASSD_RULES},
  {"cgi_path", "/cgi-bin:/scripts"},
  {"optimize_test", "yes"},
  {"checks_read_timeout", "5"},
  {"network_scan", "no"},
  {"non_simult_ports", "139, 445"},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"safe_checks", "yes"},
  {"auto_enable_dependencies", "yes"},
  {"silent_dependencies", "no"},
  {"use_mac_addr", "no"},
  {"save_knowledge_base", "no"},
  {"kb_restore", "no"},
  {"only_test_hosts_whose_kb_we_dont_have", "no"},
  {"only_test_hosts_whose_kb_we_have", "no"},
  {"kb_dont_replay_scanners", "no"},
  {"kb_dont_replay_info_gathering", "no"},
  {"kb_dont_replay_attacks", "no"},
  {"kb_dont_replay_denials", "no"},
  {"kb_max_age", "864000"},
  {"slice_network_addresses", "no"},
  {"nasl_no_signature_check", "yes"},
  {"drop_privileges", "no"},
  {"unscanned_closed", "yes"},
  // Empty options must be "\0", not NULL, to match the behavior of
  // preferences_process.
  {"vhosts", "\0"},
  {"vhosts_ip", "\0"},
  {"report_host_details", "yes"},
  {"cert_file", SCANNERCERT},
  {"key_file", SCANNERKEY},
  {"ca_file", CACERT},
  {"reverse_lookup", "no"},
  {NULL, NULL}
};

/**
 * @brief Initializes the preferences structure
 */
int
preferences_init (char *config_file, struct arglist **prefs)
{
  int result;
  *prefs = emalloc (sizeof (struct arglist));
  result = preferences_process (config_file, *prefs);
  return (result);
}


/**
 * @brief Copies the content of the prefs file to a special arglist.
 */
int
preferences_process (char *filename, struct arglist *prefs)
{
  int i = 0;
  settings_iterator_t settings;

  while (openvassd_defaults[i].option != NULL)
    {
      arg_add_value (prefs, openvassd_defaults[i].option, ARG_STRING,
                     strlen (openvassd_defaults[i].value),
                     g_strdup (openvassd_defaults[i].value));
      i++;
    }

  if (!init_settings_iterator_from_file (&settings, filename, "Misc"))
    {
      while (settings_iterator_next (&settings))
        {
          gchar *old_value = arg_get_value (prefs, settings_iterator_name
                                            (&settings));
          if (old_value == NULL)
            arg_add_value (prefs, settings_iterator_name (&settings),
                           ARG_STRING,
                           strlen (settings_iterator_value (&settings)),
                           g_strdup (settings_iterator_value (&settings)));
          else
            {
              if (g_ascii_strcasecmp (settings_iterator_value (&settings),
                                      old_value) != 0)
                {
                  g_free (old_value);
                  arg_set_value (prefs, settings_iterator_name (&settings),
                                 strlen (settings_iterator_value (&settings)),
                                 g_strdup (settings_iterator_value (&settings)));
                }
            }
        }

      cleanup_settings_iterator (&settings);
    }

  return (0);
}


int
preferences_get_host_expansion (struct arglist *preferences)
{
  char *pref;
  static int ret = -1;


  if (!preferences)
    {
      ret = -1;
      return -1;
    }

  if (ret >= 0)
    return ret;

  ret = 0;
  pref = arg_get_value (preferences, "host_expansion");
  if (!pref)
    ret = HG_SUBNET;
  else
    {
      if (strstr (pref, "dns"))
        ret = ret | HG_DNS_AXFR;
      if (strstr (pref, "nfs"))
        ret = ret | HG_NFS;
      if (strstr (pref, "ip"))
        ret = ret | HG_SUBNET;
    }

  pref = arg_get_value (preferences, "reverse_lookup");
  if (pref && strstr (pref, "yes"))
    ret = ret | HG_REVLOOKUP;
  return ret;
}

int
preferences_get_slice_network_addresses (struct arglist *preferences)
{
  char *str;

  if (preferences == NULL)
    return 0;

  str = arg_get_value (preferences, "slice_network_addresses");
  if (str == NULL)
    return 0;

  return strcmp (str, "yes") == 0;
}


int
preferences_get_checks_read_timeout (struct arglist *preferences)
{
  char *pref;
  static int ret = -1;

  if (!preferences)
    {
      ret = -1;
      return -1;
    }


  if (ret >= 0)
    return ret;

  pref = arg_get_value (preferences, "checks_read_timeout");
  if (pref)
    {
      ret = atoi (pref);
      if (!ret)
        ret = 15;
    }
  else
    ret = 15;
  return ret;
}

int
preferences_log_whole_attack (struct arglist *preferences)
{
  char *value;
  static int yes = -1;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  value = arg_get_value (preferences, "log_whole_attack");
  if (value && strcmp (value, "yes"))
    {
      yes = 0;
    }
  else
    yes = 1;

  return yes;
}

int
preferences_optimize_test (struct arglist *preferences)
{
  static int yes = -1;
  char *optimize_asc;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  optimize_asc = arg_get_value (preferences, "optimize_test");
  if (optimize_asc && !strcmp (optimize_asc, "no"))
    yes = 0;
  else
    yes = 1;

  return yes;
}




int
preferences_log_plugins_at_load (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "log_plugins_name_at_load");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

int
preferences_ntp_show_end (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "ntp_opt_show_end");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}


int
preferences_plugins_timeout (struct arglist *preferences)
{
  static int to = -1;
  char *pref;

  if (!preferences)
    {
      to = -1;
      return -1;
    }


  if (to >= 0)
    return to;

  pref = arg_get_value (preferences, "plugins_timeout");
  if (pref)
    {
      to = atoi (pref);
      if (to == 0)
        to = NVT_TIMEOUT;
    }
  else
    to = NVT_TIMEOUT;

  return to;
}


/**
 * @brief Returns the timeout defined by the client or 0 if none was set.
 *
 * @param preferences Preferences arglist.
 * @param oid         OID of NVT to ask timeout value of.
 *
 * @return 0 if no timeout for the NVT oid was found, timeout in seconds
 *         otherwise.
 */
int
preferences_plugin_timeout (struct arglist *preferences, char *oid)
{
  int ret = 0;
  char *pref_name = g_strdup_printf ("timeout.%s", oid);

  if (arg_get_type (preferences, pref_name) == ARG_STRING)
    {
      int to = atoi (arg_get_value (preferences, pref_name));
      if (to)
        ret = to;
    }

  efree (&pref_name);
  return ret;
}

int
preferences_benice (struct arglist *preferences)
{
  char *pref;
  static int yes = -1;

  if (preferences == NULL)
    {
      return yes;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "be_nice");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}


/**
 * @brief Returns the privilege setting defined by the client or the scanner
 * preference if none was set.
 *
 * @param preferences Preferences arglist.
 * @param oid         OID of NVT to ask privilege setting of. (unused)
 *
 * @return 1 if privileges should be dropped for this NVT, 0 if not.
 */
int
preferences_drop_privileges (struct arglist *preferences, char *oid)
{
  int ret = 0;

  if (preferences == NULL)
      return ret;

  if (arg_get_type (preferences, "drop_privileges") == ARG_STRING)
    {
      if (strcmp (arg_get_value (preferences, "drop_privileges"), "yes") == 0)
        ret = 1;
    }

  return ret;
}


int
preferences_save_session (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "save_session");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

int
preferences_save_empty_sessions (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "save_empty_sessions");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes == 1;
}


int
preferences_autoload_dependencies (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "auto_enable_dependencies");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}



int
preferences_safe_checks_enabled (struct arglist *preferences)
{
  static int yes = -1;
  char *value;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;
  value = arg_get_value (preferences, "safe_checks");
  if (value && !strcmp (value, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}


int
preferences_use_mac_addr (struct arglist *preferences)
{
  static int yes = -1;
  char *value;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  value = arg_get_value (preferences, "use_mac_addr");
  if (value && !strcmp (value, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

int
preferences_nasl_no_signature_check (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;


  pref = arg_get_value (preferences, "nasl_no_signature_check");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

int
preferences_report_killed_plugins (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;

  pref = arg_get_value (preferences, "report_killed_plugins");
  if ((!pref) || strcmp (pref, "yes"))
    yes = 0;
  else
    yes = 1;

  return yes;
}

int
preferences_silent_dependencies (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;


  pref = arg_get_value (preferences, "silent_dependencies");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

int
preferences_network_scan (struct arglist *preferences)
{
  static int yes = -1;
  char *pref;

  if (!preferences)
    {
      yes = -1;
      return -1;
    }


  if (yes >= 0)
    return yes;


  pref = arg_get_value (preferences, "network_scan");
  if (pref && !strcmp (pref, "yes"))
    yes = 1;
  else
    yes = 0;

  return yes;
}

/**
 * @return NULL if pref is set to "no", preference value otherwise.
 */
char *
preferences_get_string (struct arglist *preferences, char *name)
{
  char *pref = arg_get_value (preferences, name);

  if (pref && pref[0] != '\0' && strcmp (pref, "no"))
    return pref;
  else
    return NULL;
}


/**
 * @brief Resets the preference caches.
 *
 * Subsequent calls to the pseudo-boolean preference getters like
 * preferences_silent_dependencies will query a given arglist once and refill
 * the caches.
 */
void
preferences_reset_cache ()
{
  preferences_get_host_expansion (NULL);
  preferences_get_checks_read_timeout (NULL);
  preferences_log_whole_attack (NULL);
  preferences_report_killed_plugins (NULL);
  preferences_optimize_test (NULL);
  preferences_ntp_show_end (NULL);
  preferences_log_plugins_at_load (NULL);
  preferences_plugins_timeout (NULL);
  preferences_benice (NULL);
  preferences_autoload_dependencies (NULL);
  preferences_safe_checks_enabled (NULL);
  preferences_use_mac_addr (NULL);
  preferences_save_session (NULL);
  preferences_save_empty_sessions (NULL);
  preferences_silent_dependencies (NULL);
  preferences_network_scan (NULL);
}
