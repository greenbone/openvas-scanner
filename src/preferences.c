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
 * This module is under construction to migrate from a former server-centric
 * and arglist-based implemention to a general module for getting and setting
 * preferences which are stored in a global structure.
 * All functions named prefs_ are of the new type, but for the time being
 * still use arglist until the API is consquently used. All other functions
 * are from the old implementation and should be replaced/removed eventually.
 *
 * Old description for this module:
 * 
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

#include <string.h> /* for strlen() */
#include <stdlib.h> /* for atoi() */
#include <stdio.h>  /* for printf() */
#include <glib.h>

#include <openvas/base/settings.h>   /* for init_settings_iterator_from_file */
#include <openvas/misc/kb.h>

#include "comm.h"
#include "preferences.h"
#include "log.h"
#include "utils.h"

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
  {"cgi_path", "/cgi-bin:/scripts"},
  {"optimize_test", "yes"},
  {"checks_read_timeout", "5"},
  {"network_scan", "no"},
  {"non_simult_ports", "139, 445"},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"safe_checks", "yes"},
  {"auto_enable_dependencies", "yes"},
  {"use_mac_addr", "no"},
  {"nasl_no_signature_check", "yes"},
  {"drop_privileges", "no"},
  {"unscanned_closed", "yes"},
  {"unscanned_closed_udp", "yes"},
  // Empty options must be "\0", not NULL, to match the behavior of
  // preferences_process.
  {"vhosts", "\0"},
  {"vhosts_ip", "\0"},
  {"report_host_details", "yes"},
  {"cert_file", SCANNERCERT},
  {"key_file", SCANNERKEY},
  {"ca_file", CACERT},
  {"kb_location", KB_PATH_DEFAULT},
  {NULL, NULL}
};

static struct arglist *global_prefs = NULL;

/**
 * @brief Initializes the preferences structure
 */
struct arglist *
preferences_init (char *config_file)
{
  if (global_prefs)
    arg_free (global_prefs);

  global_prefs = g_malloc0 (sizeof (struct arglist));
  preferences_process (config_file, global_prefs);
  return global_prefs;
}

/**
 * @brief Get the pointer to the global preferences structure
 */
struct arglist *
preferences_get (void)
{
  return global_prefs;
}

/**
 * @brief Replace the old preferences with the given new ones.
 */
void
preferences_set (struct arglist * new_prefs)
{
  global_prefs = new_prefs;
}

/**
 * @brief Get a string preference value via a key.
 *
 * @param key    The identifier for the preference.
 *
 * @return A pointer to a string with the value for the preference.
 *         NULL in case for the key no preference was found or the
 *         preference is not of type string.
 */
const gchar *
prefs_get (const gchar * key)
{
  if (arg_get_type (global_prefs, key) != ARG_STRING)
    return NULL;

  return arg_get_value (global_prefs, key);
}

/**
 * @brief Get a boolean expression of a preference value via a key.
 *
 * @param key    The identifier for the preference.
 *
 * @return 1 if the value is considered to represent "true" and
 *         0 if the value is considered to represent "false".
 *         If the preference is of type string, value "yes" is true,
 *         anything else is false.
 *         Any other type or non-existing key is false.
 */
int
prefs_get_bool (const gchar * key)
{
  if (arg_get_type (global_prefs, key) == ARG_STRING)
    {
      gchar *str = arg_get_value (global_prefs, key);
      if (str && !strcmp (str, "yes"))
        return 1;
    }

  return 0;
}

/**
 * @brief Set a string preference value via a key.
 *
 * @param key    The identifier for the preference. A copy of this will
 *               be created if necessary.
 *
 * @param value  The value to set. A copy of this will be created. 
 */
void
prefs_set (const gchar * key, const gchar * value)
{
  if (arg_get_value (global_prefs, key))
    {
      gchar *old = arg_get_value (global_prefs, key);
      g_free (old);
      arg_set_value (global_prefs, key, strlen (value), g_strdup (value));
      return;
    }

  arg_add_value (global_prefs, key, ARG_STRING, strlen (value), g_strdup (value));
}

/**
 * @brief Dump the preferences to stdout
 */
void
preferences_dump (void)
{
  struct arglist * prefs = global_prefs;

  while (prefs && prefs->next)
    {
      printf ("%s = %s\n", prefs->name, (char *) prefs->value);
      prefs = prefs->next;
    }
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

  arg_add_value (prefs, "config_file", ARG_STRING, strlen (filename),
                 g_strdup (filename));
  return 0;
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

  g_free (pref_name);
  return ret;
}

/**
 * @brief Get a integer boolean value of a "yes"/"no" preference.
 *
 * @return 0 if the preference is "no", 1 if "yes", -1 upon error.
 */
int
preferences_get_bool (struct arglist *preferences, char *name)
{
  char *pref = arg_get_value (preferences, name);

  if (!pref || pref[0] == '\0')
    return -1;
  if (!strcmp (pref, "no"))
    return 0;
  if (!strcmp (pref, "yes"))
    return 1;

  return -1;
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
