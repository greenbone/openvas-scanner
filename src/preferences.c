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
#include <openvas/misc/kb.h>         /* for KB_PATH_DEFAULT */
#include <openvas/misc/arglists.h>   /* for struct arglist */

static struct arglist *global_prefs = NULL;

/**
 * @brief Get the pointer to the global preferences structure
 */
struct arglist *
preferences_get (void)
{
  return global_prefs;
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
 * @brief Initializes the preferences structure. If it was
 *        already initialized, remove old settings and start
 *        from scratch.
 */
void
prefs_init (void)
{
  if (global_prefs)
    arg_free (global_prefs);

  global_prefs = g_malloc0 (sizeof (struct arglist));
}

/**
 * @brief Apply the configs from given file as preferences.
 *
 * @param config    Filename of the configuration file.
 */
void
prefs_config (const char *config)
{
  settings_iterator_t settings;

  if (!global_prefs)
    prefs_init ();

  if (!init_settings_iterator_from_file (&settings, config, "Misc"))
    {
      while (settings_iterator_next (&settings))
          prefs_set (settings_iterator_name (&settings),
                     settings_iterator_value (&settings));

      cleanup_settings_iterator (&settings);
    }

  prefs_set ("config_file", config);
}

/**
 * @brief Dump the preferences to stdout
 */
void
prefs_dump (void)
{
  struct arglist * prefs = global_prefs;

  while (prefs && prefs->next)
    {
      printf ("%s = %s\n", prefs->name, (char *) prefs->value);
      prefs = prefs->next;
    }
}

/**
 * @brief Returns the timeout defined by the client or 0 if none was set.
 *
 * @param oid         OID of NVT to ask timeout value of.
 *
 * @return 0 if no timeout for the NVT oid was found, timeout in seconds
 *         otherwise.
 */
int
prefs_nvt_timeout (const char *oid)
{
  char *pref_name = g_strdup_printf ("timeout.%s", oid);
  const char * val = prefs_get (pref_name);
  int timeout = (val ? atoi (val) : 0);

  g_free (pref_name);

  return timeout;
}
