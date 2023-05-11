/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file plugs_req.c
 * @brief Performs various checks for requirements set in a given plugin.
 */

#include "plugs_req.h"

#include "pluginscheduler.h"

#include <gvm/base/prefs.h> /* for prefs_get() */
#include <gvm/util/nvticache.h>
#include <regex.h>  /* for regcomp() */
#include <stdio.h>  /* for snprintf() */
#include <stdlib.h> /* for atoi() */
#include <string.h> /* for strcmp() */

/**********************************************************

                   Private Functions

***********************************************************/

extern int
kb_get_port_state_proto (kb_t, int, char *);

/**
 * @brief Returns whether a port in a port list is closed or not.
 *
 * @return Whether a port in a port list is closed or not.
 */
static int
get_closed_ports (kb_t kb, char *ports_list, char *proto)
{
  int i;
  char **ports;

  if (!ports_list)
    return -1;
  ports = g_strsplit (ports_list, ", ", 0);
  for (i = 0; ports[i] != NULL; i++)
    {
      int iport = atoi (ports[i]);
      if (iport > 0 && kb_get_port_state_proto (kb, iport, proto) != 0)
        {
          g_strfreev (ports);
          return iport;
        }
      else
        {
          if (kb_item_get_int (kb, ports[i]) > 0)
            {
              g_strfreev (ports);
              return 1; /* should be the actual value indeed ! */
            }
        }
    }
  g_strfreev (ports);
  return 0; /* found nothing */
}

/**********************************************************

                   Public Functions

***********************************************************/

/**
 * @brief Returns the name of the first key which is not present in the \p kb.
 * @param[in]   kb      KB handle where to search for the keys.
 * @param[in]   keys    Comma separated list of keys.
 * @param[out]  keyname Key that was missing. Free with g_free().
 *
 * @return 1 if a key is missing in KB, 0 otherwise.
 */
static int
kb_missing_keyname_of_namelist (kb_t kb, char *keys, char **keyname)
{
  int i;
  char **keynames;
  if (!kb || !keys || !*keys)
    return 0;

  keynames = g_strsplit (keys, ", ", 0);
  if (!keynames)
    return 0;
  for (i = 0; keynames[i] != NULL; i++)
    {
      struct kb_item *kbi =
        kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

      if (kbi == NULL)
        {
          if (keyname)
            *keyname = g_strdup (keynames[i]);
          g_strfreev (keynames);
          return 1;
        }

      kb_item_free (kbi);
    }

  g_strfreev (keynames);
  return 0; /* All of the keys are present in the kb */
}

/**
 * @brief Returns the name of the first key which is present in the \p kb.
 * @param[in]   kb      KB handle where to search for the keys.
 * @param[in]   keys    Comma separated list of keys.
 * @param[out]  keyname Key that was found. Free with g_free().
 *
 * @return 1 if a key is present in KB, 0 otherwise.
 */
static int
kb_present_keyname_of_namelist (kb_t kb, char *keys, char **keyname)
{
  int i;
  char **keynames;

  if (!kb || !keys || !*keys)
    return 0;

  keynames = g_strsplit (keys, ", ", 0);
  if (!keynames)
    return 0;
  for (i = 0; keynames[i] != NULL; i++)
    {
      struct kb_item *kbi =
        kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

      if (kbi != NULL)
        {
          if (keyname)
            *keyname = g_strdup (keynames[i]);
          kb_item_free (kbi);
          g_strfreev (keynames);
          return 1;
        }
    }

  g_strfreev (keynames);
  return 0;
}

/**
 * @brief Checks mandatory keys presence and value in the KB.
 * @param[in]   kb      KB handle where to search for the keys.
 * @param[in]   keys    Comma separated list of mandatory keys.
 *
 * @return 1 if a key is missing or not matching its value, 0 otherwise.
 */
static int
check_mandatory_keys (kb_t kb, char *keys)
{
  int i;
  char **keynames;

  if (!kb || !keys || !*keys)
    return 0;
  keynames = g_strsplit (keys, ", ", 0);
  if (!keynames)
    return 0;
  for (i = 0; keynames[i] != NULL; i++)
    {
      struct kb_item *kbi;
      char *re_str = NULL, *pos;

      /* Split, if key requires RE matching. */
      if ((pos = strstr (keynames[i], "=")))
        {
          re_str = pos + 1;
          *pos = '\0';
        }

      kbi = kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);
      if (!kbi)
        {
          g_strfreev (keynames);
          return 1;
        }

      if (re_str)
        {
          regex_t re;

          /* Check if RE matches. */
          if (kbi->type != KB_TYPE_STR || !kbi->v_str)
            {
              g_strfreev (keynames);
              kb_item_free (kbi);
              return 1;
            }
          if (regcomp (&re, re_str, REG_EXTENDED | REG_NOSUB | REG_ICASE))
            {
              g_warning ("Couldn't compile regex %s", re_str);
              g_strfreev (keynames);
              kb_item_free (kbi);
              return 1;
            }
          if (regexec (&re, kbi->v_str, 0, NULL, 0) == REG_NOMATCH)
            {
              g_strfreev (keynames);
              kb_item_free (kbi);
              regfree (&re);
              return 1;
            }
          regfree (&re);
        }
      kb_item_free (kbi);
    }

  g_strfreev (keynames);
  return 0;
}

/**
 * @brief Check whether mandatory requirements for plugin are met.
 *
 * @param kb     The knowledge base with all keys.
 *
 * @param plugin The scheduler plugin.
 *
 * @return 1 if all mandatory requirements for the plugin are
 *         met. 0 if it is not the case.
 */
int
mandatory_requirements_met (kb_t kb, nvti_t *nvti)
{
  int ret;

  ret = check_mandatory_keys (kb, nvti_mandatory_keys (nvti));

  if (ret)
    return 0;
  return 1;
}

/**
 * @brief Determine if the plugin requirements are met.
 *
 * @return Returns NULL is everything is ok, else an error message.
 */
char *
requirements_plugin (kb_t kb, nvti_t *nvti)
{
  static char error[64];
  char *errkey = NULL, *keys, *tcp, *udp;
  const char *opti = prefs_get ("optimization_level");

  /*
   * Check whether the good ports are open
   */
  error[sizeof (error) - 1] = '\0';
  tcp = nvti_required_ports (nvti);
  if (tcp && *tcp && (get_closed_ports (kb, tcp, "tcp")) == 0)
    {
      strncpy (error, "none of the required tcp ports are open",
               sizeof (error) - 1);
      return error;
    }

  udp = nvti_required_udp_ports (nvti);
  if (udp && *udp && (get_closed_ports (kb, udp, "udp")) == 0)
    {
      strncpy (error, "none of the required udp ports are open",
               sizeof (error) - 1);
      return error;
    }

  if (opti != NULL && (strcmp (opti, "open_ports") == 0 || atoi (opti) == 1))
    return NULL;

  /*
   * Check whether a key we wanted is missing
   */
  keys = nvti_required_keys (nvti);
  if (kb_missing_keyname_of_namelist (kb, keys, &errkey))
    {
      snprintf (error, sizeof (error), "because the key %s is missing", errkey);
      g_free (errkey);
      return error;
    }

  if (opti != NULL && (strcmp (opti, "required_keys") == 0 || atoi (opti) == 2))
    return NULL;

  /*
   * Check whether a key we do not want is present
   */
  keys = nvti_excluded_keys (nvti);
  if (kb_present_keyname_of_namelist (kb, keys, &errkey))
    {
      snprintf (error, sizeof (error), "because the key %s is present", errkey);
      g_free (errkey);
      return error;
    }
  return NULL;
}
