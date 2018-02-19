/* OpenVAS
* $Id$
* Description: Performs various checks for requirements set in a given plugin.
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

#include <stdlib.h> /* for atoi() */
#include <string.h> /* for strcmp() */
#include <stdio.h>  /* for snprintf() */

#include <openvas/misc/prefs.h>          /* for prefs_get() */
#include <openvas/base/nvticache.h>

#include "pluginscheduler.h"
#include "plugs_req.h"

/**********************************************************

 		   Private Functions

***********************************************************/

extern int kb_get_port_state_proto (kb_t, int, char *);

/**
 * @brief Returns whether a port in a port list is closed or not.
 *
 * @return Whether a port in a port list is closed or not.
 */
static int
get_closed_ports (kb_t kb, char *ports_list)
{
  int i;
  char **ports;

  if (!ports_list)
    return -1;

  ports = g_strsplit (ports_list, ", ", 0);
  for (i = 0; ports[i] != NULL; i ++)
    {
      int iport = atoi (ports[i]);
      if (iport != 0)
        {
          if (kb_get_port_state_proto (kb, iport, "tcp") != 0)
            {
              g_strfreev (ports);
              return iport;
            }
        }
      else
        {
          if (kb_item_get_int (kb, ports[i]) > 0)
            {
              g_strfreev (ports);
              return 1;           /* should be the actual value indeed ! */
            }
        }
    }
  g_strfreev (ports);
  return 0;                     /* found nothing */
}


/**
 * @brief Returns whether a port in a port list is closed or not.
 */
static int
get_closed_udp_ports (kb_t kb, char *ports_list)
{
  int i;
  char **ports;

  if (!ports_list)
    return -1;
  ports = g_strsplit (ports_list, ", ", 0);
  if (!ports_list)
    return -1;

  for (i = 0; ports[i] != NULL; i ++)
    {
      int iport = atoi (ports[i]);
      if (iport > 0 && kb_get_port_state_proto (kb, iport, "udp"))
        {
          g_strfreev (ports);
          return iport;
        }
    }
  g_strfreev (ports);
  return 0;                     /* found nothing */
}

/**********************************************************

 		   Public Functions

***********************************************************/


/**
 * @brief Returns \<port\> if the lists of the required ports between
 * @brief plugin 1 and plugin 2 have at least one port in common.
 */
struct arglist *
requirements_common_ports (struct scheduler_plugin *plugin1,
                           struct scheduler_plugin *plugin2)
{
  struct arglist *ret = NULL;
  int i, j;
  char *ports1, *ports2, **array1, **array2;

  if (!plugin1 || !plugin2)
    return 0;

  ports1 = nvticache_get_required_ports (plugin1->oid);
  ports2 = nvticache_get_required_ports (plugin2->oid);
  if (!ports1 || !ports2)
    {
      g_free (ports1);
      g_free (ports2);
      return 0;
    }
  array1 = g_strsplit (ports1, ", ", 0);
  array2 = g_strsplit (ports2, ", ", 0);
  g_free (ports1);
  g_free (ports2);
  if (!array1 || !array2)
    {
      g_strfreev (array1);
      g_strfreev (array2);
      return 0;
    }

  for (i = 0; array1[i] != NULL; i ++)
    {
      for (j = 0; array2[j] != NULL; j ++)
        {
           if (!strcmp (array2[j], array1[i]))
             {
               if (!ret)
                 ret = g_malloc0 (sizeof (struct arglist));
               arg_add_value (ret, array2[j], ARG_INT, (void *) 1);
             }
        }
    }
  g_strfreev (array1);
  g_strfreev (array2);
  return ret;
}

/**
 * @brief Returns the name of the first key which is not present in the \ref kb.
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
  for (i = 0; keynames[i] != NULL; i ++)
    {
      struct kb_item *kbi = kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

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
 * @brief Returns the name of the first key which is present in the \ref kb.
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
  for (i = 0; keynames[i] != NULL; i ++)
    {
      struct kb_item *kbi = kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

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
 * @brief Check whether mandatory requirements for plugin are met.
 *
 * @param kb     The arglist knowledge base with all keys.
 *
 * @param plugin The arglist plugin.
 *
 * @return 1 if all mandatory requirements for the plugin are
 *         met. 0 if it is not the case.
 */
int
mandatory_requirements_met (kb_t kb,
                            struct scheduler_plugin *plugin)
{
  char *mandatory_keys;
  int ret;

  mandatory_keys = nvticache_get_mandatory_keys (plugin->oid);
  ret = kb_missing_keyname_of_namelist (kb, mandatory_keys, NULL);

  g_free (mandatory_keys);
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
requirements_plugin (kb_t kb, struct scheduler_plugin *plugin)
{
  static char error[64];
  char *errkey = NULL, *keys, *tcp, *udp;
  const char *opti = prefs_get ("optimization_level");

  /*
   * Check wether the good ports are open
   */
  error[sizeof (error) - 1] = '\0';
  tcp = nvticache_get_required_ports (plugin->oid);
  if (tcp && *tcp && (get_closed_ports (kb, tcp)) == 0)
    {
      strncpy (error, "none of the required tcp ports are open",
               sizeof (error) - 1);
      g_free (tcp);
      return error;
    }
  g_free (tcp);

  udp = nvticache_get_required_udp_ports (plugin->oid);
  if (udp && *udp && (get_closed_udp_ports (kb, udp)) == 0)
    {
      strncpy (error, "none of the required udp ports are open",
               sizeof (error) - 1);
      g_free (udp);
      return error;
    }
  g_free (udp);

  if (opti != NULL && (strcmp (opti, "open_ports") == 0 || atoi (opti) == 1))
    return NULL;

  /*
   * Check wether a key we wanted is missing
   */
  keys = nvticache_get_required_keys (plugin->oid);
  if (kb_missing_keyname_of_namelist (kb, keys, &errkey))
    {
      snprintf (error, sizeof (error), "because the key %s is missing", errkey);
      g_free (errkey);
      g_free (keys);
      return error;
    }
  g_free (keys);

  if (opti != NULL && (strcmp (opti, "required_keys") == 0 || atoi (opti) == 2))
    return NULL;

  /*
   * Check wether a key we do not want is present
   */
  keys = nvticache_get_excluded_keys (plugin->oid);
  if (kb_present_keyname_of_namelist (kb, keys, &errkey))
    {
      snprintf (error, sizeof (error), "because the key %s is present", errkey);
      g_free (errkey);
      g_free (keys);
      return error;
    }
  g_free (keys);
  return NULL;
}
