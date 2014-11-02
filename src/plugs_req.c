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

#include "preferences.h"     /* for prefs_get() */
#include "pluginscheduler.h"
#include "plugs_req.h"

/**********************************************************

 		   Private Functions

***********************************************************/

extern int kb_get_port_state_proto (kb_t, struct arglist *, int, char *);

/**
 * @brief Returns whether a port in a port list is closed or not.
 *
 * @return Whether a port in a port list is closed or not.
 */
static int
get_closed_ports (kb_t kb, gchar **ports,
                  struct arglist *preferences)
{
  int i;

  if (ports == NULL)
    return -1;

  for (i = 0; ports[i] != NULL; i ++)
    {
      int iport = atoi (ports[i]);
      if (iport != 0)
        {
          if (kb_get_port_state_proto (kb, preferences, iport, "tcp") != 0)
            return iport;
        }
      else
        {
          if (kb_item_get_int (kb, ports[i]) > 0)
            return 1;           /* should be the actual value indeed ! */
        }
    }
  return 0;                     /* found nothing */
}


/**
 * @brief Returns whether a port in a port list is closed or not.
 */
static int
get_closed_udp_ports (kb_t kb, gchar **ports,
                      struct arglist *preferences)
{
  int i;

  if (ports == NULL)
    return -1;

  for (i = 0; ports[i] != NULL; i ++)
    {
      int iport = atoi (ports[i]);
      if (iport > 0 && kb_get_port_state_proto (kb, preferences, iport, "udp"))
        return iport;
    }
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

  if (!plugin1 || !plugin2)
    return 0;

  if (plugin1->required_ports == NULL)
    return 0;

  if (plugin2->required_ports == NULL)
    return 0;

  for (i = 0; plugin1->required_ports[i] != NULL; i ++)
    {
      for (j = 0; plugin2->required_ports[j] != NULL; j ++)
        {
           if (!strcmp (plugin2->required_ports[j], plugin1->required_ports[i]))
             {
               if (!ret)
                 ret = g_malloc0 (sizeof (struct arglist));
               arg_add_value (ret, plugin2->required_ports[j], ARG_INT,
                              0, (void *) 1);
             }
        }
    }
  return ret;
}

/**
 * @brief Returns the name of the first key which is not present in the \ref kb.
 * @param[in] kb       KB handle where to search for the keys.
 * @param[in] keynames NULL-terminated string array of keynames.
 * @return A pointer to the string that was not found in the kb. This pointer
           points into the string in the given keynames array.
           NULL is returned in case all of the keys are present in the kb or
           the kb is NULL.
 */
static gchar *
kb_missing_keyname_of_namelist (kb_t kb, gchar **keynames)
{
  int i;

  if (kb == NULL || keynames == NULL)
    return NULL;

  for (i = 0; keynames[i] != NULL; i ++)
    {
      struct kb_item *kbi = kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

      if (kbi == NULL)
        return keynames[i]; /* This key is missing in the kb */

      kb_item_free (kbi);
    }

  return NULL; /* All of the keys are present in the kb */
}

/**
 * @brief Returns the name of the first key which is present in the \ref kb.
 * @param[in] kb       KB handle where to search for the keys.
 * @param[in] keynames NULL-terminated string array of keynames.
 * @return A pointer to the string that was found in the kb. This pointer
           points into the string in the given keynames array.
           NULL is returned in case none of the keys is present in the kb or
           the kb is NULL.
 */
static gchar *
kb_present_keyname_of_namelist (kb_t kb, gchar **keynames)
{
  int i;

  if (kb == NULL || keynames == NULL)
    return NULL;

  for (i = 0; keynames[i] != NULL; i ++)
    {
      struct kb_item *kbi = kb_item_get_single (kb, keynames[i], KB_TYPE_UNSPEC);

      if (kbi != NULL)
        {
          kb_item_free (kbi);
          return keynames[i];
        }
    }
  return NULL;
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
  if (kb_missing_keyname_of_namelist (kb, plugin->mandatory_keys))
    return 0;

  return 1;
}

/**
 * @brief Determine if the plugin requirements are met.
 *
 * @return Returns NULL is everything is ok, else an error message.
 */
char *
requirements_plugin (kb_t kb, struct scheduler_plugin *plugin,
                     struct arglist *preferences)
{
  static char error[64];
  char *missing;
  char *present;
  gchar **tcp, **udp;
  const char *opti = prefs_get ("optimization_level");

  /*
   * Check wether the good ports are open
   */
  error[sizeof (error) - 1] = '\0';
  tcp = plugin->required_ports;
  if (tcp != NULL && (get_closed_ports (kb, tcp, preferences)) == 0)
    {
      strncpy (error, "none of the required tcp ports are open",
               sizeof (error) - 1);
      return error;
    }

  udp = plugin->required_udp_ports;
  if (udp != NULL && (get_closed_udp_ports (kb, udp, preferences)) == 0)
    {
      strncpy (error, "none of the required udp ports are open",
               sizeof (error) - 1);
      return error;
    }

  if (opti != NULL && (strcmp (opti, "open_ports") == 0 || atoi (opti) == 1))
    return NULL;

  /*
   * Check wether a key we wanted is missing
   */
  if ((missing = kb_missing_keyname_of_namelist (kb, plugin->required_keys)))
    {
      snprintf (error, sizeof (error), "because the key %s is missing",
                missing);
      return error;
    }

  if (opti != NULL && (strcmp (opti, "required_keys") == 0 || atoi (opti) == 2))
    return NULL;

  /*
   * Check wether a key we do not want is present
   */
  if ((present = kb_present_keyname_of_namelist (kb, plugin->excluded_keys)))
    {
      snprintf (error, sizeof (error), "because the key %s is present",
                present);
      return error;
    }
  return NULL;
}
