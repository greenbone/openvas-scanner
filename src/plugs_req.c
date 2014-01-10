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

#include <openvas/misc/system.h>     /* for emalloc */

#include "pluginscheduler.h"
#include "plugs_req.h"

/**********************************************************

 		   Private Functions

***********************************************************/

extern int kb_get_port_state_proto (kb_t, struct arglist *, int,
                                    char *);

/**
 * @brief Returns whether a port in a port list is closed or not.
 *
 * @return Whether a port in a port list is closed or not.
 */
static int
get_closed_ports (kb_t kb, struct arglist *ports,
                  struct arglist *preferences)
{
  if (ports == NULL)
    return -1;

  while (ports->next != NULL)
    {
      int iport = atoi (ports->name);
      if (iport != 0)
        {
          if (kb_get_port_state_proto (kb, preferences, iport, "tcp") != 0)
            return iport;
        }
      else
        {
          if (kb_item_get_int (kb, ports->name) > 0)
            return 1;           /* should be the actual value indeed ! */
        }
      ports = ports->next;
    }
  return 0;                     /* found nothing */
}


/**
 * @brief Returns whether a port in a port list is closed or not.
 */
static int
get_closed_udp_ports (kb_t kb, struct arglist *ports,
                      struct arglist *preferences)
{
  if (ports == NULL)
    return -1;

  while (ports->next != NULL)
    {
      int iport = atoi (ports->name);
      if (kb_get_port_state_proto (kb, preferences, iport, "udp"))
        return iport;
      ports = ports->next;
    }
  return 0;                     /* found nothing */
}


/**
 * @brief Returns the name of the first key which is not \ref kb.
 */
static char *
key_missing (kb_t kb, struct arglist *keys)
{
  if (kb == NULL || keys == NULL)
    return NULL;
  else
    {
      while (keys->next != NULL)
        {
          if (kb_item_get_single (kb, keys->name, 0) == NULL)
            return keys->name;
          else
            keys = keys->next;
        }
    }
  return NULL;
}

/**
 * @brief The opposite of the previous function (\ref key_missing).
 */
static char *
key_present (kb_t kb, struct arglist *keys)
{
  if (kb == NULL || keys == NULL)
    return NULL;
  else
    {
      while (keys->next != NULL)
        {
          if (kb_item_get_single (kb, keys->name, 0) != NULL)
            return keys->name;
          else
            keys = keys->next;
        }
    }
  return NULL;
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
  struct arglist *req1;
  struct arglist *req2;

  if (!plugin1 || !plugin2)
    return 0;

  req1 = plugin1->required_ports;
  if (req1 == NULL)
    return 0;

  req2 = plugin2->required_ports;
  if (req2 == NULL)
    return 0;

  while (req1->next != NULL)
    {
      struct arglist *r = req2;
      if (r != NULL)
        while (r->next != NULL)
          {
            if (req1->type == r->type)
              {
                if (r->name && req1->name && !strcmp (r->name, req1->name))
                  {
                    if (!ret)
                      ret = emalloc (sizeof (struct arglist));
                    arg_add_value (ret, r->name, ARG_INT, 0, (void *) 1);
                  }
              }
            r = r->next;
          }
      req1 = req1->next;
    }
  return ret;
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
  if (key_missing (kb, plugin->mandatory_keys))
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
  struct arglist *tcp, *udp, *rkeys, *ekeys;
  char *opti = arg_get_value (preferences, "optimization_level");

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
  rkeys = plugin->required_keys;
  if ((missing = key_missing (kb, rkeys)))
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
  ekeys = plugin->excluded_keys;
  if ((present = key_present (kb, ekeys)))
    {
      snprintf (error, sizeof (error), "because the key %s is present",
                present);
      return error;
    }
  return NULL;
}
