/* OpenVAS
* $Id$
* Description: header for pluginscheduler.c
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
*
*
*/


#ifndef PLUGINSCHEDULER_H
#define PLUGINSCHEDULER_H

#include <glib.h> /* for gchar */

#include <openvas/misc/arglists.h>

struct hash;
struct plugins_scheduler;

/**
 * @brief States of scheduler_plugin.
 *
 * @todo Consider creating an enumeration.
 */
#define LAUNCH_DISABLED 0
#define LAUNCH_RUN      1

struct scheduler_plugin
{
  int running_state;
  int category;
  int timeout;
  struct arglist *required_ports;
  struct arglist *required_udp_ports;
  gchar **required_keys;  /* Last element is NULL (created by g_strsplit) */
  gchar **mandatory_keys; /* Last element is NULL (created by g_strsplit) */
  gchar **excluded_keys;  /* Last element is NULL (created by g_strsplit) */
  struct arglist *arglist;
  struct hash *parent_hash;
};


typedef struct plugins_scheduler *plugins_scheduler_t;


#define PLUG_RUNNING ((struct scheduler_plugin*)0x02)
#define PLUGIN_STATUS_UNRUN 		1
#define PLUGIN_STATUS_RUNNING		2
#define PLUGIN_STATUS_DONE		3
#define PLUGIN_STATUS_DONE_AND_CLEANED 	4


plugins_scheduler_t plugins_scheduler_init (struct arglist *, int, int);
struct scheduler_plugin *plugins_scheduler_next (plugins_scheduler_t);

void plugins_scheduler_free (plugins_scheduler_t);

#endif
