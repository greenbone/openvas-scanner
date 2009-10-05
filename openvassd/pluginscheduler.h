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

/**
 * @brief States of scheduler_plugin.
 *
 * @todo Consider creating an enumeration.
 */
#define LAUNCH_DISABLED 0
#define LAUNCH_RUN      1
#define LAUNCH_SILENT   2

struct scheduler_plugin {
	int running_state;
	int category;
	int timeout;
	struct arglist * required_ports;
	struct arglist * required_udp_ports;
	struct arglist * required_keys;
	struct arglist * mandatory_keys;
	struct arglist * excluded_keys;
	struct arglist * arglist;
	struct hash   *  parent_hash;
};

#ifndef IN_SCHEDULER_CODE
typedef void * plugins_scheduler_t;
#else
struct watch_list {
	char * name;
	struct watch_list * next;
};


struct hash {
	char * name;
	struct scheduler_plugin * plugin;
	char ** dependencies;
	int num_deps;
	struct hash ** dependencies_ptr;
	char ** ports;
	struct hash * next;
	};

struct list {
	char * name;
	struct scheduler_plugin * plugin;
	struct list * next;
	struct list * prev;
	};
	
struct plist {
	char name[64];
	int occurences;
	struct plist * next;
	struct plist * prev;
	};	

struct plugins_scheduler_struct {
	struct hash  * hash;			/* Hash list of the plugins   */
	struct list  * list[ACT_LAST+1];	/* Linked list of the plugins */
	struct plist * plist; 			/* Ports currently in use     */
	};
	
typedef struct plugins_scheduler_struct * plugins_scheduler_t;

#endif


#define PLUG_RUNNING ((struct scheduler_plugin*)0x02)
#define PLUGIN_STATUS_UNRUN 		1
#define PLUGIN_STATUS_RUNNING		2
#define PLUGIN_STATUS_DONE		3
#define PLUGIN_STATUS_DONE_AND_CLEANED 	4


void plugin_set_running_state(plugins_scheduler_t, struct scheduler_plugin * , int);

plugins_scheduler_t plugins_scheduler_init(struct arglist*, int, int);
struct scheduler_plugin * plugins_scheduler_next(plugins_scheduler_t);

void plugins_scheduler_free(plugins_scheduler_t);

#endif
