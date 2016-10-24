/* OpenVAS
* $Id$
* Description: pluginlaunch.c header.
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

#ifndef __PLUGINLAUNCH_H__
#define __PLUGINLAUNCH_H__

#include "pluginload.h"         /* for struct pl_class_t */
#include "pluginscheduler.h"    /* for struct plugins_scheduler_t */

void pluginlaunch_init (const char *);
void pluginlaunch_wait (void);
void pluginlaunch_wait_for_free_process (void);
void pluginlaunch_stop (int);
int plugin_launch (struct arglist *, struct scheduler_plugin *,
                   struct host_info *, kb_t, char *);

void pluginlaunch_child_cleanup (void);
void pluginlaunch_disable_parrallel_checks (void);
void pluginlaunch_enable_parrallel_checks (void);

int wait_for_children (void);
#endif
