/* OpenVAS
* $Id$
* Description: pluginload.c header.
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


#ifndef _OPENVAS_PLUGINLOAD_H
#define _OPENVAS_PLUGINLOAD_H

#include <openvas/misc/arglists.h>   /* for struct arglist */
#include <openvas/base/kb.h>         /* for struct kb_item */
#include <openvas/misc/network.h>

int
plugins_init (void);

void
init_loading_shm (void);

void
destroy_loading_shm (void);

int
current_loading_plugins (void);

int
total_loading_plugins (void);

/* From nasl_plugins.c */
int
nasl_plugin_add (char *, char *);

int
nasl_plugin_launch (struct arglist *, struct host_info *, kb_t, char *,
                    const char *, int);

#endif
