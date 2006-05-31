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


#ifndef _NESSUSD_PLUGINLOAD_H
#define _NESSUSD_PLUGINLOAD_H

struct arglist * plugins_init(struct arglist *, int);
struct arglist * plugins_reload(struct arglist *, struct arglist *, int);
struct arglist * plugins_reload_user(struct arglist*, struct arglist*, struct arglist*);
void plugin_set_socket(struct arglist *, int);
int  plugin_get_socket(struct arglist * );
void plugins_set_socket(struct arglist *, int);
void plugin_free(struct arglist *);
void plugins_free(struct arglist *);
typedef struct pl_class_s {
    struct pl_class_s* pl_next;
    const char* extension;
    struct pl_class_s* (*pl_init)(struct arglist*, struct arglist*);
    struct arglist* (*pl_add)(char*, char*, struct arglist*, struct arglist*);
    int (*pl_launch)(struct arglist*, struct arglist *, struct arglist*, struct arglist*, struct kb_item **, char *);
} pl_class_t;

extern pl_class_t nes_plugin_class;
extern pl_class_t nasl_plugin_class;
#endif
