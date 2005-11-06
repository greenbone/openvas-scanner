/* Nessus
 * Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
