/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   

#ifndef _NESSUSC_FAMILIES_H
#define _NESSUSC_FAMILIES_H

#define ENABLE_FAMILY 1
#define DISABLE_FAMILY 0
#define ENABLE_FAMILY_BUT_DOS 2

struct plugin_families {
	char * name;
	int enabled;
	struct plugin_families * next;
	};
	
struct plugin_families * family_init();
void family_add(struct plugin_families *, struct arglist *);
void family_enable(char *, struct arglist *, int);
int family_enabled(char *, struct arglist *);
int family_empty(char*, struct arglist*);
#endif
