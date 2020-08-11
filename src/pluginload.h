/* Portions Copyright (C) 2009-2020 Greenbone Networks GmbH
 * Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

/**
 * @file pluginload.h
 * @brief pluginload.c header.
 */

#ifndef _OPENVAS_PLUGINLOAD_H
#define _OPENVAS_PLUGINLOAD_H

#include "../misc/network.h"
#include "../misc/scanneraux.h"

#include <gvm/util/kb.h> /* for struct kb_item */

int
plugins_init (void);

int
plugins_cache_init (void);

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
nasl_plugin_launch (struct scan_globals *, struct in6_addr *, GSList *, kb_t,
                    const char *);

#endif
