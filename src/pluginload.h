/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file pluginload.h
 * @brief pluginload.c header.
 */

#ifndef OPENVAS_PLUGINLOAD_H
#define OPENVAS_PLUGINLOAD_H

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
nasl_plugin_add (const char *, char *);
int
nasl_file_check (const char *, const char *);

int
nasl_plugin_launch (struct scan_globals *, struct in6_addr *, GSList *, kb_t,
                    const char *);

#endif
