/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @file pluginscheduler.h
 * @brief header for pluginscheduler.c
 */

#ifndef PLUGINSCHEDULER_H
#define PLUGINSCHEDULER_H

#include <glib.h>

struct plugins_scheduler;

enum plugin_status
{
  PLUGIN_STATUS_UNRUN = 0,
  PLUGIN_STATUS_RUNNING,
  PLUGIN_STATUS_DONE,
};

struct scheduler_plugin
{
  char *oid;
  GSList *deps;
  enum plugin_status running_state;
};

typedef struct plugins_scheduler *plugins_scheduler_t;

#define PLUG_RUNNING ((struct scheduler_plugin *) 0x02)

plugins_scheduler_t
plugins_scheduler_init (const char *, int, int);

struct scheduler_plugin *plugins_scheduler_next (plugins_scheduler_t);

int plugins_scheduler_count_active (plugins_scheduler_t);

void plugins_scheduler_stop (plugins_scheduler_t);

void plugins_scheduler_free (plugins_scheduler_t);

#endif
