/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file pluginlaunch.h
 * @brief pluginlaunch.c header.
 */

#ifndef OPENVAS_PLUGINLAUNCH_H
#define OPENVAS_PLUGINLAUNCH_H

#include "pluginload.h"      /* for struct pl_class_t */
#include "pluginscheduler.h" /* for struct plugins_scheduler_t */

/**
 * @brief Error for when it is not possible to fork a new plugin process.
 */
#define ERR_CANT_FORK -2
/**
 * @brief Error for when the process table is full
 */
#define ERR_NO_FREE_SLOT -99

void
pluginlaunch_init (const char *);
void pluginlaunch_wait (kb_t, kb_t);
void pluginlaunch_wait_for_free_process (kb_t, kb_t);

void
pluginlaunch_stop (void);

int
plugin_launch (struct scan_globals *, struct scheduler_plugin *,
               struct in6_addr *, GSList *, kb_t, kb_t, nvti_t *, int *);

void
pluginlaunch_disable_parallel_checks (void);
void
pluginlaunch_enable_parallel_checks (void);

int
wait_for_children (void);
#endif
