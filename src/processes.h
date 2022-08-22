/* Portions Copyright (C) 2009-2022 Greenbone Networks GmbH
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
 * @file processes.h
 * @brief processes.c header.
 */

#ifndef _OPENVAS_THREADS_H
#define _OPENVAS_THREADS_H

#include "../misc/ipc.h"

#include "../misc/ipc.h"

#include <sys/types.h> /* for pid_t */

#define FORKFAILED -1
#define NOINIT -2
#define PROCSFULL -3
#define NOCHILD -4

typedef void (*process_func_t) (void *);

void
procs_init (int max);

void
procs_terminate_childs (void);

int
terminate_process (pid_t pid);

pid_t
create_ipc_process (ipc_process_func func, void *args);
const struct ipc_contexts *
procs_get_ipc_contexts (void);

#endif
