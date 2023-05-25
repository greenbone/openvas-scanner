/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file processes.h
 * @brief processes.c header.
 */

#ifndef OPENVAS_PROCESSES_H
#define OPENVAS_PROCESSES_H

#include "../misc/ipc.h"

#include <sys/types.h> /* for pid_t */

#define FORKFAILED -1
#define NOINIT -2
#define PROCSFULL -3
#define NOCHILD -4

typedef void (*process_func_t) (void *);

void
procs_terminate_childs (void);

int
terminate_process (pid_t pid);

pid_t
create_ipc_process (ipc_process_func func, void *args);
const struct ipc_contexts *
procs_get_ipc_contexts (void);

int
procs_cleanup_children (void);

#endif
