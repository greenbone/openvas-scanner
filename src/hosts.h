/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file hosts.h
 * @brief hosts.c header.
 */

#ifndef OPENVAS_HOSTS_H
#define OPENVAS_HOSTS_H

#include "../misc/scanneraux.h"

#include <gvm/base/hosts.h> /* for gvm_host_t */

int
hosts_init (int);

int
hosts_new (char *, kb_t, kb_t);

int
hosts_set_pid (char *, pid_t);

int
hosts_read (void);

void
hosts_stop_all (void);

void
host_set_time (kb_t, char *, char *);

int
host_is_currently_scanned (gvm_host_t *);

#endif
