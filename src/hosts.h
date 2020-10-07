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
 * @file hosts.h
 * @brief hosts.c header.
 */

#ifndef HOSTS_H
#define HOSTS_H

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
