/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file utils.h
 * @brief utils.c headerfile.
 */

#ifndef OPENVAS_UTILS_H
#define OPENVAS_UTILS_H

#include "../misc/scanneraux.h"

#include <sys/types.h> /* for pid_t */

int
get_max_hosts_number (void);

int
get_max_checks_number (void);

int process_alive (pid_t);

int
data_left (int);

void
wait_for_children1 (void);

int
is_scanner_only_pref (const char *);

int
store_file (struct scan_globals *globals, const char *file,
            const char *file_hash);

int
check_host_still_alive (kb_t, const char *);
#endif
