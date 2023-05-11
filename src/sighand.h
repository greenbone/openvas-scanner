/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file sighand.h
 * @brief headerfile for sighand.c.
 */

#ifndef OPENVAS_SIGHAND_H
#define OPENVAS_SIGHAND_H

void (*openvas_signal (int signum, void (*handler) (int))) (int);
void

sighand_chld (int sig);

void
sighand_segv (int sig);

void
let_em_die (int pid);
void
make_em_die (int sig);
#endif
