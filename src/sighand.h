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
 * @file sighand.h
 * @brief headerfile for sighand.c.
 */

#ifndef _OPENVAS_SIGHAND_H
#define _OPENVAS_SIGHAND_H

#define OVAS_SIG_ALWAYS -1
#define OVAS_SIG_ALL -1

void
init_signal_handlers (void);

void
free_signal_handler (int sig);

void
add_handler (int sig, void (*handler) (), void *data, int stop, int n);
#endif
