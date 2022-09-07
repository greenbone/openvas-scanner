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
#ifndef MISC_IPC_PIPE_H
#define MISC_IPC_PIPE_H

struct ipc_pipe_context
{
  int fd[2];
};

int
ipc_pipe_send (struct ipc_pipe_context *context, const char *msg, int len);

char *
ipc_pipe_retrieve (struct ipc_pipe_context *context);

int
ipc_pipe_destroy (struct ipc_pipe_context *context);

int
ipc_pipe_close (struct ipc_pipe_context *context);

struct ipc_pipe_context *
ipc_init_pipe (void);

#endif
