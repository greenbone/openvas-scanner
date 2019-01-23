/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Based on work Copyright (C) 1998 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file ftp_funcs.h
 * @brief Header file for module ftp_funcs.
 */

#ifndef OPENVAS_FTP_FUNCS_H
#define OPENVAS_FTP_FUNCS_H

#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/param.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

int ftp_log_in (int, char *, char *);
int ftp_get_pasv_address (int, struct sockaddr_in *);

#endif
