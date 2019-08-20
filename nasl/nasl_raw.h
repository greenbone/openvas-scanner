/* Based on work Copyright (C) 2002 - 2004 Tenable Network Security
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

#ifndef OPENVAS_RAW_H
#define OPENVAS_RAW_H

#ifdef __linux__
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

/* legacy feature macros */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/* New feature macro that provides everything _BSD_SOURCE provided and
   possibly more. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#endif // __linux__

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/param.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>

#endif
