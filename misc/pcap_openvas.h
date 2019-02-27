/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
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
 * @file pcap_openvas.h
 * @brief Header file for module pcap.
 */

#ifndef OPENVAS_PCAP_H
#define OPENVAS_PCAP_H

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/param.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

int
v6_is_local_ip (struct in6_addr *);

int
islocalhost (struct in_addr *);

int
v6_islocalhost (struct in6_addr *);

int
get_datalink_size (int);

char *
routethrough (struct in_addr *, struct in_addr *);

char *
v6_routethrough (struct in6_addr *, struct in6_addr *);

int
v6_getsourceip (struct in6_addr *, struct in6_addr *);

#endif
