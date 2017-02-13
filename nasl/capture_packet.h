/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CAPTURE_PACKET_H
#define CAPTURE_PACKET_H

#include <netinet/in.h>
#include <netinet/ip6.h>

int init_capture_device (struct in_addr, struct in_addr, char *);
struct ip *capture_next_packet (int, int, int *);

int init_v6_capture_device (struct in6_addr, struct in6_addr, char *);
struct ip6_hdr *capture_next_v6_packet (int, int, int *);
#endif
