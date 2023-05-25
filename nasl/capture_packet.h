/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_CAPTURE_PACKET_H
#define NASL_CAPTURE_PACKET_H

#include <netinet/in.h>
#include <netinet/ip6.h>

int
init_capture_device (struct in_addr, struct in_addr, char *);

struct ip *
capture_next_packet (int, int, int *);

char *
capture_next_frame (int, int, int *, int);

int
init_v6_capture_device (struct in6_addr, struct in6_addr, char *);

struct ip6_hdr *
capture_next_v6_packet (int, int, int *);

#endif
