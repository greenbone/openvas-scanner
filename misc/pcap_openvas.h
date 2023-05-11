/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2007 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file pcap_openvas.h
 * @brief Header file for module pcap.
 */

#ifndef MISC_PCAP_OPENVAS_H
#define MISC_PCAP_OPENVAS_H

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

char *
get_iface_from_ip (const char *);

int
get_iface_index (struct in6_addr *, int *);

#endif
