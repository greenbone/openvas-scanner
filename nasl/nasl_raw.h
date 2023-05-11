/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_RAW_H
#define NASL_NASL_RAW_H

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
