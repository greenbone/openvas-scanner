/* OpenVAS
* $Id$
* Description: Defines for UDP struct.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

/** @todo A similar file exists in openvas-libraries/nasl/, but prefixed 'nasl'
 *        instead of 'openvas'. If resolution of cnvts proceeds slowly,
 *        consider removal. */

#ifndef OPENVASUDP_H__
#define OPENVASUDP_H__

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#if !defined(HAVE_STRUCT_UDPHDR) || HAVE_STRUCT_UDPHDR == 0
#define HAVE_STRUCT_UDPHDR 1
struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};
#endif

#if defined(HAVE_STRUCT_UDPHDR) && !defined(HAVE_BSD_STRUCT_UDPHDR)
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#endif /* OPENVASUDP_H__ */
