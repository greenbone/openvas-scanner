/* OpenVAS
 * $Id$
 * Description: IDS stressing functions.
 *
 * ids_send() sends data spliced into several packets, with bad packets
 * between them, thus making bad NIDSes reassemble the tcp stream awkwardly;
 *
 * ids_open_sock_tcp() opens a tcp socket and immediately sends a badly
 * formed RST packet to the remote host, thus making bad NIDSes think
 * the connection was immediately dropped on our end.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2002 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __OPENVAS_IDS_SEND_H__
#define __OPENVAS_IDS_SEND_H__

/* for struct arglist */
#include "arglists.h"

/*
 * Transport layer options
 * XXX: These defines were moved here from libopenvas.h sind they
 * are used most often in ids_send module. More reengineering
 * probably needed.
 */
#define OPENVAS_CNX_IDS_EVASION_SPLIT	1L      /* Try to evade NIDS by spliting sends */
#define OPENVAS_CNX_IDS_EVASION_INJECT	2L      /* Split + insert garbage */
#define OPENVAS_CNX_IDS_EVASION_SHORT_TTL 4L    /* Split + too short ttl for garbage */
#define OPENVAS_CNX_IDS_EVASION_FAKE_RST  8L    /* Send a fake RST from our end after each established connection */

#define OPENVAS_CNX_IDS_EVASION_SEND_MASK (OPENVAS_CNX_IDS_EVASION_SPLIT|OPENVAS_CNX_IDS_EVASION_INJECT|OPENVAS_CNX_IDS_EVASION_SHORT_TTL)

int ids_send (int, void *, int, int);
int ids_open_sock_tcp (struct arglist *, int, int, int);

#endif
