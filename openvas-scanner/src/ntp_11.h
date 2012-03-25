/* OpenVAS
* $Id$
* Description: Header for ntp_11.c.
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


#ifndef _OPENVAS_NTP_11_H
#define _OPENVAS_NTP_11_H

#include <openvas/misc/arglists.h>   /* for struct arglist */

#define NTP_STOP_WHOLE_TEST 2
#define NTP_PAUSE_WHOLE_TEST 3
#define NTP_RESUME_WHOLE_TEST 4

int ntp_11_parse_input (struct arglist *, char *);
void ntp_11_show_end (struct arglist *, char *, int);

int ntp_1x_timestamp_host_scan_starts (struct arglist *, char *);
int ntp_1x_timestamp_host_scan_ends (struct arglist *, char *);
int ntp_1x_timestamp_host_scan_interrupted (struct arglist *, char *);

int ntp_1x_timestamp_scan_starts (struct arglist *);
int ntp_1x_timestamp_scan_ends (struct arglist *);
int ntp_1x_send_dependencies (struct arglist *);
#endif
