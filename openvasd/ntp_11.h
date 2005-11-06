/* Nessus
 * Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _NESSUSD_NTP_11_H
#define _NESSUSD_NTP_11_H

#define NTP_STOP_WHOLE_TEST 2

int ntp_11_parse_input(struct arglist *, char *);
void ntp_11_show_end(struct arglist *, char *, int);



int ntp_1x_timestamp_host_scan_starts(struct arglist*, char*);
int ntp_1x_timestamp_host_scan_ends(struct arglist*, char*);
int ntp_1x_timestamp_host_scan_interrupted(struct arglist*, char*);

int ntp_1x_timestamp_scan_starts(struct arglist*);
int ntp_1x_timestamp_scan_ends(struct arglist*);
int ntp_1x_send_dependencies(struct arglist*);
#endif
