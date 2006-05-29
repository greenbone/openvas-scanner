/* OpenVAS
* $Id $
* Description: log.c header.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Initial work)
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



#ifndef _NESSUSD_LOG_H
#define _NESSUSD_LOG_H

void log_init(const char *);
void log_close(void);
#ifdef __GNUC__
void log_write(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#else
void log_write(const char *, ...);
#endif


#endif
