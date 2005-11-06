/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   

#ifndef _NESSUSC_NESSUS_H
#define _NESSUSC_NESSUS_H

/* The default port assigned to nessus by the iana is 1241, see
   http://www.isi.edu/in-notes/iana/assignments/port-numbers */
#ifdef _WIN32
#ifndef NESIANA_PORT
#define NESIANA_PORT 1241
#endif
#endif

#define DEFAULT_SERVER "localhost"
#define PROTO_NAME "< NTP/1.2 >< plugins_cve_id plugins_version plugins_bugtraq_id plugins_xrefs timestamps dependencies >\n"

#ifdef _CYGWIN_
extern char * NESSUS_RCFILE;
extern int init_directories;
#else
#define NESSUS_RCFILE     "~/.nessusrc"
#endif


char * connect_to_nessusd(char *, int, char *, char *);

#endif
