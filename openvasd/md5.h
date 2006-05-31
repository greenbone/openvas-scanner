/* OpenVAS
* $Id$
* Description: headerfile for md5.c.
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


#ifndef NESSUSD_MD5_H
#define NESSUSD_MD5_H

#define md5_ctx void

md5_ctx * md5init();
void md5free(md5_ctx *); 
void md5update(md5_ctx *, char *, int );
char * md5final(md5_ctx *);

char * md5sum(char*, int);


#ifndef HAVE_SSL
char * rsaMD5(char*, int, u_char*);
#define MD5(x,y,z) rsaMD5(x,y,z)
#endif

#endif
