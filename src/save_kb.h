/* OpenVAS
* $Id$
* Description: save_kb.c header.
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


#ifndef SAVE_KB_H__
#define SAVE_KB_H__

#include <openvas/misc/arglists.h>   /* for struct arglist */

int save_kb_new (struct arglist *, char *);
void save_kb_close (struct arglist *, char *);

int save_kb_backup (struct arglist *, char *);
int save_kb_restore_backup (struct arglist *, char *);

int save_kb_write_int (struct arglist *, char *, char *, int);
int save_kb_write_str (struct arglist *, char *, char *, char *);

int save_kb_exists (struct arglist *, char *);
struct kb_item **save_kb_load_kb (struct arglist *, char *);

/*
 * Preferences set by the user
 */
int save_kb (struct arglist *);
int save_kb_pref_tested_hosts_only (struct arglist *);
int save_kb_pref_untested_hosts_only (struct arglist *);
int save_kb_pref_restore (struct arglist *);
long save_kb_max_age (struct arglist *);

#endif
