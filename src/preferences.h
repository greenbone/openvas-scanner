/* OpenVAS
* $Id$
* Description: preferences.c header.
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
*/


#ifndef __OPENVAS_PREFERENCES_H
#define __OPENVAS_PREFERENCES_H

const gchar * prefs_get (const gchar * key);
void prefs_set (const gchar *, const gchar *);

struct arglist * preferences_init (char *);
struct arglist * preferences_get (void);
void preferences_set (struct arglist *);
void preferences_dump (void);
int preferences_process (char *, struct arglist *);
int preferences_log_whole_attack (struct arglist *);
int preferences_optimize_test (struct arglist *);
int preferences_log_plugins_at_load (struct arglist *);
int preferences_plugins_timeout (struct arglist *);
int preferences_plugin_timeout (struct arglist *, char *);
int preferences_benice (struct arglist *);
int preferences_get_bool (struct arglist *, char *);
char *preferences_get_string (struct arglist *, char *);
int preferences_safe_checks_enabled (struct arglist *);

void preferences_reset_cache (void);
int preferences_nasl_no_signature_check (struct arglist *);
int preferences_drop_privileges (struct arglist *);

#endif
