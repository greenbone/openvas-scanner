/* OpenVAS
* $Id$
* Description: utils.c headerfile.
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


#ifndef _OPENVAS_UTILS_H
#define _OPENVAS_UTILS_H

#include <openvas/misc/arglists.h>   /* for struct arglist */

struct attack_atom
{
  char *name;
  int soc; /**< public socket  */
  int psoc;/**< private socket */
  struct attack_atom *next;
};
struct arglist *sort_plugins_by_type (struct arglist *);
int get_max_hosts_number (void);
int get_max_checks_number (void);

struct arglist *list2arglist (char *);
int common (struct arglist *, struct arglist *);

int process_alive (pid_t);
int data_left (int);

void wait_for_children1 (void);

int
is_scanner_only_pref (const char *);

void
send_printf (int, char *, ...) __attribute__ ((format (printf, 2, 3)));

#endif
