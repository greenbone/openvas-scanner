/* OpenVAS
* $Id$
* Description: comm.c header.
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

#ifndef _OPENVAS_COMM_H
#define _OPENVAS_COMM_H

#include <openvas/misc/arglists.h>   /* for struct arglist */

int comm_init (int);
int comm_loading (int);
void comm_terminate (struct arglist *);
void comm_send_pluginlist (struct arglist *);
void comm_send_preferences (struct arglist *);
void comm_send_rules (struct arglist *);
void comm_wait_order (struct arglist *);
void comm_setup_plugins (struct arglist *, char *);
void client_handler ();
void comm_send_nvt_info (struct arglist *);
void plugin_send_infos (struct arglist *, char *);

#endif
