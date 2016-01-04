/* OpenVAS
* $Id$
* Description: plugs_req.c header.
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


#ifndef PLUGINS_REQUIREMENTS_H__
#define PLUGINS_REQUIREMENTS_H__

#include <openvas/base/kb.h>         /* for struct kb_item */
#include <openvas/misc/arglists.h>   /* for struct arglist */

char *requirements_plugin (kb_t, struct scheduler_plugin *);

int mandatory_requirements_met (kb_t, struct scheduler_plugin *);

struct arglist *requirements_common_ports (struct scheduler_plugin *,
                                           struct scheduler_plugin *);

#endif
