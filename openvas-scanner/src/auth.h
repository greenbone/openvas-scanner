/* OpenVAS
* $Id $
* Description: auth.c header file.
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


#ifndef _OPENVAS_AUTH_H
#define _OPENVAS_AUTH_H

#include "users.h"

extern char *per_user_pfx;
extern struct openvas_rules *auth_check_user (struct arglist *, char *, char *);
extern int user_lookup (const char *uname);

#endif
