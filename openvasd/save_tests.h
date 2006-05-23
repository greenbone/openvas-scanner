/* OpenVAS
* $Id$
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

#ifndef SAVE_TESTS_H__
#define SAVE_TESTS_H__

int save_tests_init(struct arglist *);
void save_tests_close(struct arglist*);

void save_tests_write_data(struct arglist *, char *);
void save_tests_host_done(struct arglist*, char*);

void save_tests_playback(struct arglist *, char *, harglst*);
int save_tests_setup_playback(struct arglist *, char *);

int save_tests_delete(struct arglist*, char *);
int save_tests_send_list(struct arglist*);

int save_tests_empty(struct arglist*);
int save_tests_delete_current(struct arglist*);
#endif
