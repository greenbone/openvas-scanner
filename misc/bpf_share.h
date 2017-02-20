/* OpenVAS-Libraries
 * $Id$
 * Description: Header file for module bpf_share.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_BPF_SHARE_H
#define OPENVAS_BPF_SHARE_H

#include <sys/types.h>

int bpf_open_live (char *, char *);
u_char *bpf_next (int, int *);
u_char *bpf_next_tv (int, int *, struct timeval *);
void bpf_close (int);
int bpf_datalink (int);

#endif
