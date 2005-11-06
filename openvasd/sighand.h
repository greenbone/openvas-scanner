/* Nessus
 * Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _NESSUSD_SIGHAND_H
#define _NESSUSD_SIGHAND_H

extern void (*nessus_signal(int signum, void (*handler)(int)))(int);
extern void sighand_pipe();
extern void sighand_chld();
extern void sighand_alarm();
extern void sighand_alarm_plugin();
extern void sighand_term();
extern void sighand_int();
extern void sighand_kill();
extern void sighand_segv();
extern void sighand_sigusr1();
extern void sighand_io();
extern void sighandler(int sign);

extern void let_em_die (int pid);
extern void make_em_die (int sig);
#endif
