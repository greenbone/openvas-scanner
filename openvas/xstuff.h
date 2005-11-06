/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   
 
#ifndef _NESSUSC_XSTUFF_H
#define _NESSUSC_XSTUFF_H

int init_display(int *argc, char *** argv);
void close_display();
int close_window(GtkWidget * , GtkWidget * );
int delete_event(GtkWidget * nul, void * data);
GtkWidget *make_pixmap(GtkWidget *, GdkColor *, char **);
#endif
