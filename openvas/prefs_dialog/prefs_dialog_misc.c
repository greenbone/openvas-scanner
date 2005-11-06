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
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 */

#include <includes.h>

#ifdef USE_GTK
#include <gtk/gtk.h>
#include "../xstuff.h"
#include "../preferences.h"
#include "globals.h"


struct arglist * prefs_dialog_misc()
{
 GtkWidget * frame;
 GtkWidget * vbox;
 GtkWidget * hbox;
 GtkWidget * max_threads;
 GtkWidget * remember_plugin_set;
 GtkWidget * label;
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 
 frame = gtk_frame_new("Misc.");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 gtk_widget_show(frame);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
 vbox = gtk_vbox_new(TRUE, 10);
 gtk_container_add(GTK_CONTAINER(frame), vbox);
 gtk_container_border_width(GTK_CONTAINER(vbox), 10);
 gtk_widget_show(vbox);
 
 hbox  = gtk_hbox_new(TRUE, 10);
 gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
 gtk_widget_show(hbox);
 
 label = gtk_label_new("Max threads : ");
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 max_threads = gtk_entry_new();
 gtk_box_pack_start(GTK_BOX(hbox), max_threads, FALSE, FALSE, 0);
 gtk_widget_show(max_threads);
 arg_add_value(ctrls, "MAX_THREADS", ARG_PTR, -1, max_threads);
 
 remember_plugin_set = gtk_check_button_new_with_label("Remember the set of plugins");
 gtk_box_pack_start(GTK_BOX(vbox), remember_plugin_set, FALSE, FALSE, 0);
 gtk_widget_show(remember_plugin_set);
 arg_add_value(ctrls, "REMEMBER_PLUGIN_SET", ARG_PTR, -1, remember_plugin_set);
 return(ctrls);
}
#endif
