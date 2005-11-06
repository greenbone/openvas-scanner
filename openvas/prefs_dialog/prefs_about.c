/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
 *
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
#include <corevers.h>
#include "../xstuff.h"
#include "../xpm/nessus.xpm"
#include "globals.h"
struct arglist * 
prefs_dialog_about(window)
 GtkWidget* window;
{
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 GtkWidget * frame;
 GtkWidget * vbox;
 GtkWidget * pixmapwid;
 GdkPixmap * pixmap;
 GdkBitmap * mask;
 GtkStyle *style = NULL;
 GtkWidget * label;
 GtkWidget * table;
 GtkWidget * hr;
 
 frame = gtk_frame_new("Credits");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 gtk_widget_show(frame);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
 vbox = gtk_vbox_new(FALSE, FALSE);
 gtk_container_add(GTK_CONTAINER(frame), vbox);
 gtk_widget_show(vbox);
 
 
 if(F_show_pixmaps)
 {
 style = gtk_widget_get_style(frame);
 pixmap = gdk_pixmap_create_from_xpm_d(window->window, &mask,
 				      &style->bg[GTK_STATE_NORMAL],
				      (gchar **)nessus_xpm);
 pixmapwid = gtk_pixmap_new(pixmap, mask);
 gtk_box_pack_start(GTK_BOX(vbox), pixmapwid, FALSE, FALSE, 10);
 gtk_widget_show(pixmapwid);

 hr = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(vbox), hr, FALSE, FALSE, 10);
 gtk_widget_show(hr);
 }

 label = gtk_label_new("Nessus "NESSUS_FULL_VERSION"\nCopyright (C) 1998 - 2004 : ");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 10);
 gtk_widget_show(label);
 
 table = gtk_table_new(4,2, FALSE);
 gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, 10);
 gtk_widget_show(table);
 
 label = gtk_label_new("Author : ");
 gtk_table_attach(GTK_TABLE(table), label, 0,1,0,1, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
 label = gtk_label_new("Renaud Deraison");
 gtk_table_attach(GTK_TABLE(table), label,1,2,0,1, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
 label = gtk_label_new("SSL Support : ");
 gtk_table_attach(GTK_TABLE(table), label, 0,1,1,2, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
 label = gtk_label_new("Michel Arboi");
 gtk_table_attach(GTK_TABLE(table), label,1,2,1,2, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
  label = gtk_label_new("Pie/Charts library : ");
 gtk_table_attach(GTK_TABLE(table), label, 0,1,2,3, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
 label = gtk_label_new("Bruce Verderaime");
 gtk_table_attach(GTK_TABLE(table), label,1,2,2,3, GTK_FILL|GTK_EXPAND,1,1,1);
 gtk_widget_show(label);
 
 
 
 label = gtk_label_new("Project site : http://www.nessus.org");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 10);
 gtk_widget_show(label);
 
 label = gtk_label_new("Mailing list : http://list.nessus.org");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 10);
 gtk_widget_show(label);
 return(ctrls);
}
#endif
