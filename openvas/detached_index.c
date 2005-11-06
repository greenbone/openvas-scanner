/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
#include "gtk-compat.h"
#include <gtk/gtk.h>
#include "xstuff.h"
#ifdef ENABLE_SAVE_TESTS
#include "comm.h"

/*
 * Returns <1> if there is at least one 
 * detached session running at this time
 */
static int 
detached_running_sessions(sessions)
 harglst * sessions;
{
 hargwalk * hw = harg_walk_init(sessions);
 char * key = (char*)harg_walk_next(hw);
 harg_walk_stop(hw);
 return key ? 1:0;
}

static int
_stop_session(button, clist)
 GtkWidget * button, *clist;
{
  GList * selection;
 char * key;
 int data = -1;
 int n = 0;
 
 if(!clist)return 0;
 /*gtk_clist_freeze(GTK_CLIST(clist));*/
 if(!GTK_CLIST(clist)->rows)n++;
 

 selection = GTK_CLIST(clist)->selection;
 if(selection)
 {
  data = (int)selection->data;
  key = gtk_clist_get_row_data(GTK_CLIST(clist), data);
  comm_stop_detached_session(key);
  gtk_clist_remove(GTK_CLIST(clist), data);
 }
 /*   gtk_clist_thaw(GTK_CLIST(clist));
    gtk_widget_realize(clist);*/
 return 0;
}



static int
_close_window(button, ctrls)
 GtkWidget * button;
 struct arglist * ctrls;
{
 GtkWidget * window = arg_get_value(ctrls, "WINDOW");
 close_window(NULL, window);
 return 0;
}


static struct arglist *
detached_draw_window()
{
 GtkWidget * window, * vbox, * clist;
 GtkWidget * scrolled, * hbox, * button, * label;
 struct arglist * ret = emalloc(sizeof(*ret));
 char * titles[] = {"Session ID", "Targets"}; 
 
 window = gtk_window_new(WINDOW_DIALOG);
 gtk_window_set_title(GTK_WINDOW(window), "Detached sessions");
 gtk_widget_set_usize(GTK_WIDGET(window), 640, 480);
 gtk_container_border_width(GTK_CONTAINER(window), 10);
 
 arg_add_value(ret, "WINDOW", ARG_PTR, -1, window);
 gtk_signal_connect(GTK_OBJECT(window), "destroy", 
 		GTK_SIGNAL_FUNC(close_window), window);
		
 vbox = gtk_vbox_new(FALSE, 5);
 gtk_container_add(GTK_CONTAINER(window), vbox);
 gtk_widget_show(vbox);
 
 label = gtk_label_new("The following detached sessions are currently running : ");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 5);
 gtk_widget_show(label);
 
 scrolled = gtk_scrolled_window_new(NULL, NULL);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
				 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
				 
				 
 gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 10);
 gtk_widget_show(scrolled);
 
 clist = gtk_clist_new_with_titles(2, titles);
 #if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(scrolled),clist);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled), clist);
#endif
 gtk_widget_show(clist);
 arg_add_value(ret, "CLIST", ARG_PTR, -1, clist);
 gtk_widget_show(clist);
 
 hbox = gtk_hbox_new(FALSE, 10);
 gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 10);
 gtk_widget_show(hbox);
 
 button = gtk_button_new_with_label("Stop session(s)");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect(GTK_OBJECT(button), "clicked", 
 		    (GtkSignalFunc)_stop_session, 
		    (void*)clist);
 gtk_widget_show(button);
 
 button = gtk_button_new_with_label("Close window");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_widget_show(button);
 gtk_signal_connect(GTK_OBJECT(button), "clicked", 
 		    (GtkSignalFunc)_close_window, 
		    (void*)ret);
 
 gtk_widget_show(window);
 return ret;
}

static void
detached_fill_sessions(ctrls, sessions)
 struct arglist * ctrls;
 harglst * sessions;
{
 GtkWidget * clist = arg_get_value(ctrls, "CLIST"); 
 char**empty;
 int last, i;
 hargwalk * hw;
 char * key;
 
 empty = emalloc(2*sizeof(char*));
 empty[0] = strdup("");
 empty[1] = strdup("");
  
  
 gtk_clist_freeze(GTK_CLIST(clist));
 last = gtk_clist_append(GTK_CLIST(clist), empty);
 for(i=last;i>=0;i--)gtk_clist_remove(GTK_CLIST(clist), i);
 i = 0; 
  
 hw = harg_walk_init(sessions);
 while((key = (char*)harg_walk_next(hw)))
 {
   char * data[2];
   int row;
   data[0] = key;
   data[1] = harg_get_string(sessions, key);
   row =  gtk_clist_append(GTK_CLIST(clist), data);
   gtk_clist_set_row_data(GTK_CLIST(clist), row, key);
   i++; 
 }
  harg_walk_stop(hw);
#if GTK_VERSION > 10
  gtk_clist_sort(GTK_CLIST(clist));
  gtk_clist_set_column_width(GTK_CLIST(clist),
 			0,
			gtk_clist_optimal_column_width(GTK_CLIST(clist), 0)
			);
#endif
  gtk_clist_thaw(GTK_CLIST(clist));
  
  
}

void detached_show_window(prefs)
 struct arglist * prefs;
{
 struct arglist * ctrls;
 harglst * sessions = comm_get_detached_sessions();
 if(detached_running_sessions(sessions))
 {
 ctrls = detached_draw_window();
 detached_fill_sessions(ctrls, sessions);
 }
}
 
#endif
#endif

