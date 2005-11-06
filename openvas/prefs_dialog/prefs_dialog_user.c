/* Nessus
 * Copyright (C) 1998, 1999, 2000 Renaud Deraison
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
#include <gdk/gdk.h>
#include "../xstuff.h"
#include "../preferences.h"
#include "../password_dialog.h"
#include "globals.h"
#include "error_dialog.h"
static int add_rule_callback(GtkWidget *, struct arglist *);
static void sigh_button_event(GtkWidget *, GdkEventButton *, struct arglist *);




 
struct arglist * prefs_dialog_user(prefs)
 struct arglist * prefs;
{
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 GtkWidget * frame;
 GtkWidget * table;
 GtkWidget * label;
 GtkWidget * button;
 GtkWidget * entry;
 GtkWidget * list;
 GtkWidget * s_window;
 /*ENABLE_CRYPTO_LAYER*/
 frame = gtk_frame_new("User");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 gtk_widget_show(frame);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
 table = gtk_table_new(3,7,FALSE);
 gtk_table_set_row_spacings(GTK_TABLE(table), 15);
 gtk_table_set_col_spacing(GTK_TABLE(table), 1, 10);
 gtk_container_add(GTK_CONTAINER(frame), table);
 gtk_container_border_width(GTK_CONTAINER(table), 10);
 gtk_widget_show(table);
 /*ENABLE_CRYPTO_LAYER*/
 label = gtk_label_new("Rules : ");
 gtk_table_attach(GTK_TABLE(table), label, 0,1,4,5, GTK_FILL | GTK_EXPAND, 0,0,0);
 gtk_widget_show(label);
 entry = gtk_entry_new();
 gtk_table_attach(GTK_TABLE(table), entry, 1,2,4,5, GTK_FILL | GTK_EXPAND, 0,0,0);
 gtk_widget_show(entry);
 arg_add_value(ctrls, "RULE", ARG_PTR, -1, entry);
 
 button = gtk_button_new_with_label("Add rule");
 gtk_table_attach(GTK_TABLE(table), button, 2,3,4,5, 0, 0, 0,0);
 gtk_signal_connect(GTK_OBJECT(button), "clicked",
 	GTK_SIGNAL_FUNC(add_rule_callback), ctrls);
 gtk_widget_show(button);

 
 s_window = gtk_scrolled_window_new(NULL, NULL);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s_window),
                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
 gtk_table_attach_defaults(GTK_TABLE(table), s_window, 0,3,5,7);
 gtk_widget_show(s_window);
 list = gtk_list_new();
 gtk_signal_connect(GTK_OBJECT(list),                           
                       "button_release_event",                      
                       GTK_SIGNAL_FUNC(sigh_button_event),
                       ctrls);   
 gtk_table_set_row_spacing(GTK_TABLE(table), 1, 10);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(s_window), list);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(s_window), list);
#endif
 gtk_widget_show(list);
 arg_add_value(ctrls, "RULES", ARG_PTR, -1, list);
 arg_add_value(ctrls, "PREFERENCES", ARG_ARGLIST, -1, prefs);
 return(ctrls);
}
 
 
static void sigh_button_event(w, event, ctrls)
 GtkWidget * w;
 GdkEventButton * event;
 struct arglist * ctrls;
{
  if (event->type==GDK_BUTTON_RELEASE)
  {
   GList * dlist;
   struct arglist * p = arg_get_value(ctrls, "PREFERENCES");
   struct arglist * r = arg_get_value(p, "RULES");
   dlist = GTK_LIST(w)->selection;
   if(dlist)while(dlist)
   {
    char * name = gtk_object_get_data(GTK_OBJECT(dlist->data), "rule");
    gtk_widget_hide(dlist->data);
    if(name)arg_set_value(r, name, 0, "");
    else fprintf(stderr, "Warning: could not actually delete the selected rule");
    dlist = dlist->next;
   }
  }
}


static int add_rule_callback(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{ 
 struct arglist * p = arg_get_value(ctrls, "PREFERENCES");
 int num = 1;
 GtkWidget * text;
 GtkWidget * list, * box, *label, * item;
 GList * dlist = NULL;
 char * rule, *z;
 struct arglist * t;
 char * name;
 
 p = arg_get_value(p, "RULES");
 list = arg_get_value(ctrls, "RULES");
 text = arg_get_value(ctrls, "RULE");
 t = p;
 while(t && t->next){num++;t=t->next;}
 
 if(text)
 {
  z = (char*)gtk_entry_get_text(GTK_ENTRY(text));
  rule = emalloc(strlen(z)+1);
  strncpy(rule, z, strlen(z));
 
  name = emalloc(10);
  sprintf(name, "%d", num);
  arg_add_value(p, name, ARG_STRING, strlen(rule), rule);
  item = gtk_list_item_new();
  gtk_object_set_data(GTK_OBJECT(item), "rule", name);
  box = gtk_hbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(item), box);
  gtk_widget_show(box);
  label = gtk_label_new(rule);
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
  dlist = g_list_append(dlist, item);
  gtk_widget_show(item);
  gtk_list_append_items(GTK_LIST(list), dlist);
  gtk_entry_set_text(GTK_ENTRY(text), "");
  }
  return(0);
}
#endif
