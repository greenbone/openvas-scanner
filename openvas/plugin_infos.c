/* Nessus
 * Copyright (C) 1998,1999,2000 Renaud Deraison
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
 *
 */
 

#include <includes.h>

#ifdef USE_GTK 
#include "gtk-compat.h"
#include <gtk/gtk.h>

#include "xstuff.h"
#include "globals.h"


static void
show_deps(foo, name)
 GtkWidget * foo;
 char * name;
{
 GtkWidget * window;
 GtkWidget * w;
 GtkWidget * box;
 struct arglist * deps;
 char * lbl = emalloc(strlen(name) + 255);
 int label_size = 1024;
 char * label;
 sprintf(lbl, "Dependencies of '%s'", name);

 window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_window_set_title(GTK_WINDOW(window), lbl);

 
 gtk_container_border_width(GTK_CONTAINER(window), 10);
 gtk_signal_connect(GTK_OBJECT(window), "destroy", 
                GTK_SIGNAL_FUNC(close_window), window);
 
 box = gtk_vbox_new(FALSE, 5);
 gtk_container_add(GTK_CONTAINER(window), box);
 gtk_widget_show(box);
 
 w = gtk_label_new(lbl);
 efree(&lbl);
 gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 5);
 gtk_widget_show(w);
 
 w = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 5);
 gtk_widget_show(w);

 
 deps = arg_get_value(Dependencies, name);
 if(!deps)
  {
   return; /* XXX */
  } 
 label = emalloc(label_size);
 
 while(deps->next)
 {
 struct arglist * p = arg_get_value(Plugins, deps->name);
 
 if(p == NULL) 
 	p = arg_get_value(Scanners, deps->name);
 if(p)
 {
  char * family = arg_get_value(p, "FAMILY");
  if(strlen(deps->name) + strlen(family) + 255 > label_size)
  { 
   label_size *= 2;
   label = erealloc(label, label_size);
  }
  strncpy(label, deps->name, label_size);
  strncat(label, " (", label_size);
  strncat(label, family, label_size);
  strncat(label, "), currently ", label_size);
  if(arg_get_value(p, "ENABLED"))
  	strncat(label, "enabled", label_size);
  else
  	strncat(label, "disabled", label_size);
 }
 else strncpy(label, deps->name, label_size);
 w = gtk_label_new(label);
 gtk_box_pack_start(GTK_BOX(box), w,   TRUE, TRUE, 2);
 gtk_widget_show(w);
 deps = deps->next;
 }
 
 efree(&label);
 w = gtk_button_new_with_label("Close");
 gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 3);
 gtk_signal_connect(GTK_OBJECT(w), "clicked",GTK_SIGNAL_FUNC(close_window), window);
 gtk_widget_show(w);


 gtk_widget_show(window);
}

static void 
do_set_timeout(b, ctrls)
 GtkWidget* b;
 struct arglist * ctrls;
{ 
 struct arglist * serv_prefs = arg_get_value(Prefs, "SERVER_PREFS");
 GtkWidget * w      = arg_get_value(ctrls, "ENTRY");
 GtkWidget * window = arg_get_value(ctrls, "WINDOW");
 char * to;
 int id;
 char * pref;
 int type;
 
 id  = (int)arg_get_value(ctrls, "ID");
 
 to = (char*)gtk_entry_get_text(GTK_ENTRY(w));
 pref = emalloc(40);
 
 sprintf(pref, "timeout.%d", id);
 if((type = arg_get_type(serv_prefs, pref)) >= 0)
 {
  char * old = arg_get_value(serv_prefs, pref);
  if(type == ARG_STRING)efree(&old);
  arg_set_type(serv_prefs, pref, ARG_STRING);
  arg_set_value(serv_prefs, pref, sizeof(int), estrdup(to));
 }
 else
  arg_add_value(serv_prefs, pref, ARG_STRING, sizeof(int), estrdup(to));
  
  close_window(NULL, window);
}



static struct arglist * 
set_timeout_build_window(id, cur_to, def_to)
 int id;
 char* cur_to;
 int def_to;
{
 GtkWidget * window;
 GtkWidget * w;
 GtkWidget * box, * hbox;
 struct arglist * ctrls = emalloc(sizeof(*ctrls));
 

 window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_window_set_title(GTK_WINDOW(window), "Set plugin timeout...");
 gtk_container_border_width(GTK_CONTAINER(window), 10);
 gtk_signal_connect(GTK_OBJECT(window), "destroy", 
                GTK_SIGNAL_FUNC(close_window), window);
 
 box = gtk_vbox_new(FALSE, 5);
 gtk_container_add(GTK_CONTAINER(window), box);
 gtk_widget_show(box);
 
 w = gtk_label_new("Set plugin timeout : ");
 gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 10);
 gtk_widget_show(w);
 
 w = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 10);
 gtk_widget_show(w);

 
 
 w = gtk_entry_new();
 gtk_box_pack_start(GTK_BOX(box),w, TRUE, TRUE, 10);
 gtk_widget_show(w);
 if(!def_to){
	gtk_entry_set_text(GTK_ENTRY(w), cur_to);
	}
	
 arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, window);
 arg_add_value(ctrls, "ENTRY", ARG_PTR, -1, w);
 arg_add_value(ctrls, "ID", ARG_INT, sizeof(int), (void*)id);
 
 
 hbox =  gtk_hbox_new(FALSE, 5);
 gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 10);
 gtk_widget_show(hbox);
 
 w = gtk_button_new_with_label("Cancel");
 gtk_box_pack_start(GTK_BOX(hbox), w, TRUE, TRUE, 3);
 gtk_signal_connect(GTK_OBJECT(w), "clicked",GTK_SIGNAL_FUNC(close_window), window);
 gtk_widget_show(w);


 w = gtk_button_new_with_label("Set new timeout");
 gtk_box_pack_start(GTK_BOX(hbox), w, TRUE, TRUE, 3);
 gtk_signal_connect(GTK_OBJECT(w), "clicked",GTK_SIGNAL_FUNC(do_set_timeout), ctrls);
 gtk_widget_show(w);
 
 
 
 gtk_widget_show(window);
 return ctrls;
}




static int
set_timeout(w, id)
 GtkWidget * w;
 int id;
{
 struct arglist * serv_prefs = arg_get_value(Prefs, "SERVER_PREFS");
 char * name = emalloc(40);
 int to_set = 1;
 char* timeout = NULL;
 
 sprintf(name, "timeout.%d", id);
 if(arg_get_type(serv_prefs,  name) == ARG_STRING)
  timeout = arg_get_value(Prefs, name);
 else
  to_set = 0;
    
    
 /*
  * Now, build a dialog
  */ 
  
 set_timeout_build_window(id, timeout, !to_set);
 return 0;
}





/*
 * plugin_info_window_setup 
 *
 * This function draws the window
 * which contains informations about a plugin
 */
void 
plugin_info_window_setup(res, pluginname)
 struct arglist* res;
 char * pluginname;
{
 GtkWidget * window;
 GtkWidget * box;
 GtkWidget * hbox;
 GtkWidget * subbox;
 GtkWidget * label;
 GtkWidget * text;
 GtkWidget * button;
 GtkWidget * separator;  
 GtkAdjustment * vadj;
 GtkWidget * vsb;
 GtkWidget * table;
 
 

 char * category;
 char buf[4096];
 struct arglist * plugin;
 char * txt;
 
 
 plugin = arg_get_value(res, pluginname);
 if(!plugin)
 {
#ifdef DEBUG
  fprintf(stderr, "Error ! Plugin selected not found ?!\n");
#endif
  return;
 }

 window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_VERSION > 10
 gtk_window_set_default_size(GTK_WINDOW(window), 400,500);
#else
 gtk_widget_set_usize(GTK_WIDGET(window), 400, 500);
#endif
 gtk_container_border_width(GTK_CONTAINER(window),10);
 gtk_window_set_title(GTK_WINDOW(window), pluginname);
 
 box = gtk_vbox_new(FALSE,3);
 gtk_container_add(GTK_CONTAINER(window), box);
 
 
 hbox = gtk_hbox_new(FALSE,10);
 gtk_box_pack_start(GTK_BOX(box), hbox, FALSE,FALSE,0);
 gtk_widget_show(hbox);
 
 
 
 separator = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), separator, FALSE, FALSE,0);
 gtk_widget_show(separator);
 
 
 sprintf(buf, "Family : %s", (char*)arg_get_value(plugin, "FAMILY"));
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 
 sprintf(buf, "Category : %s", (char*)arg_get_value(plugin, "CATEGORY"));
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 
 sprintf(buf, "Nessus Plugin ID : %d", (int)arg_get_value(plugin, "ID"));
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 
 txt = arg_get_value(plugin, "CVE_ID");
 if( txt != NULL && txt[0] != '\0' )
 {
 snprintf(buf, sizeof(buf), "CVE : %s", txt);
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 }
 
 txt = arg_get_value(plugin, "BUGTRAQ_ID");
 if( txt != NULL  && txt[0] != '\0' )
 {
 snprintf(buf, sizeof(buf), "Bugtraq ID : %s", txt);
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 }
 
 
 txt = arg_get_value(plugin, "XREFS");
 if( txt != NULL  && txt[0] != '\0' )
 {
 snprintf(buf, sizeof(buf), "Other references : %s", txt);
 label = gtk_label_new(buf);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 }
 
 
 
 
 label = gtk_label_new(arg_get_value(plugin, "VERSION"));
 gtk_box_pack_start(GTK_BOX(box), label, FALSE,FALSE,0);
 gtk_widget_show(label);
 
 
 
 
 separator = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), separator, FALSE, FALSE,0);
 gtk_widget_show(separator);
 
 label = gtk_label_new("What is shown if the attack is successful : ");
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 
 
 vadj = GTK_ADJUSTMENT (gtk_adjustment_new (0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
 vsb = gtk_vscrollbar_new (vadj);
 table = gtk_table_new(1,2,FALSE);
 gtk_box_pack_start(GTK_BOX(box), table, TRUE,TRUE,0);
 gtk_widget_show(table);
 
 text = gtk_text_new(NULL,vadj);
 gtk_table_attach (GTK_TABLE (table), vsb, 1, 2, 0, 1,
                    0, GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0);
 gtk_table_attach (GTK_TABLE (table), text, 0, 1, 0, 1,
                   GTK_EXPAND | GTK_SHRINK | GTK_FILL,
                    GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0); 
 gtk_container_border_width (GTK_CONTAINER (table), 2);  
 gtk_widget_show(vsb);
  
 gtk_widget_realize (text);  
 gtk_text_set_editable(GTK_TEXT(text), FALSE);
 gtk_text_set_word_wrap(GTK_TEXT(text), TRUE);
 if(arg_get_value(plugin, "DESCRIPTION"))
 gtk_text_insert(GTK_TEXT(text), NULL,NULL,NULL, arg_get_value(plugin, "DESCRIPTION"),
 	-1);
 gtk_widget_show(text);
 
 separator = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), separator, FALSE, FALSE,0);
 gtk_widget_show(separator);
 
 button = gtk_button_new_with_label("Set plugin timeout...");
 gtk_signal_connect(GTK_OBJECT(button), "clicked",GTK_SIGNAL_FUNC(set_timeout), arg_get_value(plugin, "ID"));
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 gtk_widget_show(button);
 
 button = gtk_button_new_with_label("Show dependencies");
 gtk_signal_connect(GTK_OBJECT(button), "clicked", GTK_SIGNAL_FUNC(show_deps), arg_get_value(plugin, "NAME"));
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 gtk_widget_show(button);
 if(!arg_get_value(Dependencies, pluginname))
 {
  gtk_widget_set_sensitive(button,FALSE);  
 }
 
 button = gtk_button_new_with_label("Close");
 gtk_signal_connect(GTK_OBJECT(button), "clicked",GTK_SIGNAL_FUNC(close_window), window);
 gtk_box_pack_end(GTK_BOX(box), button, FALSE, FALSE,5);
 gtk_widget_show(button);
 
 gtk_widget_realize(window);
 category = arg_get_value(plugin, "CATEGORY");

 
 
 subbox = gtk_vbox_new(FALSE,3);
 gtk_box_pack_start(GTK_BOX(hbox), subbox, FALSE,FALSE,0);
 gtk_widget_show(subbox);
 
 label = gtk_label_new(pluginname);
 gtk_box_pack_start(GTK_BOX(subbox), label, FALSE, FALSE,0);
 gtk_widget_show(label);
 
 label = gtk_label_new(arg_get_value(plugin, "COPYRIGHT"));
 gtk_box_pack_start(GTK_BOX(subbox), label, FALSE,FALSE,0);
 gtk_widget_show(label);
 
 
 gtk_widget_show(box);
 gtk_widget_show(window);
  
}
#endif
