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
#include "prefs_dialog.h"
#include "../monitor_dialog.h"
#include "../error_dialog.h"
#include "../read_target_file.h"
#include "globals.h"
#include "../comm.h"


static void
save_session_cb(w, ctrls)
 GtkWidget* w;
 struct arglist *ctrls;
{
 GtkWidget * wg = arg_get_value(ctrls, "SAVE_EMPTY_SESSIONS");
 gtk_widget_set_sensitive(wg, GTK_TOGGLE_BUTTON(w) -> active);   
}

static void
delete_session_cb(nul, clist)
 GtkWidget* nul, *clist;
{
 GList * selection;
 char * key;
 int data = -1;
 int n = 0;
 
 if(!clist)return;
 /*gtk_clist_freeze(GTK_CLIST(clist));*/
 if(!GTK_CLIST(clist)->rows)n++;
 

 selection = GTK_CLIST(clist)->selection;
 if(selection)
 {
  data = (int)selection->data;
  key = gtk_clist_get_row_data(GTK_CLIST(clist), data);
  comm_delete_session(key);
  gtk_clist_remove(GTK_CLIST(clist), data);
  /*selection = selection->next;*/
 }
 /*   gtk_clist_thaw(GTK_CLIST(clist));
    gtk_widget_realize(clist);*/
}



static void
restore_session_cb(nul, clist)
 GtkWidget * nul, * clist;
{
 GList * selection;
 char * key;
 struct arglist * prefs;
 struct arglist * serv;
 struct arglist * t;
 char expansion[30];
 char * s;
 char * hostname;
 GtkWidget * gtkw;
 struct arglist * ctrls = MainDialog; 
  
 if(!clist)
 {
  show_error("There is no session to restore !");
  return;
 }
 selection = GTK_CLIST(clist)->selection;
 if(!selection)
 {
  show_error("You must select a session to restore !");
  return;
 }
 if(selection->next)
 {
  show_error("Can only restore one session at a time !");
  return;
 }
   
  key = gtk_clist_get_row_data(GTK_CLIST(clist), (int)selection->data); 
  bzero(expansion, 30);
  prefs = arg_get_value(ctrls, "PREFERENCES");
  serv = arg_get_value(prefs, "SERVER_PREFS");
  if(!serv)
  {
   serv = emalloc(sizeof(struct arglist));
   arg_add_value(prefs, "SERVER_PREFS", ARG_ARGLIST, -1, serv);
  }
  
 /*
  * Host expansion
  */
  t = arg_get_value(ctrls, "TARGET");
  gtkw = arg_get_value(t, "DNS_EXPAND");
  if(GTK_TOGGLE_BUTTON(gtkw)->active)
   	strcat(expansion, "dns;");
   
   strcat(expansion, "ip;");    
   
   if(!strlen(expansion))strncpy(expansion, "none;", 5);
   expansion[strlen(expansion)-1]=0;
   
   s = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(t, "TARGET")));
   hostname = target_translate(s); /* if the target is a file, then
   				      translate it */
   
   s = emalloc(strlen(expansion)+1);
   strncpy(s, expansion, strlen(expansion));
   
   if(arg_get_value(serv, "host_expansion"))
    arg_set_value(serv, "host_expansion", strlen(s), s);
   else
    arg_add_value(serv, "host_expansion", ARG_STRING, strlen(s), s);
    

 
  /*
   * Plugins preferences
   */
  {
   struct arglist * plugs[2];
   int i;
   
   plugs[0] = Plugins;
   plugs[1] = Scanners;
   
   for(i=0;i<2;i++)
   {
    struct arglist  * plugins = plugs[i];
    
    while(plugins && plugins->next)
    {
     struct arglist * pref;
     char * type;
     char * value;
    
     if((pref = arg_get_value(plugins->value, "plugin_prefs")))
      while(pref && pref->next)
      {
       if((type = (char*)arg_get_value(pref->value, "type")))
       {
        if(!strcmp(type, PREF_ENTRY))
         {
	  GtkWidget * entry = arg_get_value(pref->value, "ENTRY");
	  if(entry)
	  {
	  value = (char*)gtk_entry_get_text(GTK_ENTRY(entry));			      
	  arg_set_value(pref->value, "value", strlen(value), 
	 	       estrdup(value));
	  }
	 }
	 else if(!strcmp(type, PREF_CHECKBOX))
	 {
	  GtkWidget * button = arg_get_value(pref->value, "CHECKBOX");
	
  	  if(button)
	  {
	   char * value = GTK_TOGGLE_BUTTON(button)->active ? "yes":"no";
	   arg_set_value(pref->value, "value", strlen(value),
	 		estrdup(value));		
	  }
	 }
       else if(!strcmp(type, PREF_RADIO))
       {
        GSList * list = arg_get_value(pref->value, "RADIOBUTTONS");
        char * value = NULL;
       
        if(list)while(list && !value)
        {
          GtkWidget * button = list->data;
	  if(GTK_TOGGLE_BUTTON(button)->active)
	   value = (char*)gtk_object_get_data(GTK_OBJECT(button), "name");
	  list = list->next;
        }
        else {
         char * t;
	 if(pref->value)
           value = arg_get_value(pref->value, "value");
 	 if(value&&(t = strchr(value, ';')))t[0] = 0;
	 }
       if(value)arg_set_value(pref->value, "value", strlen(value),
      		             estrdup(value));
        }		  
       }
      pref = pref->next;
      }	   				      
    plugins = plugins->next;
   }
  }
  }
      
   
  
  /*
   * Scan options
   */
  
   t = arg_get_value(ctrls, "SCAN_OPTIONS");
   gtkw = arg_get_value(t, "PING_HOSTS");
   s = emalloc(4);
   
   if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
   else strncpy(s, "no", 4);
   
   if(arg_get_value(serv, "ping_hosts"))
    arg_set_value(serv, "ping_hosts", strlen(s), s);
   else
    arg_add_value(serv, "ping_hosts", ARG_STRING, strlen(s), s);
    
    
   gtkw = arg_get_value(t, "REVERSE_LOOKUP");
   s = emalloc(4);
   if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
   else strncpy(s, "no", 4);
   
   if(arg_get_value(serv, "reverse_lookup"))
    arg_set_value(serv, "reverse_lookup", strlen(s), s);
   else
    arg_add_value(serv, "reverse_lookup", ARG_STRING, strlen(s), s);
     
   gtkw = arg_get_value(t, "OPTIMIZE_TEST");
   s = emalloc(4);
   if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
   else strncpy(s, "no", 4);
   
   if(arg_get_value(serv, "optimize_test"))
    arg_set_value(serv, "optimize_test", strlen(s), s);
   else
    arg_add_value(serv, "optimize_test", ARG_STRING, strlen(s), s);
  
  
 gtkw = arg_get_value(t, "PORT_RANGE");
 s = emalloc(strlen((char*)gtk_entry_get_text(GTK_ENTRY(gtkw)))+1);
 strncpy(s, gtk_entry_get_text(GTK_ENTRY(gtkw)), 
 	strlen(gtk_entry_get_text(GTK_ENTRY(gtkw))));
 
 if(arg_get_value(serv, "port_range"))
  arg_set_value(serv, "port_range", strlen(s), s);
 else
  arg_add_value(serv, "port_range", ARG_STRING, strlen(s), s);
         
 gtkw = arg_get_value(t, "MAX_HOSTS");
 
 s = emalloc(strlen(gtk_entry_get_text(GTK_ENTRY(gtkw)))+1);
  
 strncpy(s, gtk_entry_get_text(GTK_ENTRY(gtkw)), 
  	strlen(gtk_entry_get_text(GTK_ENTRY(gtkw))));
  
 if(arg_get_value(serv, "max_hosts"))
    arg_set_value(serv, "max_hosts", strlen(s), s);
  else
    arg_add_value(serv, "max_hosts", ARG_STRING, strlen(s), s);
    
 gtkw = arg_get_value(t, "MAX_CHECKS");
 
 s = emalloc(strlen(gtk_entry_get_text(GTK_ENTRY(gtkw)))+1);
  
 strncpy(s, gtk_entry_get_text(GTK_ENTRY(gtkw)), 
  	strlen(gtk_entry_get_text(GTK_ENTRY(gtkw))));
  
 if(arg_get_value(serv, "max_checks"))
    arg_set_value(serv, "max_checks", strlen(s), s);
  else
    arg_add_value(serv, "max_checks", ARG_STRING, strlen(s), s);      
 
 
 gtkw = arg_get_value(t, "CGI_PATH");
 s = (char*)gtk_entry_get_text(GTK_ENTRY(gtkw));
 s = emalloc(strlen(s)+1);
 strncpy(s, gtk_entry_get_text(GTK_ENTRY(gtkw)), 
  	strlen(gtk_entry_get_text(GTK_ENTRY(gtkw))));
        
  if(arg_get_value(serv, "cgi_path"))
    arg_set_value(serv, "cgi_path", strlen(s), s);
  else
    arg_add_value(serv, "cgi_path", ARG_STRING, strlen(s), s);   
  
  /*
   * Check for the errors
   */
  if(GlobalSocket < 0)
  {
   show_error("You must connect to a nessusd host before you start \n\
a scan in the 'nessusd' section");
   return;
  }
 
  
  /*
   * Set up the GUI for the attack, and start it !
   */
  close_window(nul, arg_get_value(ctrls, "WINDOW"));
  monitor_dialog_setup(key, 1);
}
 
void
prefs_dialog_target_free_list(ctrls)
 struct arglist *ctrls;
{
 GtkWidget * clist = arg_get_value(ctrls, "SESSIONS");
 int last;
 char*empty[] = {"", ""};
 int i;
 if(!clist)return;
 last = gtk_clist_append(GTK_CLIST(clist), empty);
 for(i=last;i>=0;i--)gtk_clist_remove(GTK_CLIST(clist), i);
}



 
void
prefs_dialog_target_fill_sessions(dialog, sessions)
 struct arglist * dialog;
 harglst * sessions;
{
  hargwalk * hw;
  char * key;
  int i = 0;
  GtkWidget * clist = arg_get_value(dialog, "SESSIONS");
  int last;
  char**empty;
  

  
  if(!clist)return;
  if(!sessions)return;
  
  empty = emalloc(2*sizeof(char*));
  empty[0] = estrdup("");
  empty[1] = estrdup("");
  

  
  hw = harg_walk_init(sessions);
  gtk_clist_freeze(GTK_CLIST(clist));
  last = gtk_clist_append(GTK_CLIST(clist), empty);
  for(i=last;i>=0;i--)gtk_clist_remove(GTK_CLIST(clist), i);
  i = 0;
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
#if GTK_VERSION > 10
  gtk_clist_sort(GTK_CLIST(clist));
  gtk_clist_set_column_width(GTK_CLIST(clist),
 			0,
			gtk_clist_optimal_column_width(GTK_CLIST(clist), 0)
			);
#endif
  gtk_clist_thaw(GTK_CLIST(clist));
}
struct arglist * prefs_dialog_target(preferences)
 struct arglist * preferences;
{
 GtkWidget * frame;
 GtkWidget * table;
 GtkWidget * label;
 GtkWidget * check_dns;
 GtkWidget * entry;
 GtkWidget * hbox;
 GtkWidget * button;
 struct arglist *  ctrls = emalloc(sizeof(struct arglist));
#ifdef ENABLE_SAVE_TESTS
 GtkWidget * clist;
 GtkWidget * scrolled;
 char * titles[] = {"Session", "Targets"};
#endif
 frame = gtk_frame_new("Target selection");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 gtk_widget_show(frame);
 
 arg_add_value(ctrls,"PREFERENCES", ARG_PTR, -1, frame);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
 
 table = gtk_table_new(7, 2, FALSE);
 gtk_container_add(GTK_CONTAINER(frame), table);
 gtk_container_border_width(GTK_CONTAINER(table), 10);
 gtk_table_set_row_spacings(GTK_TABLE(table), 5);
 gtk_widget_show(table);

 label = gtk_label_new("Target(s) : ");
 gtk_table_attach(GTK_TABLE(table), label, 0,1,0,1,GTK_FILL | GTK_EXPAND,0,0,0);
 gtk_widget_show(label);
 
 hbox = gtk_hbox_new(FALSE, 10);
 gtk_table_attach(GTK_TABLE(table), hbox, 1,2,0,1, GTK_FILL|GTK_EXPAND, 0,0,0);
 gtk_widget_show(hbox);
 
 entry = gtk_entry_new();
 gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
 gtk_widget_show(entry);
 
 button = gtk_button_new_with_label("Read file...");
 gtk_box_pack_end(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect /*_object*/ (GTK_OBJECT (button),
             "clicked", (GtkSignalFunc)target_file_select, NULL);

 gtk_widget_show(button);
 
 
 gtk_widget_show(entry);
 arg_add_value(ctrls, "TARGET", ARG_PTR, -1, entry);
 
 
 check_dns = gtk_check_button_new_with_label("Perform a DNS zone transfer");
 arg_add_value(ctrls, "DNS_EXPAND", ARG_PTR, -1, check_dns);
 gtk_table_attach(GTK_TABLE(table), check_dns, 1,2,1,2,GTK_FILL | GTK_EXPAND,0,0,0);
 
 gtk_widget_show(check_dns);
 
#ifdef ENABLE_SAVE_TESTS
 button = gtk_check_button_new_with_label("Save this session");
 arg_add_value(ctrls, "SAVE_THIS_SESSION", ARG_PTR, -1, button);
 gtk_table_attach(GTK_TABLE(table), button, 0,2, 2, 3, GTK_FILL|GTK_EXPAND,0,0,0);
 gtk_widget_show(button);
 gtk_signal_connect(GTK_OBJECT(button),
		     "clicked",
		     GTK_SIGNAL_FUNC(save_session_cb),
		     ctrls);
		     
		     
 
 hbox = gtk_hbox_new(TRUE, 10);
 gtk_table_attach(GTK_TABLE(table), hbox, 0,2,3,4, GTK_FILL|GTK_EXPAND,0,0,0);
 gtk_widget_show(hbox);
 
 button = gtk_check_button_new_with_label("Save empty sessions");
 arg_add_value(ctrls, "SAVE_EMPTY_SESSIONS", ARG_PTR, -1, button);
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 10);
 gtk_widget_show(button);
 
 label = gtk_label_new("Previous sessions : ");
 gtk_table_attach(GTK_TABLE(table), label, 0, 2, 4, 5,GTK_FILL|GTK_EXPAND,0,0,0);
 gtk_widget_show(label);
 
 scrolled = gtk_scrolled_window_new(NULL, NULL);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
				 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
				 
 gtk_table_attach(GTK_TABLE(table), scrolled, 0, 2, 5, 6,GTK_FILL|GTK_EXPAND,GTK_FILL|GTK_EXPAND,0,0);				 
 gtk_widget_show(scrolled);
 clist = gtk_clist_new_with_titles(2, titles);
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(scrolled),clist);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled), clist);
#endif
 gtk_widget_show(clist);

 gtk_clist_set_selection_mode(GTK_CLIST(clist), GTK_SELECTION_SINGLE);
#if GTK_VERSION > 10
 gtk_clist_set_reorderable(GTK_CLIST(clist), TRUE);
#endif
 arg_add_value(ctrls, "SESSIONS", ARG_PTR, -1, clist);
 
 hbox = gtk_hbox_new(TRUE, 5);
 gtk_table_attach(GTK_TABLE(table), hbox, 0, 2, 6, 7, GTK_FILL|GTK_EXPAND,0,0,0);
 gtk_widget_show(hbox);
 
 button = gtk_button_new_with_label("Restore session");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect(GTK_OBJECT(button), 
 		"clicked", (GtkSignalFunc)restore_session_cb, clist);
 gtk_widget_show(button);
 
 button = gtk_button_new_with_label("Delete session");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect /*_object*/ (GTK_OBJECT (button),
             "clicked", (GtkSignalFunc)delete_session_cb, clist);
 gtk_widget_show(button);
#endif
 
 return(ctrls);
}


#endif

