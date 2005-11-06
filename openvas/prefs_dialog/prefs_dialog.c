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
#include "../sighand.h"
#include "prefs_dialog_scan_opt.h"
#include "prefs_target.h"
#include "prefs_dialog_user.h"
#include "prefs_dialog_auth.h"
#include "prefs_help.h"
#include "prefs_plugins.h"
#include "prefs_dialog_plugins_prefs.h"
#include "prefs_dialog.h"
#include "prefs_about.h"


#ifdef ENABLE_SAVE_KB
#include "prefs_kb.h"
#endif


#include "../error_dialog.h"
#include "../monitor_dialog.h"
#include "../report.h"
#include "../read_target_file.h"
#include "globals.h"

static void prefs_dialog_set_tooltips(struct arglist *);
int prefs_dialog_ok(GtkWidget * , struct arglist *);
/*
 * prefs_dialog_setup
 * 
 * This function draws the preferences dialog of the Nessus
 * client
 *
 */
void 
prefs_dialog_setup(widget, preferences)
 GtkWidget * widget;
 struct arglist * preferences;
{
 GtkWidget * window;
 GtkWidget * notebook;
 GtkWidget * label;
 GtkWidget * frame;
 GtkWidget * box, * hbox;
 GtkWidget * ok, * loadrep, * cancel;
 struct arglist * prefs_scan;
 struct arglist * prefs_target;
 struct arglist * prefs_user;
 struct arglist * prefs_auth;
 struct arglist * prefs_plugins;
 struct arglist * prefs_plugins_prefs;
#ifdef ENABLE_SAVE_KB 
 struct arglist * prefs_kb;
#endif 
 struct arglist * prefs_about;
 struct arglist * ctrls = emalloc(sizeof(struct arglist));


 MainDialog = ctrls;


/*
 * We draw the window ....
 */
 window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_signal_connect(GTK_OBJECT(window), "delete_event",
                     (GtkSignalFunc)close_display,NULL);
                     
 gtk_container_border_width(GTK_CONTAINER(window), 10);
 gtk_window_set_title(GTK_WINDOW(window), "Nessus Setup");
 arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, window);
 arg_add_value(ctrls, "PREFERENCES", ARG_ARGLIST, -1, preferences);
 /*
  * We put a vbox in it...
  */
 box = gtk_vbox_new(FALSE, 10);
 gtk_container_add(GTK_CONTAINER(window), box);
 gtk_widget_show(box);
/* 
 * We set up the notebook
 */
 notebook = gtk_notebook_new();
 gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
 gtk_box_pack_start(GTK_BOX(box), notebook, TRUE, TRUE, 5);
 gtk_widget_show(notebook);
 arg_add_value(ctrls, "NOTEBOOK", ARG_PTR, -1, notebook);

/*
 * We set up the pages of our notebook
 */
 prefs_scan = prefs_dialog_scan_opt();
 prefs_target = prefs_dialog_target(preferences);
 prefs_user = prefs_dialog_user(preferences);
 prefs_auth = prefs_dialog_auth(window);
 prefs_plugins = prefs_dialog_plugins(window);
 prefs_plugins_prefs = prefs_dialog_plugins_prefs();
#ifdef ENABLE_SAVE_KB
 prefs_kb = prefs_dialog_kb(); 
#endif 
 prefs_about  = prefs_dialog_about(window);
 
 arg_add_value(ctrls, "SCAN_OPTIONS", ARG_ARGLIST, -1, prefs_scan);
 arg_add_value(ctrls, "TARGET", ARG_ARGLIST, -1, prefs_target);
 arg_add_value(prefs_target, "MAIN", ARG_ARGLIST, -1, ctrls);
 arg_add_value(ctrls, "USER", ARG_ARGLIST, -1, prefs_user);
 arg_add_value(ctrls, "AUTH", ARG_ARGLIST, -1, prefs_auth);
 arg_add_value(ctrls, "PLUGINS", ARG_ARGLIST, -1, prefs_plugins);
 arg_add_value(ctrls, "PLUGINS_PREFS", ARG_ARGLIST, -1, prefs_plugins_prefs);
#ifdef ENABLE_SAVE_KB
 arg_add_value(ctrls, "SAVE_KB", ARG_ARGLIST, -1, prefs_kb);
#endif 
 arg_add_value(ctrls, "ABOUT", ARG_ARGLIST, -1, prefs_about);
/*
 * and we append them to it
 */

 label = gtk_label_new("Nessusd host");
 frame = arg_get_value(prefs_auth, "FRAME");
 gtk_widget_show(frame);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
 

 label = gtk_label_new("Plugins");
 frame = arg_get_value(prefs_plugins, "FRAME");
 gtk_widget_show(frame);
 gtk_signal_connect(GTK_OBJECT(frame), "expose_event",
		     GTK_SIGNAL_FUNC(prefs_plugins_redraw),
		     prefs_plugins);
                                        
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
 
 label = gtk_label_new("Credentials");
 frame = arg_get_value(prefs_plugins_prefs, "FRAME_CREDENTIALS");
 gtk_widget_show(frame);
 gtk_signal_connect(GTK_OBJECT(frame), "expose_event", 
 		   GTK_SIGNAL_FUNC(prefs_plugins_prefs_redraw),
		   prefs_plugins_prefs);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
 
 	
 label = gtk_label_new("Scan Options");
 frame = arg_get_value(prefs_scan, "FRAME");
 gtk_widget_show(frame);
 gtk_signal_connect(GTK_OBJECT(frame), "expose_event",
		     GTK_SIGNAL_FUNC(prefs_scanner_redraw),
		     prefs_scan);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
 
 

 label = gtk_label_new("Target");
 frame = arg_get_value(prefs_target, "FRAME");
 gtk_widget_show(frame);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);

 label = gtk_label_new("User");
 frame = arg_get_value(prefs_user, "FRAME");
 gtk_widget_show(frame);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);


 label = gtk_label_new("Prefs.");
 frame = arg_get_value(prefs_plugins_prefs, "FRAME");
 gtk_widget_show(frame);
 gtk_signal_connect(GTK_OBJECT(frame), "expose_event", 
 		   GTK_SIGNAL_FUNC(prefs_plugins_prefs_redraw),
		   prefs_plugins_prefs);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);

#ifdef ENABLE_SAVE_KB
 label = gtk_label_new("KB");
 frame = arg_get_value(prefs_kb, "FRAME");
 gtk_widget_show(frame);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
#endif

 label = gtk_label_new("Credits");
 frame = arg_get_value(prefs_about, "FRAME");
 gtk_widget_show(frame);
 gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, label);
 
 
 hbox = gtk_hbox_new(TRUE, 10);
 gtk_box_pack_end(GTK_BOX(box), hbox, FALSE, FALSE, 0);
 gtk_widget_show(hbox);
 
 
 ok = gtk_button_new_with_label("Start the scan");
 gtk_signal_connect(GTK_OBJECT(ok), "clicked",
 	GTK_SIGNAL_FUNC(prefs_dialog_ok), ctrls);
 gtk_box_pack_start(GTK_BOX(hbox), ok,TRUE, TRUE, 0);
 gtk_widget_show(ok);
 
 loadrep = gtk_button_new_with_label("Load report");
 gtk_signal_connect(GTK_OBJECT(loadrep), "clicked",
 	GTK_SIGNAL_FUNC(open_report_selectfile), NULL );
 gtk_box_pack_start(GTK_BOX(hbox), loadrep,TRUE, TRUE, 0);
 gtk_widget_show(loadrep);

 cancel = gtk_button_new_with_label("Quit");
 gtk_signal_connect(GTK_OBJECT(cancel), "clicked",
 	GTK_SIGNAL_FUNC(close_display), NULL);
 gtk_box_pack_end(GTK_BOX(hbox), cancel,TRUE, TRUE, 0);
 gtk_widget_show(cancel);
 
 prefs_dialog_set_defaults(ctrls, preferences);
 prefs_dialog_set_tooltips(ctrls);
 gtk_widget_show(window);
 
}


void prefs_dialog_set_defaults(ctrls, preferences)
 struct arglist * ctrls;
 struct arglist * preferences;
{
#define EX_NONE 1
#define EX_DNS 2
#define EX_IP 4
#define EX_NFS 8
 
 struct arglist * t, * serv;
 char * v;
 int flag = 0;
 GtkWidget * gtkw;
 
 
 serv = arg_get_value(preferences, "SERVER_PREFS");
 if(!serv)return;
 
 
 t = arg_get_value(ctrls, "PLUGINS");
 gtkw = arg_get_value(t, "ENABLE_DEPS_AT_RUNTIME");
 if(gtkw)
 {
  v = arg_get_value(serv, "auto_enable_dependencies");
  if(arg_get_type(serv, "auto_enable_dependencies") == ARG_INT)
  {
      char * s = strdup(v ? "yes":"no");
      arg_set_type(serv, "auto_enable_dependencies", ARG_STRING);
      arg_set_value(serv, "auto_enable_dependencies", strlen(s), s);
      v = s;
  } 
  if(v && !strcmp(v, "yes"))
  	GTK_TOGGLE_BUTTON(gtkw)->active = TRUE;
  else
  	GTK_TOGGLE_BUTTON(gtkw)->active = FALSE;
 }
 gtkw = arg_get_value(t, "SILENT_DEPS");
 if(gtkw)
 {
  v = arg_get_value(serv, "silent_dependencies");
  if(arg_get_type(serv, "silent_dependencies") == ARG_INT)
  {
      char * s = strdup(v ? "yes":"no");
      arg_set_type(serv, "silent_dependencies", ARG_STRING);
      arg_set_value(serv, "silent_dependencies", strlen(s), s);
      v = s;
  } 
  if(v && !strcmp(v, "yes"))
  	GTK_TOGGLE_BUTTON(gtkw)->active = TRUE;
  else
  	GTK_TOGGLE_BUTTON(gtkw)->active = FALSE;
 }
 /*
  *  Host expansion options
  */
 t = arg_get_value(ctrls, "TARGET");
 v = arg_get_value(serv, "host_expansion");
 if(!v)
  flag |= EX_NONE;
 else
 {
 if(strstr(v, "dns"))flag = EX_DNS;
 if(strstr(v, "nfs"))flag |= EX_NFS;
 if(strstr(v, "none"))flag |= EX_NONE;
 if(strstr(v, "ip"))flag |= EX_IP;
 }
 
 if(!(flag & EX_NONE))
 {
  GtkWidget *w;
  w = arg_get_value(t, "DNS_EXPAND");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), (flag & EX_DNS));
 }

#ifdef ENABLE_SAVE_TESTS
  gtkw = arg_get_value(t, "SAVE_THIS_SESSION");
  v = arg_get_value(serv, "save_session");
  if(arg_get_type(serv, "save_session") == ARG_INT)
  {
      char * s = strdup(v ? "yes":"no");
      arg_set_type(serv, "save_session", ARG_STRING);
      arg_set_value(serv, "save_session", strlen(s), s);
      v = s;
  } 
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw),(v && !strcmp(v, "yes")));

 
  gtkw = arg_get_value(t, "SAVE_EMPTY_SESSIONS");
  v = arg_get_value(serv, "save_empty_sessions");
  if(arg_get_type(serv, "save_empty_sessions") == ARG_INT)
  {
      char * s = strdup(v ? "yes":"no");
      arg_set_type(serv, "save_empty_sessions", ARG_STRING);
      arg_set_value(serv, "save_empty_sessions", strlen(s), s);
      v = s;
  } 
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw),(v && !strcmp(v, "yes")));




#endif 
 
 /*
  * Scan options 
  */
  t = arg_get_value(ctrls, "SCAN_OPTIONS");
  gtkw = arg_get_value(t, "PING_HOSTS");
  v = arg_get_value(serv, "ping_hosts");
  if(arg_get_type(serv, "ping_hosts")==ARG_INT)
  {
   char * s = emalloc(4);
   if(v)strncpy(s, "yes", 3);
   else strncpy(s, "no", 2);
   
   arg_set_value(serv, "ping_hosts", strlen(s), s);
   arg_set_type(serv, "ping_hosts", ARG_STRING);
  }
  v = arg_get_value(serv, "ping_hosts");
  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  
  gtkw = arg_get_value(t, "REVERSE_LOOKUP");
  v = arg_get_value(serv, "reverse_lookup");
  if(arg_get_type(serv, "reverse_lookup")==ARG_INT)
  {
   char * s = emalloc(4);
   if(v)strncpy(s, "yes", 3);
   else strncpy(s, "no", 2);
   
   arg_set_value(serv, "reverse_lookup", strlen(s), s);
   arg_set_type(serv, "reverse_lookup", ARG_STRING);
  }
  v = arg_get_value(serv, "reverse_lookup");
  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  
  
  gtkw = arg_get_value(t, "OPTIMIZE_TEST");
  v = arg_get_value(serv, "optimize_test");
  if(arg_get_type(serv, "optimize_test")==ARG_INT)
  {
   char * s = emalloc(4);
   if(v)strncpy(s, "yes", 3);
   else strncpy(s, "no", 2);
   
   arg_set_value(serv, "optimize_test", strlen(s), s);
   arg_set_type(serv, "optimize_test", ARG_STRING);
  }
  v = arg_get_value(serv, "optimize_test");
  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  else gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 1);
 
 
  gtkw = arg_get_value(t, "SAFE_CHECKS");
  v = arg_get_value(serv, "safe_checks");
  if(arg_get_type(serv, "safe_checks")==ARG_INT)
  {
   char * s = emalloc(4);
   if(v)strncpy(s, "yes", 3);
   else strncpy(s, "no", 2);
   
   arg_set_value(serv, "safe_checks", strlen(s), s);
   arg_set_type(serv, "safe_checks", ARG_STRING);
  }
  
   v = arg_get_value(serv, "safe_checks");
  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  else gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 1);
  
  
  gtkw = arg_get_value(t, "USE_MAC_ADDR");
  v = arg_get_value(serv, "use_mac_addr");
  if(arg_get_type(serv, "use_mac_addr")==ARG_INT)
  {
   char * s = emalloc(4);
   if(v)strncpy(s, "yes", 3);
   else strncpy(s, "no", 2);
   
   arg_set_value(serv, "use_mac_addr", strlen(s), s);
   arg_set_type(serv, "use_mac_addr", ARG_STRING);
  }
  
  v = arg_get_value(serv, "use_mac_addr");
  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  else gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 0);
 
  
#if 0
#ifdef ENABLE_SAVE_KB

  /*
   * Detached scan and continuous scan are ALWAYS
   * disabled
   */
  gtkw = arg_get_value(t, "DETACHED_SCAN");
  v = arg_get_value(serv, "detached_scan");
  if(arg_get_type(serv, "detached_scan")==ARG_INT)
  {
   char * s = strdup("no");
   
   arg_set_value(serv, "detached_scan", strlen(s), s);
   arg_set_type(serv, "detached_scan", ARG_STRING);
  }
  
  v = arg_get_value(serv, "detached_scan");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 0);
  
  
  gtkw = arg_get_value(t, "EMAIL_ADDR");
  v = arg_get_value(serv, "detached_scan_email_address");
  
  if(arg_get_type(serv, "detached_scan_email_address") == ARG_INT)
   {
   char * s = strdup("");
   arg_set_type(serv, "detached_scan_email_address", ARG_STRING);
   arg_set_value(serv, "detached_scan_email_address", strlen(s), s);
   }
  else if(arg_get_type(serv, "detached_scan_email_address") < 0)
   arg_add_value(serv, "detached_scan_email_address", ARG_STRING, 0, strdup(""));
   
  gtk_entry_set_text(GTK_ENTRY(gtkw), 
  		arg_get_value(serv,"detached_scan_email_address"));
  
   
  gtkw = arg_get_value(t, "CONTINUOUS_SCAN");
  v = arg_get_value(serv, "continuous_scan");
  if(arg_get_type(serv, "continuous_scan")==ARG_INT)
  {
   char * s = strdup("no");
   
   arg_set_value(serv, "continuous_scan", strlen(s), s);
   arg_set_type(serv, "continuous_scan", ARG_STRING);
  }
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 0);
  

  v = arg_get_value(serv, "delay_between_scan_loops");
  if(v)
  {
   gtkw = arg_get_value(t, "DELAY");
   gtk_entry_set_text(GTK_ENTRY(gtkw), v);
  }
#endif  
#endif
 
 
  v = arg_get_value(serv, "port_range");
  if(v)
  {
   gtkw = arg_get_value(t, "PORT_RANGE");
   if(gtkw)gtk_entry_set_text(GTK_ENTRY(gtkw), v);
  }
 
  gtkw = arg_get_value(t, "UNSCANNED_CLOSED");
  v = arg_get_value(serv, "unscanned_closed");
  if(arg_get_type(serv, "unscanned_closed")==ARG_INT)
  {
   
   char * s;
   int v;
   v = (int)arg_get_value(serv, "unscanned_closed");
   if(v)
    s = strdup("yes");
   else
    s = strdup("no");
    
   arg_set_value(serv, "unscanned_closed", strlen(s), s);
   arg_set_type(serv, "unscanned_closed", ARG_STRING);
  }
  v = arg_get_value(serv, "unscanned_closed");

  if(v)gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), !strcmp(v, "yes"));
  else gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(gtkw), 0);
  
  
  
  gtkw = arg_get_value(t, "MAX_HOSTS");
  if(gtkw)
  {
   v = arg_get_value(serv, "max_hosts");
   if(v)gtk_entry_set_text(GTK_ENTRY(gtkw), v);
  }
  
  gtkw = arg_get_value(t, "MAX_CHECKS");
  if(gtkw)
  {
   v = arg_get_value(serv, "max_checks");
   if(v)gtk_entry_set_text(GTK_ENTRY(gtkw), v);
  }
   
   gtkw = arg_get_value(t, "CGI_PATH");
   if(gtkw)
   {
    v = arg_get_value(serv, "cgi_path");
    if(v)gtk_entry_set_text(GTK_ENTRY(gtkw), v);
   }
   /*
    * User
    */
    
    t = arg_get_value(ctrls, "USER");
 
    gtkw = arg_get_value(t, "RULES");
    if(gtkw)
    {
     GtkWidget * item;
     GtkWidget * label;
          
     GList * dlist = NULL;
     GList * oldlist = (void *)arg_get_value(t, "RULES_DLIST");
     struct arglist * rules = arg_get_value(preferences, "RULES");
     
     if(oldlist)gtk_list_remove_items(GTK_LIST(gtkw), oldlist);
 
     while(rules && rules->next)
     {
      GtkWidget * box;
      if(strlen(rules->value))
      {
       item = gtk_list_item_new();
       gtk_object_set_data(GTK_OBJECT(item), "rule", rules->name);
       box = gtk_hbox_new(FALSE, 0);
       gtk_container_add(GTK_CONTAINER(item), box);
       gtk_widget_show(box);
       label = gtk_label_new(rules->value);
       gtk_widget_show(label);
       gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
       dlist = g_list_append(dlist, item);
       rules = rules->next;
       gtk_widget_show(item);
       }
     }
     if(arg_get_value(t, "RULES_DLIST"))
      arg_set_value(t, "RULES_DLIST", -1, dlist);
     else
      arg_add_value(t, "RULES_DLIST", ARG_PTR, -1, dlist);
     gtk_list_append_items(GTK_LIST(gtkw), dlist);
    }
    
#ifdef ENABLE_SAVE_KB
   prefs_dialog_kb_set_prefs(arg_get_value(ctrls, "SAVE_KB"),
   			     preferences);
#endif    
}
  
  
static void prefs_dialog_set_tooltips(ctrls)
 struct arglist * ctrls;
{
 struct arglist * t;
 GtkTooltips * tooltips;
 GtkWidget * w;
 tooltips = gtk_tooltips_new();

 t = arg_get_value(ctrls, "PLUGINS");
 w = arg_get_value(t, "ENABLE_DEPS_AT_RUNTIME");
 gtk_tooltips_set_tip(tooltips, w, HLP_ENABLE_DEPS_AT_RUNTIME,"");
 
 w = arg_get_value(t, "SILENT_DEPS");
 gtk_tooltips_set_tip(tooltips, w, HLP_SILENT_DEPS,"");
 t = arg_get_value(ctrls, "AUTH") ;
#ifdef USE_AF_INET
 w = arg_get_value(t, "HOSTNAME");
 gtk_tooltips_set_tip(tooltips, w, HLP_AUTH_SERVER,"");
 w = arg_get_value(t, "PORT");
 gtk_tooltips_set_tip(tooltips, w, HLP_AUTH_PORT,"");
#endif
 /*ENABLE_CRYPTO_LAYER*/
 w = arg_get_value(t, "USERNAME");
 gtk_tooltips_set_tip(tooltips, w, HLP_LOGIN_USER,"");
 
 t = arg_get_value(ctrls, "TARGET");
 w = arg_get_value(t, "DNS_EXPAND");
 gtk_tooltips_set_tip(tooltips, w, HLP_HOST_EXPANSION_DNS,"");
 
 w = arg_get_value(t, "TARGET");
 gtk_tooltips_set_tip(tooltips, w, HLP_TARGET_PRIMARY_TARGET, "");
 
 
 t = arg_get_value(ctrls, "SCAN_OPTIONS");
 w = arg_get_value(t, "PING_HOSTS");
 gtk_tooltips_set_tip(tooltips, w, HLP_SCAN_OPT_PING,"");
 w = arg_get_value(t, "OPTIMIZE_TEST");
 gtk_tooltips_set_tip(tooltips, w, HLP_SCAN_OPT_OPTIMIZE, "");
 
 w = arg_get_value(t, "SAFE_CHECKS");
 gtk_tooltips_set_tip(tooltips, w, HLP_SCAN_OPT_SAFE_CHECKS, "");
 
 w = arg_get_value(t, "USE_MAC_ADDR");
 gtk_tooltips_set_tip(tooltips, w, HLP_SCAN_OPT_USE_MAC_ADDR, "");

 w = arg_get_value(t, "REVERSE_LOOKUP");
 gtk_tooltips_set_tip(tooltips, w, HLP_SCAN_OPT_REVERSE_LOOKUP, "");
 w = arg_get_value(t, "PORT_RANGE");
 gtk_tooltips_set_tip(tooltips, w,  HLP_SCAN_OPT_PORT_RANGE, "");
 w = arg_get_value(t, "UNSCANNED_CLOSED");
 gtk_tooltips_set_tip(tooltips, w, HLP_UNSCANNED_CLOSED, "");
 
 w = arg_get_value(t, "MAX_HOSTS");
 gtk_tooltips_set_tip(tooltips, w, HLP_MISC_MAX_HOSTS,"");
 w = arg_get_value(t, "MAX_CHECKS");
 gtk_tooltips_set_tip(tooltips, w, HLP_MISC_MAX_CHECKS, "");
 w = arg_get_value(t, "CGI_PATH");
 gtk_tooltips_set_tip(tooltips, w, HLP_CGI_PATH, "");
 t = arg_get_value(ctrls, "USER");
 gtk_tooltips_enable(tooltips);
}


int prefs_dialog_ok(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
  struct arglist * prefs;
  struct arglist * serv;
  struct arglist * t;
  char expansion[30];
  char * s, *e;
  char * hostname;
  GtkWidget * gtkw;
  
  
  bzero(expansion, 30);
  prefs = arg_get_value(ctrls, "PREFERENCES");
  serv = arg_get_value(prefs, "SERVER_PREFS");
  if(!serv)
  {
   serv = emalloc(sizeof(struct arglist));
   arg_add_value(prefs, "SERVER_PREFS", ARG_ARGLIST, -1, serv);
  }
  
  
 t = arg_get_value(ctrls, "PLUGINS");
 gtkw = arg_get_value(t, "ENABLE_DEPS_AT_RUNTIME");
 if(gtkw)
 {
   char * s;
   if(GTK_TOGGLE_BUTTON(gtkw)->active)s = estrdup("yes");
   else s = estrdup("no");
  
   if(arg_get_value(serv, "auto_enable_dependencies"))
   arg_set_value(serv, "auto_enable_dependencies", strlen(s), s);
  else
   arg_add_value(serv, "auto_enable_dependencies", ARG_STRING, strlen(s), s);
  }
 
 
 gtkw = arg_get_value(t, "SILENT_DEPS");
 if(gtkw)
 {
   char * s;
   if(GTK_TOGGLE_BUTTON(gtkw)->active)s = estrdup("yes");
   else s = estrdup("no");
  
   if(arg_get_value(serv, "silent_dependencies"))
   arg_set_value(serv, "silent_dependencies", strlen(s), s);
  else
   arg_add_value(serv, "silent_dependencies", ARG_STRING, strlen(s), s);
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
   
#ifdef ENABLE_SAVE_TESTS   
  gtkw = arg_get_value(t, "SAVE_THIS_SESSION");
  if(GTK_TOGGLE_BUTTON(gtkw) -> active)
  	s = strdup("yes");
  else
  	s = strdup("no");

  if(arg_get_value(serv, "save_session"))
   arg_set_value(serv, "save_session", strlen(s), s);
  else
   arg_add_value(serv, "save_session", ARG_STRING, strlen(s), s);
   
   
   gtkw = arg_get_value(t, "SAVE_EMPTY_SESSIONS");
  if(GTK_TOGGLE_BUTTON(gtkw) -> active)
  	s = strdup("yes");
  else
  	s = strdup("no");

  if(arg_get_value(serv, "save_empty_sessions"))
   arg_set_value(serv, "save_empty_sessions", strlen(s), s);
  else
   arg_add_value(serv, "save_empty_sessions", ARG_STRING, strlen(s), s);
   
    
#endif 
   
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
        if(!strcmp(type, PREF_ENTRY) ||
	   !strcmp(type, PREF_FILE) ||
	   !strcmp(type, PREF_PASSWORD))
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
    
    
   gtkw = arg_get_value(t, "SAFE_CHECKS");
   s = emalloc(4);
   if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
   else strncpy(s, "no", 4);
   
   if(arg_get_value(serv, "safe_checks"))
    arg_set_value(serv, "safe_checks", strlen(s), s);
   else
    arg_add_value(serv, "safe_checks", ARG_STRING, strlen(s), s);
    
    
   gtkw = arg_get_value(t, "USE_MAC_ADDR");
   s = emalloc(4);
   if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
   else strncpy(s, "no", 4);
   
   if(arg_get_value(serv, "use_mac_addr"))
    arg_set_value(serv, "use_mac_addr", strlen(s), s);
   else
    arg_add_value(serv, "use_mac_addr", ARG_STRING, strlen(s), s);  
  
  
  
#if 0 
#ifdef ENABLE_SAVE_KB
   gtkw = arg_get_value(t, "DETACHED_SCAN");
   if(GTK_TOGGLE_BUTTON(gtkw)->active){
   	 s = strdup("yes");
	 DetachedMode = 1;
	}
   else {
   	 s = strdup("no");
    	 DetachedMode = 0;
        }
   if(arg_get_value(serv, "detached_scan"))
    arg_set_value(serv, "detached_scan", strlen(s), s);
   else
    arg_add_value(serv, "detached_scan", ARG_STRING, strlen(s), s);  
  
   gtkw = arg_get_value(t, "EMAIL_ADDR");
   s = estrdup(gtk_entry_get_text(GTK_ENTRY(gtkw)));
   arg_set_value(serv, "detached_scan_email_address", strlen(s), s);
   
   
   
   gtkw = arg_get_value(t, "CONTINUOUS_SCAN");
  
   
   if(GTK_TOGGLE_BUTTON(gtkw)->active)s = strdup("yes");
   else s = strdup("no");
   
   if(arg_get_value(serv, "continuous_scan"))
    arg_set_value(serv, "continuous_scan", strlen(s), s);
   else
    arg_add_value(serv, "continuous_scan", ARG_STRING, strlen(s), s);  
   
   gtkw = arg_get_value(t, "DELAY");
   s = strdup(gtk_entry_get_text(GTK_ENTRY(gtkw)));
   if(arg_get_value(serv, "delay_between_scan_loops"))
    arg_set_value(serv, "delay_between_scan_loops", strlen(s), s);
   else
    arg_add_value(serv, "delay_between_scan_loops", ARG_STRING, strlen(s), s); 
    
#endif     
#endif
 gtkw = arg_get_value(t, "PORT_RANGE");
 s = emalloc(strlen(gtk_entry_get_text(GTK_ENTRY(gtkw)))+1);
 strncpy(s, gtk_entry_get_text(GTK_ENTRY(gtkw)), 
 	strlen(gtk_entry_get_text(GTK_ENTRY(gtkw))));
 
 if(arg_get_value(serv, "port_range"))
  arg_set_value(serv, "port_range", strlen(s), s);
 else
  arg_add_value(serv, "port_range", ARG_STRING, strlen(s), s);
         
	 
 gtkw = arg_get_value(t, "UNSCANNED_CLOSED");
 s = emalloc(4);
 if(GTK_TOGGLE_BUTTON(gtkw)->active)strncpy(s, "yes", 3);
 else strncpy(s, "no", 4);
   
 if(arg_get_value(serv, "unscanned_closed"))
    arg_set_value(serv, "unscanned_closed", strlen(s), s);
   else
    arg_add_value(serv, "unscanned_closed", ARG_STRING, strlen(s), s);
    
    	 
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
 s = estrdup((char*)gtk_entry_get_text(GTK_ENTRY(gtkw)));

        
  if(arg_get_value(serv, "cgi_path"))
    arg_set_value(serv, "cgi_path", strlen(s), s);
  else
    arg_add_value(serv, "cgi_path", ARG_STRING, strlen(s), s);   

#ifdef ENABLE_SAVE_KB
  t = arg_get_value(ctrls, "SAVE_KB");
  prefs_dialog_kb_get_prefs(t);
#endif

  
 /* 
  * User
  * We don't handle the rules here, since a special callback has been 
  * set up for this one...
  */
  
  
 t = arg_get_value(ctrls, "USER");
 e = NULL;
 
  /*
   * Check for the errors
   */
 
  if(GlobalSocket < 0)
  {
   show_error("You must connect to a nessusd host before you start \n\
a scan in the 'nessusd' section");
   return(0);
  }
  
  
  if( hostname == NULL || hostname[0] == '\0' )
  { 
   show_error("You must enter the name of the primary target\n\
to attack in the 'target' section");
   return(0);
  }
 

  
  /*
   * Set up the GUI for the attack, and start it !
   */
  close_window(w, arg_get_value(ctrls, "WINDOW"));
  monitor_dialog_setup(hostname, 0);
  
  return(0);
}
#endif
