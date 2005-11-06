
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
#include "../nessus.h"
#include "../auth.h"
#include "../error_dialog.h"
#include "../xpm/computer.xpm"
#include "../xpm/user.xpm"
#include "prefs_dialog.h"
#include "prefs_plugins.h"
#include "prefs_dialog_plugins_prefs.h"
#include "globals.h"
extern char * stored_pwd;

static char * get_username();
static int prefs_dialog_login_callback(GtkWidget* , struct arglist *);
static int prefs_dialog_logout_callback(GtkWidget* , struct arglist *);
struct arglist * prefs_dialog_auth();

#ifndef USE_AF_INET      
#undef ENABLE_CRYPTO_LAYER
#endif

/*
 * get_username : returns the name of the current user
 */
static char *
get_username
  (void)
{
  /*ENABLE_CRYPTO_LAYER*/
  char * user;
  struct passwd * pwd;
  /* Look up the user's name. */
  user = getenv ("USER");
  if (user)
    return user;

  user = getenv ("LOGNAME");
  if (user)
    return user;

  pwd = getpwuid (getuid ());
  if (pwd && pwd->pw_name)
    return pwd->pw_name;
  return "";
}

struct arglist * prefs_dialog_auth(window)
 GtkWidget * window;
{
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 GtkWidget * frame;
 GtkWidget * label;
 GtkWidget * button;
 GtkWidget * table;
 GtkStyle *style = NULL;
 GtkWidget * pixmapwid;
 GdkPixmap * pixmap;
 GdkBitmap * mask;
 GtkWidget * box;        
 GtkWidget * separator;
 GtkWidget * entry;
 char * default_server = arg_get_value(Prefs, "nessusd_host");
 char * default_user = arg_get_value(Prefs, "nessusd_user");
    
  /*
   * Set up the main frame
   */
   frame = gtk_frame_new("New session setup");
   gtk_container_border_width(GTK_CONTAINER(frame), 10);
   gtk_widget_show(frame);
   arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
  /*
   * Set up the table which will contain everything
   */
   /*ENABLE_CRYPTO_LAYER*/
  table = gtk_table_new(6, 2, TRUE);
  gtk_container_add(GTK_CONTAINER (frame), table);
  gtk_container_border_width(GTK_CONTAINER(table), 10);
  gtk_widget_show(table);

#ifdef USE_AF_INET
  entry = gtk_entry_new();
# ifdef DEFAULT_SERVER
  gtk_entry_set_text 
    (GTK_ENTRY(entry), default_server? default_server:DEFAULT_SERVER);
# endif /* DEFAULT_SERVER */
  arg_add_value(ctrls, "HOSTNAME", ARG_PTR, -1, entry);
  gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,0,1);
  gtk_widget_show(entry);
  
  box = gtk_hbox_new(FALSE,0);
  gtk_table_attach_defaults(GTK_TABLE(table), box, 0,1,1,2);
  gtk_widget_show(box);
  label = gtk_label_new("Port : ");
  gtk_box_pack_end(GTK_BOX(box), label, FALSE, FALSE,0);
  gtk_widget_show(label);
  
  entry = gtk_entry_new();
  {
   char tbuf[10];
   sprintf (tbuf, "%d", NESIANA_PORT);
   gtk_entry_set_text (GTK_ENTRY(entry), tbuf);
   arg_add_value(ctrls, "PORT", ARG_PTR, -1, entry);
  }
  gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,1,2);
  gtk_widget_show(entry);

  separator = gtk_hseparator_new();
  gtk_table_attach_defaults(GTK_TABLE(table), separator, 0,2,2,3);
  gtk_widget_show(separator);
#endif /* AF_INET */
  
  entry = gtk_entry_new();
  gtk_entry_set_text (GTK_ENTRY(entry), default_user?default_user:get_username ());
  
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,3,4);
  arg_add_value(ctrls, "USERNAME", ARG_PTR, -1, entry);
  gtk_widget_show(entry);
  
  box = gtk_hbox_new(FALSE,0);
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach_defaults(GTK_TABLE(table), box, 0,1,4,5);
  gtk_widget_show(box);
  
  /*ENABLE_CRYPTO_LAYER*/
  label = gtk_label_new("Password : ");
  gtk_box_pack_end(GTK_BOX(box), label, FALSE, FALSE,0);
  gtk_widget_show(label);
  
  entry = gtk_entry_new();
  gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,4,5);
  arg_add_value(ctrls, "PASSWORD", ARG_PTR, -1, entry);
  gtk_widget_show(entry);

  button = gtk_button_new_with_label("Log in");
  GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach(GTK_TABLE(table), button, 1,2,6,7,GTK_FILL | GTK_EXPAND,0,10,10);
  arg_add_value(ctrls, "BUTTON_LOG_IN", ARG_PTR, -1, button);
  gtk_signal_connect /*_object*/(GTK_OBJECT (button), "clicked",
 			   (GtkSignalFunc)prefs_dialog_login_callback,
 			   (void *)ctrls);

  gtk_widget_show(button);
  
  button = gtk_button_new_with_label(" Log out");
  GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach(GTK_TABLE(table), button, 1,2,7,8,GTK_FILL | GTK_EXPAND,0,10,10);
  arg_add_value(ctrls, "BUTTON_LOG_OUT", ARG_PTR, -1, button);
  gtk_signal_connect /*_object*/(GTK_OBJECT (button), "clicked",
 			   (GtkSignalFunc)prefs_dialog_logout_callback,
 			   (void *)ctrls);
                           

  
  label = gtk_label_new(" Connected");
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach(GTK_TABLE(table), label, 0,1,5,6, GTK_FILL | GTK_EXPAND, 0,10,10);
  arg_add_value(ctrls, "CONNECTED", ARG_PTR, -1, label);
  
  box = gtk_hbox_new(FALSE,5);
  gtk_table_attach_defaults(GTK_TABLE(table), box, 0,1,0,1);
  gtk_widget_show(box);
 
  gtk_widget_realize(window);

  if(F_show_pixmaps)
  {
  style = gtk_widget_get_style(frame);
#ifdef USE_AF_INET
  pixmap = gdk_pixmap_create_from_xpm_d(window->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(gchar **)computer_xpm);             
  pixmapwid = gtk_pixmap_new(pixmap, mask);			   
  gtk_box_pack_start(GTK_BOX(box), pixmapwid, FALSE,FALSE,0);
  gtk_widget_show(pixmapwid);	
#endif
  }
  
#ifdef USE_AF_INET
  label = gtk_label_new("Nessusd Host : ");
  gtk_box_pack_end(GTK_BOX(box), label,FALSE,FALSE,0);
  gtk_widget_show(label);
#endif
  
  box = gtk_hbox_new(FALSE,0);
  /*ENABLE_CRYPTO_LAYER*/
  gtk_table_attach_defaults(GTK_TABLE(table), box, 0,1,3,4);
  gtk_widget_show(box);
  
  if(F_show_pixmaps)
  {
  pixmap = gdk_pixmap_create_from_xpm_d(window->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(gchar **)user_xpm);             
  pixmapwid = gtk_pixmap_new(pixmap, mask);	   
  gtk_box_pack_start(GTK_BOX(box), pixmapwid, FALSE,FALSE,0);
  gtk_widget_show(pixmapwid);
  }
  label = gtk_label_new("Login : ");
  gtk_box_pack_end(GTK_BOX(box), label, FALSE, FALSE,0);
  gtk_widget_show(label);
  return(ctrls);
}

static int prefs_dialog_logout_callback(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 shutdown(GlobalSocket, 2);
 closesocket(GlobalSocket);
 GlobalSocket = -1;
 
 gtk_widget_hide(arg_get_value(ctrls, "BUTTON_LOG_OUT"));
 gtk_widget_show(arg_get_value(ctrls, "BUTTON_LOG_IN"));
 gtk_widget_hide(arg_get_value(ctrls, "CONNECTED"));
 return 0;
}
static int prefs_dialog_login_callback(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 char * username;
 char * password = NULL;
#ifdef USE_AF_INET
 char * hostname;
 int port;
#endif
 char * t;
 char * err;
#ifdef USE_AF_INET
 t = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(ctrls, "HOSTNAME")));
 if((!t) ||(!strlen(t)))
 {
  show_warning("You must enter an hostname");
  return(1);
 }
 hostname = emalloc(strlen(t)+1);
 strncpy(hostname, t, strlen(t));
 t = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(ctrls, "PORT")));
 if((!t) ||(!strlen(t)))
   {
     show_warning("You must enter a valid port number !");
     return(1);
   }
 port = atoi(t);
 if((port < 0) || (port > 65536))
   {
     show_warning("Your port specification is illegal");
     return(1);
   }
#endif
  t = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(ctrls, "USERNAME")));
  if((!t) ||(!strlen(t)))
    {
      show_warning("You must enter a valid username");
      return(1);
    }
  username = emalloc(strlen(t)+1);
  strncpy(username, t, strlen(t));
  /*ENABLE_CRYPTO_LAYER*/
  t = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(ctrls, "PASSWORD")));
  if((!t) ||(!strlen(t)))
    {
      show_warning("You must enter a valid password");
      return(1);
    }
  password = emalloc(strlen(t)+1);
  strncpy(password, t, strlen(t));

#ifdef USE_AF_INET
  /*ENABLE_CRYPTO_LAYER*/
  err = connect_to_nessusd(hostname, port, username, password);
#else
  err = connect_to_nessusd("localhost", -1, username, password);
#endif
  if(err){
	  /*ENABLE_CRYPTO_LAYER*/
	  show_error(err);
	}
 else
 {
   /*ENABLE_CRYPTO_LAYER*/
 gtk_widget_hide(arg_get_value(ctrls, "BUTTON_LOG_IN"));
 gtk_widget_show(arg_get_value(ctrls, "BUTTON_LOG_OUT"));
 gtk_widget_show(arg_get_value(ctrls, "CONNECTED"));
 
 /*
  * Go to the plugins page
  */
 gtk_notebook_set_page(GTK_NOTEBOOK(arg_get_value(MainDialog, "NOTEBOOK")), 1);
 if(First_time==0)
 {
  prefs_plugins_redraw(NULL,NULL,arg_get_value(MainDialog, "PLUGINS"));
  prefs_dialog_set_defaults(MainDialog, Prefs);
 }
  prefs_plugins_prefs_redraw(NULL, NULL, arg_get_value(MainDialog, "PLUGINS_PREFS"));
 
 First_time++;
 }
 return(0);
}
#endif
