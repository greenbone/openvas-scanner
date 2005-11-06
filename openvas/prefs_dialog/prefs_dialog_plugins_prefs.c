/* Nessus
 * Copyright (C) 1999 - 2005 Renaud Deraison
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
#include "../globals.h"
#include "prefs_dialog_plugins_prefs.h"


static void pprefs_add_separator(struct arglist *, char *, int);
static void pprefs_add_entry(struct arglist *, struct arglist *, char *, int);
static void pprefs_add_password(struct arglist *, struct arglist *, char *, int);
static void pprefs_add_file(struct arglist*, struct arglist*, char*, int);
static void pprefs_add_checkbox(struct arglist *, struct arglist *, char *, int);
static void pprefs_add_radio(struct arglist *, struct arglist *, char *, int);
void prefs_dialog_plugins_prefs_fill(struct arglist *, struct arglist *);


struct arglist *
prefs_dialog_plugins_prefs()
{
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 GtkWidget * frame, * s_window, * vbox;
 GtkWidget * cred_frame, * cred_s_window, * cred_vbox;
 
 frame = gtk_frame_new("Advanced Plugins preferences");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 gtk_widget_show(frame);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);

 cred_frame = gtk_frame_new("Credentials");
 gtk_container_border_width(GTK_CONTAINER(cred_frame), 10);
 gtk_widget_show(cred_frame);
 arg_add_value(ctrls, "FRAME_CREDENTIALS", ARG_PTR, -1, cred_frame);


 
 s_window = gtk_scrolled_window_new(NULL, NULL);
 gtk_container_border_width(GTK_CONTAINER(s_window), 10);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s_window),
 				GTK_POLICY_AUTOMATIC,
				GTK_POLICY_AUTOMATIC);
 gtk_container_add(GTK_CONTAINER(frame), s_window);
 gtk_widget_show(s_window);

 cred_s_window = gtk_scrolled_window_new(NULL, NULL);
 gtk_container_border_width(GTK_CONTAINER(cred_s_window), 10);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(cred_s_window),
 				GTK_POLICY_AUTOMATIC,
				GTK_POLICY_AUTOMATIC);
 gtk_container_add(GTK_CONTAINER(cred_frame), cred_s_window);
 gtk_widget_show(cred_s_window);
 
 vbox = gtk_vbox_new(FALSE, FALSE);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(s_window), vbox);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(s_window), vbox);
#endif
 gtk_widget_show(vbox);

 cred_vbox = gtk_vbox_new(FALSE, FALSE);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(cred_s_window), cred_vbox);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(cred_s_window), cred_vbox);
#endif
 gtk_widget_show(cred_vbox);

 arg_add_value(ctrls, "SCROLLED_WINDOW", ARG_PTR, -1, s_window);
 arg_add_value(ctrls, "VBOX", ARG_PTR, -1, cred_vbox);
 arg_add_value(ctrls, "VBOX_CREDENTIALS", ARG_PTR, -1, vbox);
 arg_add_value(ctrls, "SCROLLED_WINDOW_CREDENTIALS", ARG_PTR, -1, cred_s_window);


 arg_add_value(ctrls, "PLUGINS_NUM", ARG_INT, sizeof(int), (void*)0);
 arg_add_value(ctrls, "SCANNERS_NUM", ARG_INT, sizeof(int), (void*)0);
 return(ctrls);
}				


static int is_credentials(char * plugin_name, char * preference_name)
{
 if ( strcmp(plugin_name, "SSH settings") == 0 )
	return 1;
 else if ( strcmp(plugin_name, "Kerberos configuration") == 0 )
	return 1;
 else if ( strcmp(plugin_name, "Login configurations") == 0 ) 
	{
	 if ( preference_name == NULL ) return 0;
	 if ( strncmp(preference_name, "SMB", 3) == 0 )
		return 1;
	}
 return 0;
}


void
prefs_dialog_plugins_prefs_fill(ctrls, plugins)
 struct arglist * ctrls;
 struct arglist * plugins;
{
 struct arglist * plugs = plugins;
 int credentials;
 while(plugs && plugs->next)
 {
  struct arglist * prefs;

  if((prefs = arg_get_value(plugs->value, "plugin_prefs")))
  {
   credentials = is_credentials(plugs->name, NULL); 
   if ( credentials == 0 )
	pprefs_add_separator(ctrls, plugs->name, 0);

   while(prefs != NULL && prefs->next != NULL )
   {
     char * type, *value;
     credentials = is_credentials(plugs->name, prefs->name);
     type  = arg_get_value(prefs->value, "type");
     value = arg_get_value(prefs->value, "value");
     if(type)
     {
      if(!strcmp(type, PREF_ENTRY))
        pprefs_add_entry(ctrls, prefs, value, credentials);
      else if(!strcmp(type, PREF_PASSWORD))
        pprefs_add_password(ctrls, prefs, value, credentials);
      else if(!strcmp(type, PREF_RADIO))
        pprefs_add_radio(ctrls, prefs, value, credentials);
      else if(!strcmp(type, PREF_CHECKBOX))
     	pprefs_add_checkbox(ctrls, prefs, value, credentials);
      else if(!strcmp(type, PREF_FILE))
        pprefs_add_file(ctrls, prefs, value, credentials);
     }
     prefs = prefs->next;
   }
  
   credentials = is_credentials(plugs->name, NULL); 
   if ( credentials == 0 )
   	pprefs_add_separator(ctrls, NULL, 0);
  }
  plugs = plugs->next;
 }
}

/*
 * Clean up the plugin preferences and plugin
 * preferences widgets
 */
void
prefs_plugins_reset(ctrls, plugins, scanners)
 struct arglist * ctrls;
 struct arglist * plugins;
 struct arglist * scanners;
{
 struct arglist * prefs;
 struct arglist * s[2];
 GtkWidget * frame, *cred_frame;
 GtkWidget * s_window, *cred_s_window;
 GtkWidget * vbox, *cred_vbox;
 int i;
 

 s[0] = plugins;
 s[1] = scanners;
 
 if((!ctrls )|| (!plugins)||(!scanners))return;
 frame = arg_get_value(ctrls, "FRAME");
 s_window = arg_get_value(ctrls, "SCROLLED_WINDOW");
 gtk_widget_hide(s_window);
 gtk_container_remove(GTK_CONTAINER(frame), s_window);

 cred_frame = arg_get_value(ctrls, "FRAME_CREDENTIALS");

 cred_s_window = arg_get_value(ctrls, "SCROLLED_WINDOW_CREDENTIALS");
 gtk_widget_hide(cred_s_window);
 gtk_container_remove(GTK_CONTAINER(cred_frame), cred_s_window);
 
 s_window = gtk_scrolled_window_new(NULL, NULL);
 gtk_container_border_width(GTK_CONTAINER(s_window), 10);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s_window),
 				GTK_POLICY_AUTOMATIC,
				GTK_POLICY_AUTOMATIC);
 gtk_container_add(GTK_CONTAINER(frame), s_window);
 gtk_widget_show(s_window);

 cred_s_window = gtk_scrolled_window_new(NULL, NULL);
 gtk_container_border_width(GTK_CONTAINER(cred_s_window), 10);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(cred_s_window),
 				GTK_POLICY_AUTOMATIC,
				GTK_POLICY_AUTOMATIC);
 gtk_container_add(GTK_CONTAINER(cred_frame), cred_s_window);
 gtk_widget_show(cred_s_window);
 
 vbox = gtk_vbox_new(FALSE, FALSE);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(s_window), vbox);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(s_window), vbox);
#endif
 gtk_widget_show(vbox);		

 cred_vbox = gtk_vbox_new(FALSE, FALSE);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(cred_s_window), cred_vbox);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(cred_s_window), cred_vbox);
#endif
 gtk_widget_show(cred_vbox);		
 arg_set_value(ctrls, "SCROLLED_WINDOW", -1, s_window);   
 arg_set_value(ctrls, "VBOX", -1, vbox);		  
 arg_set_value(ctrls, "SCROLLED_WINDOW_CREDENTIALS", -1, cred_s_window);   
 arg_set_value(ctrls, "VBOX_CREDENTIALS", -1, cred_vbox);		  
 arg_set_value(ctrls, "PLUGINS_NUM", sizeof(int), (void*)0);
 arg_set_value(ctrls, "SCANNERS_NUM", sizeof(int), (void*)0);
 for(i=0;i<2;i++)
 {
 struct arglist * p = s[i];
 while(p && p->next)
 {
  prefs = arg_get_value(p, "plugin_prefs");
  if(prefs)while(prefs && prefs->next)
   {
   struct arglist * v;
   /*
    * We keep the first two fields (type and value) and we
    * destroy the others
    */
   v = prefs->value;
   v = v->next;
  /* arg_free(v->next); */
   v->next = emalloc(sizeof(struct arglist));
   prefs = prefs->next;
   }
  p = p->next;
  }
 }
 gtk_widget_show(vbox);
}		   

/*
 * Redraw the plugins preferences
 */
int
prefs_plugins_prefs_redraw(bidon1, bidon2, ctrls)
  GtkWidget * bidon1;
  void * bidon2;
  struct arglist * ctrls;
{
 int num = (int)arg_get_value(ctrls, "PLUGINS_NUM");
 int num2 = (int)arg_get_value(ctrls, "SCANNERS_NUM");
 if((num != PluginsNum)||(num2 != ScannersNum))
 {
 prefs_plugins_reset(ctrls, Plugins, Scanners);
 prefs_dialog_plugins_prefs_fill(ctrls, Scanners);
 prefs_dialog_plugins_prefs_fill(ctrls, Plugins);
 arg_set_value(ctrls, "PLUGINS_NUM", sizeof(int), (void *)PluginsNum);
 arg_set_value(ctrls, "SCANNERS_NUM", sizeof(int), (void*)ScannersNum);
 }
 return 0;
}




static void
 pprefs_add_separator(ctrls, name, credentials)
  struct arglist * ctrls;
  char * name;
  int credentials;
{
 GtkWidget * vbox, * label;
 GtkWidget * separator;
 char * str;
 int len;
 vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 if(name)
 {
  len  = strlen(name);
  str = emalloc(len + 2);
  strncpy(str, name, strlen(name));
  strncat(str, ":", 1);
  label = gtk_label_new(str);
  gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, FALSE, 5);
  gtk_widget_show(label);
 }
 separator = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(vbox), separator, TRUE, FALSE, 5);
 gtk_widget_show(separator);
}


static int
file_dialog_hide(GtkWidget * filew, GtkWidget * nul)
{
 gtk_widget_hide(filew);
 gtk_widget_destroy(filew);
 return 0;
}


static int
file_selected(GtkWidget * nul,
	      GtkWidget * filew)
{
  struct arglist * c;
 GtkWidget * entry;
 char * fname = (char*) gtk_file_selection_get_filename(GTK_FILE_SELECTION(filew));
 gtk_widget_hide(filew);
 c = gtk_object_get_data(GTK_OBJECT(filew), "data");
 entry = arg_get_value(c, "ENTRY");
 gtk_entry_set_text(GTK_ENTRY(entry), fname);
 return 0;
}	    
static int
select_file(GtkWidget * b, 
	    struct arglist * ctrls)
{

 GtkWidget * filew = gtk_file_selection_new("Select file");
 gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(filew)->ok_button),
 		"clicked", (GtkSignalFunc)file_selected, filew);
  gtk_signal_connect_object (GTK_OBJECT (GTK_FILE_SELECTION (filew)->cancel_button),
                                 "clicked",
                                 GTK_SIGNAL_FUNC (file_dialog_hide),
                                 GTK_OBJECT (filew));			 
 gtk_object_set_data(GTK_OBJECT(filew), "data", ctrls);		
 gtk_widget_show(filew);		
 return 0;		
}


static void
 pprefs_add_entry(ctrls, pref, value, credentials)
  struct arglist * ctrls;
  struct arglist * pref;
  char * value;
  int credentials;
{
 GtkWidget * vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 GtkWidget * entry, * text, * box;
 char * name = pref->name;
 char * fullname = arg_get_value(pref->value, "fullname");
 struct arglist * pprefs = arg_get_value(Prefs, "PLUGINS_PREFS");
 
 if(pprefs)
 {
  int type;
  if((type = arg_get_type(pprefs, fullname))>=0)
  {
   value = arg_get_value(pprefs, fullname);
   if(type==ARG_INT)
    {
    if(value)value=strdup("yes");
    else value = strdup("no");
    }
  }
 }
 box = gtk_hbox_new(FALSE, 0);
 gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);
 gtk_widget_show(box);
 
 text = gtk_label_new(estrdup(name));
 gtk_box_pack_start(GTK_BOX(box), text,TRUE, TRUE, 5);
 gtk_widget_show(text);
 
 entry = gtk_entry_new();
 gtk_entry_set_text(GTK_ENTRY(entry), value);
 gtk_box_pack_end(GTK_BOX(box), entry, TRUE, TRUE, 5);
 gtk_widget_show(entry);
 arg_add_value(pref->value, "ENTRY", ARG_PTR, -1, entry);
}


static void
 pprefs_add_password(ctrls, pref, value, credentials)
  struct arglist * ctrls;
  struct arglist * pref;
  char * value;
  int credentials;
{
 GtkWidget * vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 GtkWidget * entry, * text, * box;
 char * name = pref->name;
 char * fullname = arg_get_value(pref->value, "fullname");
 struct arglist * pprefs = arg_get_value(Prefs, "PLUGINS_PREFS");


 
 if(pprefs)
 {
  int type;
  if((type = arg_get_type(pprefs, fullname))>=0)
  {
   value = arg_get_value(pprefs, fullname);
   if(type==ARG_INT)
    {
    if(value)value=strdup("yes");
    else value = strdup("no");
    }
  }
 }
 box = gtk_hbox_new(FALSE, 0);
 gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);
 gtk_widget_show(box);
 
 text = gtk_label_new(estrdup(name));
 gtk_box_pack_start(GTK_BOX(box), text,TRUE, TRUE, 5);
 gtk_widget_show(text);
 
 entry = gtk_entry_new();
 gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
 gtk_entry_set_text(GTK_ENTRY(entry), value);
 gtk_box_pack_end(GTK_BOX(box), entry, TRUE, TRUE, 5);
 gtk_widget_show(entry);
 arg_add_value(pref->value, "ENTRY", ARG_PTR, -1, entry);
}

static void
 pprefs_add_file(ctrls, pref, value, credentials)
  struct arglist * ctrls;
  struct arglist * pref;
  char * value;
  int credentials;
{
 GtkWidget * vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 GtkWidget * entry, * text, * box;
 GtkWidget * hbox, * button;
 char * name = pref->name;
 char * fullname = arg_get_value(pref->value, "fullname");
 struct arglist * pprefs = arg_get_value(Prefs, "PLUGINS_PREFS");
 
 if(pprefs)
 {
  int type;
  if((type = arg_get_type(pprefs, fullname))>=0)
  {
   value = arg_get_value(pprefs, fullname);
   if(type==ARG_INT)
    {
    if(value)value=strdup("yes");
    else value = strdup("no");
    }
  }
 }
 box = gtk_hbox_new(FALSE, 0);
 gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);
 gtk_widget_show(box);
 
 text = gtk_label_new(estrdup(name));
 gtk_box_pack_start(GTK_BOX(box), text,TRUE, TRUE, 5);
 gtk_widget_show(text);
 
 hbox = gtk_hbox_new(FALSE, 0);
 gtk_box_pack_end(GTK_BOX(box), hbox, TRUE, TRUE, 5);
 gtk_widget_show(hbox);
 
 entry = gtk_entry_new();
 gtk_entry_set_text(GTK_ENTRY(entry), value);
 gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 5);
 gtk_widget_show(entry);
 arg_add_value(pref->value, "ENTRY", ARG_PTR, -1, entry);
 
 button = gtk_button_new_with_label("Select...");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 5);
 gtk_signal_connect(GTK_OBJECT(button), "clicked", (GtkSignalFunc)select_file,
 			pref->value);
			
 gtk_widget_show(button);
}



static void
 pprefs_add_radio(ctrls, pref, value, credentials)
  struct arglist * ctrls;
  struct arglist * pref;
  char * value;
  int credentials;
{
 GtkWidget * vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 GtkWidget * orig;
 GtkWidget * button, * first_button;
 GtkWidget * label;
 char * t;
 GSList * list = NULL;
 char * fullname = arg_get_value(pref->value, "fullname");
 struct arglist * pprefs = arg_get_value(Prefs, "PLUGINS_PREFS");
 char * def = NULL;
 if(pprefs)
 {
  int type;
  if((type = arg_get_type(pprefs, fullname))>=0)
  {
   def = arg_get_value(pprefs, fullname);
   if(type==ARG_INT)
    {
    if(def)def=strdup("yes");
    else def = strdup("no");
    }
  }
 }
 
 
 label = gtk_label_new(estrdup(pref->name));
 gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, FALSE, 5);
 gtk_widget_show(label);
 
 t = strchr(value, ';');
 if(t)t[0] = '\0';
 first_button = orig = gtk_radio_button_new_with_label(NULL, value);
 gtk_box_pack_start(GTK_BOX(vbox), orig, TRUE, FALSE, 5);
 gtk_object_set_data(GTK_OBJECT(orig), "name", value);
 gtk_widget_show(orig);
#if GTK_VERSION > 10
 gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(orig),TRUE);
#else
 GTK_TOGGLE_BUTTON(orig)->active = TRUE;
#endif
 value = t+sizeof(char);
 if(t)
    while(value)
    {
      if((t = strchr(value, ';')))t[0]='\0';
      button = gtk_radio_button_new_with_label(
           gtk_radio_button_group(GTK_RADIO_BUTTON(orig)), 
	   value);
      gtk_object_set_data(GTK_OBJECT(button), "name", value);
      if(def && !strcmp(def, value))
       {
#if GTK_VERSION > 10
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button),TRUE);
#else
	GTK_TOGGLE_BUTTON(button)->active = TRUE;
#endif
	}
      gtk_box_pack_start(GTK_BOX(vbox), button, TRUE, FALSE, 5);
      gtk_widget_show(button);
      if(t)value = t+sizeof(char);
      else value = NULL;
     }
 list = gtk_radio_button_group(GTK_RADIO_BUTTON(orig));

 arg_add_value(pref->value, "RADIOBUTTONS", ARG_PTR, -1, list);
}

static void
 pprefs_add_checkbox(ctrls, pref, value, credentials)
  struct arglist * ctrls;
  struct arglist * pref;
  char * value;
  int credentials;
{
 GtkWidget * vbox = arg_get_value(ctrls, credentials == 0 ? "VBOX":"VBOX_CREDENTIALS");
 GtkWidget * box;
 GtkWidget * button;
 char * name = pref->name;
 struct arglist * pprefs = arg_get_value(Prefs, "PLUGINS_PREFS");
 char * def = NULL;
 char * fullname = arg_get_value(pref->value, "fullname");
 if(pprefs)
 {
  int type;
  if((type = arg_get_type(pprefs, fullname))>=0)
  {
   def = arg_get_value(pprefs, fullname);
   if(type==ARG_INT)
    {
    if(def)def=strdup("yes");
    else def = strdup("no");
    }
  }
 }
 box = gtk_hbox_new(FALSE, 0);
 gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);
 gtk_widget_show(box);
 
 button = gtk_check_button_new_with_label(estrdup(name));
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 gtk_widget_show(button);
 if(def)
 {
  if(!strcmp(def, "yes"))
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  else
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), FALSE);
  }
 else
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), !strcmp(value, "yes"));
 arg_add_value(pref->value, "CHECKBOX", ARG_PTR, -1, button);
}
#endif
