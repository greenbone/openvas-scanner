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
#include "../plugin_infos.h"
#include "../families.h"
#include "../preferences.h"
#include "globals.h"
#include "../xpm/warning_small.xpm"
#include "../error_dialog.h"
#include "prefs_help.h"
#include "filter.h"
#include "comm.h"


static struct plugin_families * families;

int prefs_plugins_redraw(GtkWidget *, void *, struct arglist *);
void fill_plugins_family(struct arglist *);
static void prefs_family_toggle_callback(GtkWidget * , struct arglist *);
static void prefs_plugin_list_toggle_callback(GtkWidget * , struct arglist * );
static void prefs_plugin_list_callback(GtkWidget * , struct arglist * );
static void prefs_family_list_callback(GtkWidget * , struct arglist * );
static GtkWidget * warning_sign(GtkWidget *);
static int glist_cmp( gconstpointer a, gconstpointer b);


static int warning_expl()
{
 show_info(HLP_WARNING);
 return 0;
}


static GtkWidget * 
warning_sign(w)
 GtkWidget * w;
{
 GtkStyle * style;
 GtkWidget * p;
 GtkWidget * ret;
 
 style = gtk_widget_get_style(w);
 p = make_pixmap(w, &style->bg[GTK_STATE_NORMAL], warning_small_xpm);
 
 ret = gtk_button_new();
 gtk_widget_set_usize(ret, 20, 20);
#if GTK_VERSION > 10
 gtk_button_set_relief(GTK_BUTTON(ret), GTK_RELIEF_NONE);
#endif
 gtk_container_add(GTK_CONTAINER(ret), p);
 gtk_signal_connect(GTK_OBJECT(ret),
			     "clicked",
			     GTK_SIGNAL_FUNC(warning_expl),
			     NULL);
 gtk_widget_show(p);
 return ret;
}				    


static int
set_filter(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 struct plugin_filter filter;
 char * old;
 struct arglist * plugins = Plugins;
 GList * dlist;

 ask_filter(&filter);
 if(!filter.pattern)
  return 0;
 

 if((old = arg_get_value(ctrls, "FILTER")))
 {
  arg_set_value(ctrls, "FILTER", sizeof(filter), &filter);
 }
 else
  arg_add_value(ctrls, "FILTER", ARG_STRUCT, sizeof(filter), &filter);

  
  Filter = filter;
  memcpy(&Filter, &filter, sizeof(filter));
  
  if(plugins)
   while(plugins->next)
   {
    if(filter_plugin(&filter, plugins->value))plug_set_launch(plugins->value, 0);
    plugins = plugins->next;
   } 
  
  dlist = GTK_LIST(arg_get_value(ctrls,"FAMILIES_LIST"))->children;
  while(dlist)
  {
   char  * name = gtk_object_get_data(GTK_OBJECT(dlist->data), "list_item_data");
   if(family_empty(name, Plugins))
    gtk_widget_hide(GTK_WIDGET(dlist->data));
   else
    {
    if(!family_enabled(name, Plugins))
    {
      GtkWidget * checkbox = gtk_object_get_data(GTK_OBJECT(dlist->data),
      							"list_item_checkbox");
							
      GTK_TOGGLE_BUTTON(checkbox)->active = 0;							
    }
    gtk_widget_show(GTK_WIDGET(dlist->data));
    }
   dlist = dlist->next;
  }
  prefs_family_list_callback(arg_get_value(ctrls,"FAMILIES_LIST"), ctrls);
  
  return 0;
}
static int 
disable_all(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 struct arglist * buttons = arg_get_value(ctrls, "families_buttons");
 while(buttons && buttons->next)
 {
  gtk_object_set_data(GTK_OBJECT(buttons->value), "be_lazy", (void*)1);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(buttons->value), 0);
  family_enable(buttons->name, Plugins, DISABLE_FAMILY);
  gtk_object_remove_data(GTK_OBJECT(buttons->value), "be_lazy");
  buttons = buttons->next;
 }
 pluginset_reload(Plugins, Scanners);
 return 0;
}

static int 
enable_all(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 struct arglist * buttons = arg_get_value(ctrls, "families_buttons");
 if(buttons)
  while(buttons->next)
 {
  gtk_object_set_data(GTK_OBJECT(buttons->value), "be_lazy", (void*)1);
  family_enable(buttons->name, Plugins, ENABLE_FAMILY);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(buttons->value), 1);
  gtk_object_remove_data(GTK_OBJECT(buttons->value), "be_lazy");
  buttons = buttons->next;
 }
 pluginset_reload(Plugins, Scanners);
 return 0;
}





/*
 * plugin_list_setup
 *
 * Draws the main window showing informations
 * about the plugins of the server
 */
struct arglist *  
prefs_dialog_plugins(window)
 GtkWidget * window;
{
  struct arglist * ctrls = emalloc(sizeof(struct arglist));
  GtkWidget * frame;
  GtkWidget * families_window;
  GtkWidget * plugins_window;
  GtkWidget * w_box;
  GtkWidget * list;
  GtkWidget * vbox, * hbox;
  GtkWidget * button;
#if GTK_VERSION > 10
#if GTK_VERSION < 20
  GtkAccelGroup * accel = gtk_accel_group_new();
#endif
#endif
 
  frame = gtk_frame_new("Plugin selection");
  gtk_container_border_width(GTK_CONTAINER(frame), 10);
  arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
  
  w_box = gtk_vbox_new(TRUE, 5);
  gtk_container_border_width(GTK_CONTAINER(w_box), 5);
  gtk_container_add(GTK_CONTAINER(frame), w_box);
  
  
  		     
  
  families_window = gtk_scrolled_window_new(NULL,NULL);
  gtk_container_border_width(GTK_CONTAINER(families_window), 10);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(families_window),
				 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
 
  vbox = gtk_vbox_new(FALSE, 0);
  gtk_box_pack_start(GTK_BOX(w_box), vbox, TRUE, TRUE, 0);
  gtk_widget_show(vbox);
  
  gtk_box_pack_start(GTK_BOX(vbox), families_window, TRUE, TRUE, 0);
  
  
  hbox = gtk_hbox_new(FALSE, 5);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
  gtk_widget_show(hbox);
  
  button = gtk_button_new_with_label("Enable all");
  gtk_signal_connect(GTK_OBJECT(button),
			     "clicked",
			     GTK_SIGNAL_FUNC(enable_all),
			     ctrls);
			   
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  button = gtk_button_new_with_label("Disable all");
  gtk_signal_connect(GTK_OBJECT(button),
			     "clicked",
			     GTK_SIGNAL_FUNC(disable_all),
			     ctrls);
			   
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  
#if GTK_VERSION < 20
  button = gtk_button_new_with_label("Filter...");
#else  
  button = gtk_button_new_with_mnemonic("Fi_lter...");  
#endif  
  gtk_signal_connect(GTK_OBJECT(button),
  				"clicked",
				GTK_SIGNAL_FUNC(set_filter),
				ctrls);
				
							     
#if GTK_VERSION > 10
#if GTK_VERSION < 20
  gtk_widget_add_accelerator(GTK_WIDGET(button),
  			     "clicked",
			     accel,
			     'l',
			     0,
			     GTK_ACCEL_LOCKED);
  gtk_window_add_accel_group(GTK_WINDOW(window), accel);
#endif  
#endif
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
 
 
  
  
#if 0
  button = gtk_button_new_with_label("Upload plugin...");
  gtk_signal_connect(GTK_OBJECT(button),
			     "clicked",
			     GTK_SIGNAL_FUNC(hdl_plugin_upload),
			     ctrls);
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);	
#endif
  
  
  hbox = gtk_hbox_new(FALSE, 5);
  gtk_box_pack_start(GTK_BOX(vbox),
  		     hbox, 
		     FALSE, FALSE, 5);
  gtk_widget_show(hbox);
  
  button = gtk_check_button_new_with_label("Enable dependencies at runtime");
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  arg_add_value(ctrls, "ENABLE_DEPS_AT_RUNTIME", ARG_PTR, -1, button);
  
  button = gtk_check_button_new_with_label("Silent dependencies");
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  arg_add_value(ctrls, "SILENT_DEPS", ARG_PTR, -1, button);
  

  		      
  
  plugins_window = gtk_scrolled_window_new(NULL,NULL);
  gtk_container_border_width(GTK_CONTAINER(plugins_window), 10);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(plugins_window),
				 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   
  
  gtk_box_pack_start(GTK_BOX(w_box), plugins_window, TRUE, TRUE, 0);
  
  
  list = gtk_list_new();
  arg_add_value(ctrls, "FAMILIES_LIST", ARG_PTR, -1, list);
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(families_window),list);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(families_window), list);
#endif
  gtk_widget_show(list);
  
  gtk_signal_connect(GTK_OBJECT(list),
		     "selection_changed",
		     GTK_SIGNAL_FUNC(prefs_family_list_callback),
		     ctrls);
  
  list = gtk_list_new();                          
  arg_add_value(ctrls, "PLUGINS_LIST", ARG_PTR, -1, list);
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(plugins_window), list);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(plugins_window),list);
#endif
  gtk_widget_show(list);
  gtk_signal_connect(GTK_OBJECT(list),
		     "selection_changed",
		     GTK_SIGNAL_FUNC(prefs_plugin_list_callback),     
		     ctrls);   
 arg_add_value(ctrls, "FAMILIES", ARG_PTR, -1, families);                   
 fill_plugins_family(ctrls);
 gtk_widget_show(families_window);
 gtk_widget_show(plugins_window);
 gtk_widget_show(w_box);
 gtk_widget_show(frame);
 arg_add_value(ctrls, "PLUGINS_NUM", ARG_INT, sizeof(int), (void *)PluginsNum);
 arg_add_value(ctrls, "SCANNERS_NUM", ARG_INT, sizeof(int), (void*)ScannersNum);
 return(ctrls);
}



static void 
prefs_plugin_list_callback(widget, ctrls)
     GtkWidget * widget;
     struct arglist * ctrls;
{
  GtkObject * list_item;
  char * cur_plug;
  GList * dlist;
  GtkWidget * list = arg_get_value(ctrls, "PLUGINS_LIST");
  dlist = GTK_LIST(list)->selection;
  if(!dlist)return;
  
  list_item = GTK_OBJECT(dlist->data);
  cur_plug = gtk_object_get_data(list_item,"list_item_data");
  plugin_info_window_setup(Plugins, cur_plug);             
}

static void 
prefs_family_toggle_callback(w, ctrls)
     GtkWidget * w;
     struct arglist * ctrls;
{
  int enable = GTK_TOGGLE_BUTTON (w)->active;
  GList * dlist = NULL;
  GtkObject * list_item;
  char * name;
  GtkWidget * item;
  int check_manually = 1;
  
  if(gtk_object_get_data(GTK_OBJECT(w), "be_lazy"))
   return;
   

  item = w->parent->parent;
  list_item = GTK_OBJECT(item);
  name = gtk_object_get_data(list_item,"list_item_data");
  dlist = GTK_LIST(arg_get_value(ctrls, "PLUGINS_LIST"))->children;

 if(check_manually)family_enable(name, Plugins, enable);
 pluginset_reload(Plugins, Scanners);
 
 prefs_family_list_callback(arg_get_value(ctrls,"FAMILIES_LIST"), ctrls);
}

static 
void prefs_plugin_list_toggle_callback(w, plugin)
     GtkWidget * w;
     struct arglist * plugin;
{
  int state = GTK_TOGGLE_BUTTON(w)->active;
  
  plug_set_launch(plugin,state);
  pluginset_reload(Plugins, Scanners);
}

static
void 
prefs_family_list_callback(widget, ctrls)
     GtkWidget * widget; 
     struct arglist * ctrls;
{
  GList * dlist;
  GtkObject * list_item;
  char * cur_family;
  struct arglist * plugs = Plugins;
  GtkTooltips * tooltips;
  struct plugin_filter * filter = arg_get_value(ctrls, "FILTER");
  
  if(gtk_object_get_data(GTK_OBJECT(widget), "be_lazy"))
   return;
   
 
  
  
  dlist = GTK_LIST(arg_get_value(ctrls, "FAMILIES_LIST"))->selection;
  if(!dlist)return;
  
  list_item = GTK_OBJECT(dlist->data);
  cur_family = gtk_object_get_data(list_item,"list_item_data");
  dlist = GTK_LIST(arg_get_value(ctrls, "PLUGINS_LIST"))->children;
  if(dlist)gtk_list_remove_items(GTK_LIST(arg_get_value(ctrls, "PLUGINS_LIST")),dlist); 
  dlist = NULL;
  tooltips = gtk_tooltips_new();
  if(plugs)while(plugs->next)
    {
      GtkWidget * item;
      GtkWidget * box;
      GtkWidget * button;
      GtkWidget * label;
      
      
      if(arg_get_value(plugs->value, "FAMILY") &&
	 !strcmp(arg_get_value(plugs->value, "FAMILY"), cur_family))
	{
	  char * cat = arg_get_value(plugs->value, "CATEGORY");
	  int warning = cat? (!strcmp(cat, "denial") ||
			      !strcmp(cat, "kill_host") ||
			      !strcmp(cat, "flood") ||
	  		      !strcmp(cat, "destructive_attack")):0;
	  GtkWidget * sign = NULL;
	  	
	  if(filter)
	  {
	   if(filter_plugin(filter, plugs->value))
	    {
	     plugs = plugs->next;
	     continue;
	    }
	  }
	  item = gtk_list_item_new();
	  
	  
	  button = gtk_check_button_new();
	  gtk_widget_set_usize(button, 20, 20);
	  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), 
				      (int)plug_get_launch(plugs->value));
	  
	  label = gtk_label_new(plugs->name);
	  box = gtk_hbox_new(FALSE,5);
	  gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
	  gtk_widget_show(label);
	  
	 
	  gtk_box_pack_end(GTK_BOX(box), button, FALSE, FALSE,0);
	  if(warning)
	  {
	   sign = warning_sign(widget);
	   gtk_box_pack_end(GTK_BOX(box), sign, FALSE, FALSE, 0); 
	  }
	  gtk_container_add(GTK_CONTAINER(item), box);
	  gtk_signal_connect(GTK_OBJECT(button),
			     "clicked",
			     GTK_SIGNAL_FUNC(prefs_plugin_list_toggle_callback),
			     plugs->value);
	  gtk_widget_show(button);
	  if(warning)gtk_widget_show(sign);
	  gtk_widget_show(box);
	  gtk_widget_show(item);
	  if(arg_get_value(plugs->value, "SUMMARY"))
	    gtk_tooltips_set_tip(tooltips, item, 
				 (gchar *)arg_get_value(plugs->value, "SUMMARY"),"");
	  dlist = g_list_append(dlist, item);
	  gtk_object_set_data(GTK_OBJECT(item),
			      "list_item_data",
			      plugs->name);
	  gtk_object_set_data(GTK_OBJECT(item),
			      "button",
			      button);
	  gtk_object_set_data(GTK_OBJECT(item),
			      "plugin",
			      plugs->value);                                        
	}                    
      plugs = plugs->next;	
    }
  gtk_tooltips_enable(tooltips);
  dlist = g_list_sort(dlist, glist_cmp);
  gtk_list_append_items(GTK_LIST(arg_get_value(ctrls, "PLUGINS_LIST")), dlist);
  pluginset_reload(Plugins, Scanners);
}


int prefs_plugins_redraw(w, dumb, ctrls)
 GtkWidget * w;
 void * dumb;
 struct arglist * ctrls;
{
 int num;
 
 num = (int)arg_get_value(ctrls, "PLUGINS_NUM");
 if(num != PluginsNum){
  fill_plugins_family(ctrls);
  arg_set_value(ctrls, "PLUGINS_NUM", sizeof(int), (void *)PluginsNum);
 }
 return 0;
}

static int glist_cmp( gconstpointer a, gconstpointer b)
{
     GtkWidget * item_a = (GtkWidget*)a;
     GtkWidget * item_b = (GtkWidget*)b;

     char * str_a, * str_b;

     str_a = gtk_object_get_data(GTK_OBJECT(item_a), "list_item_data");
     str_b = gtk_object_get_data(GTK_OBJECT(item_b), "list_item_data");
     return strcmp(str_a, str_b);
}

void 
fill_plugins_family(ctrls)
 struct arglist * ctrls;
{
 GtkTooltips * tooltips;
 struct arglist * plugs = Plugins;
 struct plugin_families * lfamilies, *f;
 struct arglist * buttons;
 GList * dlist = NULL;
 
 

 

 buttons = arg_get_value(ctrls, "families_buttons");
 if(buttons)
 {
  /* arg_free(buttons); */
   buttons = emalloc(sizeof(struct arglist));
  arg_set_value(ctrls,"families_buttons",-1, buttons);
 }
 else 
 {
  buttons = emalloc(sizeof(struct arglist));
  arg_add_value(ctrls, "families_buttons", ARG_ARGLIST, -1, buttons);
 }
 

 tooltips = gtk_tooltips_new();
 lfamilies = families = family_init();
 if(plugs)
  while(plugs->next)
    {
      family_add(families, plugs->value);
      plugs = plugs->next;
    }
 plugs = Plugins;
  

 if(lfamilies)
  while(lfamilies->next)
   {
     GtkWidget * item;
     GtkWidget * box;
     GtkWidget * button;
     GtkWidget * label;
     struct plugin_families * old = arg_get_value(ctrls, "FAMILIES");
     int flag = 0;
     if(old)
      while(old->next && !flag)
      {
      if(old->name)flag = !strcmp(old->name, lfamilies->name);
      old = old->next;
      }
      
     if(flag){
     	lfamilies = lfamilies->next;
	continue;
	}
     	
     item = gtk_list_item_new();
     
     
     button = gtk_check_button_new();
     arg_add_value(buttons, lfamilies->name, ARG_PTR, -1, button);
     gtk_tooltips_set_tip(tooltips, button, lfamilies->name, "");
     
     gtk_widget_set_usize(button, 15, 15);
     gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), 
				 family_enabled(lfamilies->name, Plugins) ? TRUE:FALSE);
     label = gtk_label_new(lfamilies->name);
     box = gtk_hbox_new(FALSE,5);
     gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
     gtk_widget_show(label);
     gtk_box_pack_end(GTK_BOX(box), button, FALSE, FALSE,0);
	
     gtk_container_add(GTK_CONTAINER(item), box);
     gtk_signal_connect(GTK_OBJECT(button),
			"clicked",
			GTK_SIGNAL_FUNC(prefs_family_toggle_callback),
			ctrls);
     
     gtk_widget_show(button);
     gtk_widget_show(box);
     gtk_widget_show(item);
     dlist = g_list_append(dlist, item);
     gtk_object_set_data(GTK_OBJECT(item),
     			 "list_item_checkbox",
			 button);
     gtk_object_set_data(GTK_OBJECT(item),
			 "list_item_data",
			 lfamilies->name);
     lfamilies = lfamilies->next;
   }

   dlist = g_list_sort(dlist, glist_cmp);
   gtk_tooltips_enable(tooltips);
   gtk_list_append_items(GTK_LIST(arg_get_value(ctrls, "FAMILIES_LIST")), dlist);
   f = arg_get_value(ctrls, "FAMILIES");
   arg_set_value(ctrls, "FAMILIES", -1, families);
   while(f && f->next)
   {
    struct plugin_families * prev;
    efree(&f->name);
    prev = f;
    f = f->next;
    efree(&prev);
   }
}
#endif
