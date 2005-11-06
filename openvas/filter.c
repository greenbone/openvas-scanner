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
#ifdef HAVE_REGEX_SUPPORT
#include <regex.h>
#else
#include "nessus_regex.h"
#endif
#include "error_dialog.h"

#include <gtk/gtk.h>
#include "filter.h"



	
static int filter_on_name = 1;
static int filter_on_description = 0;
static int filter_on_summary = 0;
static int filter_on_author = 0;
static int filter_on_id = 0;
static int filter_on_category = 0;
static int filter_on_cve = 0;
static int filter_on_bid = 0;
static int filter_on_xref = 0;


static void
ask_filter_callback(u1, ctrls)
 GtkWidget * u1;
 struct arglist * ctrls;
{
 GtkWidget * w = arg_get_value(ctrls, "WINDOW");
 gtk_widget_hide(w);
 if(arg_get_value(ctrls,"CANCEL") == u1)
  {
   arg_add_value(ctrls, "FILTER", ARG_STRING, 0, (void*)(-1));
   return;
  }
 else {
 	char * filter = (char*)gtk_entry_get_text(GTK_ENTRY(arg_get_value(ctrls,"ENTRY")));
	filter_on_name = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_NAME"))->active;
	filter_on_description = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_DESCRIPTION"))->active;
	filter_on_summary = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_SUMMARY"))->active;
	filter_on_author = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_AUTHOR"))->active;
	filter_on_id = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_ID"))->active;
	filter_on_category = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_CATEGORY"))->active;
	filter_on_bid = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_BID"))->active;
	filter_on_cve =  GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_CVE"))->active;
	filter_on_xref = GTK_TOGGLE_BUTTON(arg_get_value(ctrls, "FILTER_XREF"))->active;
	arg_add_value(ctrls, "FILTER", ARG_STRING,filter ? strlen(filter):0, filter);
      }
}

static struct arglist *
build_filter_dlog()
{
 GtkWidget * w, * label, *sep, * button, *entry;
 GtkWidget * box, *hbox, *frame,*vbox;
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 
 
 w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_window_set_title(GTK_WINDOW(w), "Filter plugins...");
 
 gtk_container_border_width(GTK_CONTAINER(w), 6);
 arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, w);
 gtk_window_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
 gtk_widget_realize(w);
 
 box = gtk_vbox_new(FALSE, 6);
 gtk_container_add(GTK_CONTAINER(w), box);
 gtk_widget_show(box);

 
 
 label = gtk_label_new("Filter plugins...");
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 1);
 gtk_widget_show(label);
 sep = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
 gtk_widget_show(sep);
 sep = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
 gtk_widget_show(sep);
 
 hbox = gtk_hbox_new(FALSE, FALSE);
 gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 3);
 label = gtk_label_new("Pattern : ");
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 6);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 arg_add_value(ctrls,"ENTRY", ARG_PTR, -1, entry);
 gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 6);
 gtk_widget_show(entry);
 gtk_widget_show(hbox);
 
 frame = gtk_frame_new("Filter on : ");
 gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 6);
 vbox = gtk_vbox_new(FALSE, FALSE);
 gtk_container_border_width(GTK_CONTAINER(frame), 6);
 gtk_container_add(GTK_CONTAINER(frame), vbox);
 gtk_widget_show(vbox);
 
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("Name");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_NAME", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_name);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("Description");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_DESCRIPTION", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_description);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("Summary");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_SUMMARY", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_summary);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("Author");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_AUTHOR", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_author);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("ID number");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_ID", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_id);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("Category");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_CATEGORY", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_category);
 /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("CVE");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_CVE", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_cve);
  /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("BID");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_BID", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_bid);
 
  /*--------------------------------------------*/
 button = gtk_check_button_new_with_label("XREF");
 gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 3);
 gtk_widget_show(button);
 arg_add_value(ctrls, "FILTER_XREF", ARG_PTR, -1, button);
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), filter_on_xref);
 
 
 gtk_widget_show(frame);
 
 hbox = gtk_hbox_new(TRUE, 6);
 gtk_box_pack_start(GTK_BOX(box), hbox,FALSE, FALSE, 6);
 gtk_widget_show(hbox);
 
 button = gtk_button_new_with_label("OK");
 gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 6);
 GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
 gtk_widget_grab_default(button);
 gtk_widget_show(button);
 
 gtk_signal_connect(GTK_OBJECT(button), "clicked", 
 		    (GtkSignalFunc)ask_filter_callback, 
		    (void*)ctrls);
		    
		    
 button = gtk_button_new_with_label("Cancel");
 arg_add_value(ctrls, "CANCEL", ARG_PTR, -1, button);
 gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 6);
 gtk_signal_connect(GTK_OBJECT(button), "clicked", 
 		    (GtkSignalFunc)ask_filter_callback, 
		    (void*)ctrls);
 gtk_widget_show(button);;
 
 gtk_widget_show(w);
 gtk_grab_add(w);
 return ctrls;
} 
 
 
int ask_filter(filter)
 struct plugin_filter * filter;
{
 struct arglist * ctrls = build_filter_dlog();
 char * ret;
  while(!arg_get_value(ctrls, "FILTER"))
  while(gtk_events_pending()){
  	gtk_main_iteration();
#if !defined(WIN32) && !defined(_WIN32)
	usleep(10000);
#endif
	}	

 ret = arg_get_value(ctrls, "FILTER");
 if(ret == (void*)-1)filter->pattern = NULL;
 else filter->pattern = estrdup(ret);
 
 filter->filter_on_name = filter_on_name;
 filter->filter_on_description = filter_on_description;
 filter->filter_on_summary = filter_on_summary;
 filter->filter_on_author = filter_on_author;
 filter->filter_on_id = filter_on_id;
 filter->filter_on_category = filter_on_category;
 filter->filter_on_cve = filter_on_cve;
 filter->filter_on_bid = filter_on_bid;
 filter->filter_on_xref = filter_on_xref;
 
 gtk_widget_destroy(arg_get_value(ctrls, "WINDOW"));
 arg_free(ctrls);
 return 0;
}

#else
/*
 * Not used yet
 */
char *
ask_filter()
{
 char * ret = emalloc(1024);
 printf("Enter a new filter : ");
 fgets(ret, 1023, stdin);
 return ret;
}
#endif /* defined(USE_GTK) */

#ifndef NS
#define NS 1024
#endif


#ifdef USE_GTK
static int match(str, pat)
 char * str, * pat;
{
  regex_t re;
  regmatch_t subs[NS];

  re_set_syntax(RE_SYNTAX_POSIX_EGREP);
  if(regcomp(&re, pat, REG_EXTENDED|REG_ICASE))
  {
   show_error("Invalid regular expression");
   bzero(pat, strlen(pat));
   return -1;
  }
  if(regexec(&re, str, (size_t)NS, subs, 0) == 0)
  {
    regfree(&re);
    return 0;
  }
   regfree(&re);
   return 1;
}
#endif

int 
filter_plugin(filter, plugin)
 struct plugin_filter *filter;
 struct arglist * plugin;
{
 int ret = 0; /* Don't filter it */
 
#ifdef USE_GTK
 char * name = arg_get_value(plugin, "NAME");
 char * description = arg_get_value(plugin, "DESCRIPTION");
 char * summary = arg_get_value(plugin, "SUMMARY");
 char * author = arg_get_value(plugin, "COPYRIGHT");
 char * id = arg_get_value(plugin, "ASC_ID");
 char * category = arg_get_value(plugin, "CATEGORY");
 char * cve = arg_get_value(plugin, "CVE_ID");
 char * bid = arg_get_value(plugin, "BUGTRAQ_ID");
 char * xref = arg_get_value(plugin, "XREFS");
 
 if(!filter->pattern || !strlen(filter->pattern))
  return 0;
 
 if(filter->filter_on_name)
	 {
	  ret = match(name, filter->pattern);
	  if(!ret)return 0;
	 }
 if(filter->filter_on_description)
	{
	  ret = match(description, filter->pattern);
	  if(!ret)return 0;
	}
 if(filter->filter_on_summary)
 	{
	 ret = match(summary, filter->pattern);
	 if(!ret)return 0;
	 }
 if(filter->filter_on_author)
	 {
	  ret = match(author, filter->pattern);
	  if(!ret)return 0;
	 }
 if(filter->filter_on_category)
	 {
	  ret = match(category, filter->pattern);
	  if(!ret)return 0;
	 }
	 
 if( filter->filter_on_cve  )
 	{
	 if (cve != NULL ) ret = match(cve, filter->pattern);
	 else ret = 0;
	 if(!ret)return 0;
	}
	
 if( filter->filter_on_bid )
 	{
	 if (bid != NULL ) ret = match(bid, filter->pattern);
	 else ret = 0;
	 
	 if(!ret)return 0;
	}		
	
 if( filter->filter_on_xref ) 
 	{
	 if(xref != NULL ) ret = match(xref, filter->pattern);
	 else ret = 0;
	 
	 if (!ret) return 0;
	 }	 
 if(filter->filter_on_id)ret= match(id, filter->pattern);
#endif
  return ret;
}

