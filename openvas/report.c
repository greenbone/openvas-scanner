/* Nessus
 * Copyright (C) 1998, 1999, 2000 Renaud Deraison
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

/* Pluto 26.6.00:
 *
 * changed infos_and_holes_to into findings_to 
 */

#include <includes.h>
#include "globals.h"
#ifdef USE_GTK

#define MAX_ITEMS_IN_LIST 500 	   /* only show the 500 first entries */
#define MAX_ITEMS_IN_LIST_ASC "500"
#define TOO_MANY_ITEMS "Only the first "MAX_ITEMS_IN_LIST_ASC" entries will be shown.\nExport the report to another format for a complete version"


#include "gtk-compat.h"
#include <gtk/gtk.h>
#include "xstuff.h"
#include "xpm/yellow.xpm"
#include "xpm/orange.xpm"
#include "xpm/red.xpm"
#include "xpm/white.xpm"
#include "report_ng.h"
#endif

#include "report.h"
#include "families.h"
#include "nsr_output.h"
#include "html_output.h"
#include "html_graph_output.h"
#include "report_utils.h"
#include "error_dialog.h"
#include "latex_output.h"
#include "text_output.h"
#include "xml_output.h"
#include "globals.h"
#include "comm.h"
#include "backend.h"

#include "prefs_dialog/prefs_target.h"

#define SAVE_NSR 0
#define SAVE_HTML 1
#define SAVE_TEXT 2
#define SAVE_LATEX 3
#define SAVE_HTML_GRAPH 4
#define SAVE_XML 5
#define SAVE_MAX SAVE_XML
 
#ifdef USE_GTK

static void save_report_ask(GtkWidget *, GtkWidget *);
static void save_report(GtkWidget *, GtkWidget *);
GtkWidget * report_to_tree(struct arglist *, GtkWidget *);
static void do_create_report_window(struct arglist *, int, int);
#endif



#ifdef USE_GTK

static void 
report_click(GtkWidget * list, GtkWidget * data)
{
 GtkWidget * window = gtk_object_get_data(GTK_OBJECT(list), "window");
 GtkWidget * box = gtk_object_get_data(GTK_OBJECT(list), "box");
 GList * dlist = GTK_LIST(list)->selection;
 GtkObject * item;
 struct arglist * report;
 GtkWidget * tree = NULL;
 GtkWidget * old_tree = NULL;
 int new_tree = 0;
 if(!dlist)
  return;
  
 item = GTK_OBJECT(dlist->data);
 report = gtk_object_get_data(item, "results");
 
 if(report){
 	tree = gtk_object_get_data(item, "tree");
	if(!tree)
	{
 	 tree = report_to_tree(report->value, window);
	 gtk_object_set_data(item, "tree", tree);
	 new_tree++;
	}
    }
    
    			
 if(tree)
 {
   old_tree = gtk_object_get_data(GTK_OBJECT(box), "tree");
   if(old_tree){
   	GtkAdjustment * adj;
   	gtk_widget_hide(old_tree);
	adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(window));
   	gtk_adjustment_set_value(adj, 0);
	}
    if(new_tree)
    {
     gtk_box_pack_start(GTK_BOX(box), tree, TRUE, TRUE, 0);
    } 
     gtk_widget_show(tree);
#if GTK_VERSION > 10
    gtk_widget_map(tree);
#endif  
  
  gtk_widget_realize(tree);
  gtk_object_set_data(GTK_OBJECT(box), "tree", tree);
 }
}




static
GtkWidget * summary_host_label(name, window, severity)
 char * name;
 GtkWidget * window;
 int severity;
{
 GtkWidget * label;
 GtkWidget * hbox;
 char ** pixdata = NULL;
 GtkStyle * style;
 GtkWidget * pixmapwid;
 switch(severity)
 {
  case HOLE_PRESENT :
  	pixdata = red_dot_xpm;
	break;
  case WARNING_PRESENT :
  	pixdata = orange_dot_xpm;
	break;
  case NOTE_PRESENT :
  	pixdata = yellow_dot_xpm;
	break;
  default :
  	pixdata = white_dot_xpm;
	break;
 }
 style = gtk_widget_get_style(window);
 pixmapwid = make_pixmap(window, &style->bg[GTK_STATE_NORMAL], pixdata);
 hbox = gtk_hbox_new(FALSE,FALSE);
               
 label = gtk_label_new(name);
 gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
 gtk_box_pack_start(GTK_BOX(hbox), pixmapwid, FALSE, FALSE, 0);
 gtk_widget_show(pixmapwid);
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);
 gtk_widget_show(label);
 return hbox;
}
static void 
fill_summary_box(box, scrolled, results, sorted)
 GtkWidget * box, * scrolled;
 struct arglist * results;
 int sorted;
{
 GtkWidget * label = gtk_label_new("Summary");
 GtkWidget * sep = gtk_hseparator_new();
 char * data = emalloc(4096);
 GtkWidget * window;
 GtkWidget * list;
 GtkWidget * hbox;
 
 int count;
 
 GList * dlist = NULL;
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
 gtk_widget_show(sep);
 
 if (sorted) sprintf(data, "Number of ports found : %d", arglist_length(results));
 else sprintf(data, "Number of hosts tested : %d", arglist_length(results));
 label = gtk_label_new(data);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 sprintf(data, "Found %d security holes", number_of_holes(results));

 label = gtk_label_new(data);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 sprintf(data, "Found %d security warnings", number_of_warnings(results));
 label = gtk_label_new(data);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 sprintf(data, "Found %d security notes", number_of_notes(results));
 label = gtk_label_new(data);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 sep = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
 gtk_widget_show(sep);
 
 window = gtk_scrolled_window_new(NULL,NULL);

 gtk_box_pack_start(GTK_BOX(box), window, TRUE, TRUE, 0);

 
 list = gtk_list_new();
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(window),list);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(window), list);
#endif
 gtk_widget_show(list);
 gtk_object_set_data(GTK_OBJECT(list), "window", scrolled);
 hbox = gtk_hbox_new(FALSE, FALSE);
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(scrolled),hbox);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled), hbox);
#endif 
  gtk_object_set_data(GTK_OBJECT(list), "box", hbox);
 gtk_widget_show(hbox);
 gtk_widget_realize(scrolled);
  gtk_signal_connect(GTK_OBJECT(list),
		     "selection_changed",
		     GTK_SIGNAL_FUNC(report_click),
		     NULL);
		     
  if (arglist_length(results) > MAX_ITEMS_IN_LIST)
    show_warning(TOO_MANY_ITEMS);
 count = MAX_ITEMS_IN_LIST ;
 while(results && results->next && --count)
 {
  GtkWidget * item;
  int severity;
  
  
  item = gtk_list_item_new();
  gtk_object_set_data(GTK_OBJECT(item), "results", results->value);
  
  if (number_of_holes_by_host(results->value)) severity = HOLE_PRESENT;
  else if (number_of_warnings_by_host(results->value)) severity = WARNING_PRESENT;
  else if (number_of_notes_by_host(results->value)) severity = NOTE_PRESENT;
  else severity = 0;

  label = summary_host_label(results->name, scrolled, severity);
  gtk_container_add(GTK_CONTAINER(item), label);
  gtk_widget_show(label);
  dlist = g_list_append(dlist, item);
  gtk_widget_show(item);
  results = results->next;
 }
 gtk_list_append_items(GTK_LIST(list), dlist);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(window), 
  		 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC); 

 gtk_widget_show(window);
 gtk_widget_realize(window);
 free(data);
}

static void create_report_window(args, interrupted_test)
  struct arglist * args;
  int interrupted_test;
{

  do_create_report_window(args, interrupted_test, 0);
}
static void create_report_window_by_port(nul, reportw)
  GtkWidget * nul;
  GtkWidget * reportw;
{
 struct arglist * hosts = gtk_object_get_data(GTK_OBJECT(reportw), "hosts");
 hosts = sort_by_port(hosts);
 hosts = sort_dangerous_hosts(hosts);
 do_create_report_window(hosts, 0, 1);
   
}

/*
 * Creation of the reporting window
 */
static void do_create_report_window(args, interrupted_test, sorted_by_port)
  struct arglist * args;
  int interrupted_test;
  int sorted_by_port;
{
  
  GtkWidget * window;
  GtkWidget * widget;
  GtkWidget * vbox;
  GtkWidget * hbox;
  GtkWidget * paned;
  
  GtkWidget * button;
  GtkWidget * by_port;
  GtkWidget * optionmenu;
  GtkWidget * type;
  GtkWidget * menu;
  GtkWidget * summary_box;
  struct arglist * report = args;
  struct arglist * hosts;
  
  if(!args || !args->next){
	if(!interrupted_test)
	{
#ifdef ENABLE_SAVE_KB
	if(DetachedMode)
	{
	 struct arglist * arg;
	 show_info("nessusd is now scanning the remote network \n\
in detached mode");
  	 /*
	  * Restore the login button
	  */
	 arg = arg_get_value(MainDialog, "AUTH");
	 gtk_widget_hide(arg_get_value(arg, "CONNECTED"));
	 gtk_widget_hide(arg_get_value(arg, "BUTTON_LOG_OUT"));
	 gtk_widget_show(arg_get_value(arg, "BUTTON_LOG_IN"));
	 GlobalSocket = -1;
	}
	else
#endif		
  	show_info("No problem has been found, or none of the \
hosts tested was alive");
	}
	else
	{
	 show_warning("nessusd abruptly shut the communication down.\n\
No problem has been found at this stage of the test");
	 }	
	return;
	}
  else if(interrupted_test)
  {
  	show_warning("nessusd closed the communication before the end of the test !");
  }
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_VERSION > 10
  gtk_window_set_default_size(GTK_WINDOW(window), 640,480);
#else
  gtk_widget_set_usize(GTK_WIDGET(window), 640, 480);
#endif
  gtk_widget_realize(window);
  gtk_signal_connect(GTK_OBJECT(window), "destroy", 
     	GTK_SIGNAL_FUNC(close_window), window);
  gtk_signal_connect(GTK_OBJECT(window), "delete_event", 
  	GTK_SIGNAL_FUNC(delete_event), window);
       
  if (sorted_by_port)  gtk_window_set_title(GTK_WINDOW(window), "Nessus Report by port");
  else   gtk_window_set_title(GTK_WINDOW(window), "Nessus Report");
       
  gtk_container_border_width(GTK_CONTAINER(window), 10);
  
  paned = gtk_hpaned_new();
#if GTK_VERSION <= 11  
  gtk_paned_gutter_size(GTK_PANED(paned), 15);
#else
  gtk_paned_set_gutter_size(GTK_PANED(paned), 15);
#endif  
  gtk_container_add(GTK_CONTAINER(window), paned);
  gtk_widget_show(paned);
  
  vbox = gtk_vbox_new(FALSE, 0);
 
   summary_box = gtk_vbox_new(FALSE, 5);
  
  gtk_paned_add1(GTK_PANED(paned), summary_box);
  gtk_paned_add2(GTK_PANED(paned), vbox);
  

  
  
  widget = gtk_scrolled_window_new(NULL,NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(widget), 
  		 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
 
  gtk_box_pack_start(GTK_BOX(vbox), widget, TRUE, TRUE, 5);
  gtk_widget_show(widget);
  
  fill_summary_box(summary_box, widget, args, sorted_by_port);
  gtk_widget_show(summary_box);
  
  
  hosts = emalloc(sizeof(struct arglist));
 
  gtk_widget_realize(widget);
  
  hbox = gtk_hbox_new(TRUE,10);
 
  if (!sorted_by_port) {
    by_port = gtk_button_new_with_label("Sort by port");
    gtk_signal_connect(GTK_OBJECT(by_port),"clicked",
                    GTK_SIGNAL_FUNC(create_report_window_by_port),by_port); 
		    
    gtk_box_pack_start(GTK_BOX(hbox), by_port, TRUE, TRUE, 0);
    gtk_widget_show(by_port);

  gtk_object_set_data(GTK_OBJECT(by_port), "hosts", report);

  button = gtk_button_new_with_label("Save as...");
  
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  
  optionmenu = gtk_option_menu_new();
  menu = gtk_menu_new();
  gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu), menu);
  gtk_widget_show(menu);
  
  gtk_object_set_data(GTK_OBJECT(menu), "hosts", report);
  
  type = gtk_menu_item_new_with_label("Save as NSR");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_NSR);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  type = gtk_menu_item_new_with_label("Save as HTML");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_HTML);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  type = gtk_menu_item_new_with_label("Save as LaTeX");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_LATEX);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  type = gtk_menu_item_new_with_label("Save as ASCII text");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_TEXT);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);

#ifndef _NO_PIES
  type = gtk_menu_item_new_with_label("Save as HTML with Pies and Graphs");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_HTML_GRAPH);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
#endif  
 
  type = gtk_menu_item_new_with_label ("Save as XML (experimental)");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_XML);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  gtk_signal_connect(GTK_OBJECT(button),"clicked",
                    GTK_SIGNAL_FUNC(save_report_ask),menu); 
  gtk_box_pack_start(GTK_BOX(hbox), optionmenu, TRUE, TRUE, 0);
  gtk_widget_show(optionmenu);
  gtk_option_menu_set_history(GTK_OPTION_MENU(optionmenu), 0);
  }
  button = gtk_button_new_with_label("Close");
  gtk_signal_connect(GTK_OBJECT(button),"clicked",
                    GTK_SIGNAL_FUNC(close_window),(void *) window); 
  gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  
  gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
 
  gtk_widget_show(hbox);
  gtk_widget_show(vbox);
  gtk_widget_show(window);
}



static
GtkWidget * data_to_tree_build_label(name)
 char * name;
{
 GtkWidget * label;
 GtkWidget * hbox;
 
 hbox = gtk_hbox_new(FALSE,FALSE);
               
 label = gtk_label_new(name);
 gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 15);
 gtk_widget_show(label);
 return hbox;
}

static 
GtkWidget * data_to_tree(arglist)
 struct arglist * arglist;
{
 GtkWidget * tree;
 int count = MAX_ITEMS_IN_LIST;
 
 if(!(arglist && arglist->next))
  return NULL;
 
 tree = gtk_tree_new();
 
 if(arglist_length(arglist) > count)
  show_warning(TOO_MANY_ITEMS);

 while(arglist && arglist->next && count--)
 {
  GtkWidget * tree_item;
  GtkWidget * report_data = data_to_tree_build_label(arglist->value);
  
  tree_item = gtk_tree_item_new();
 
  gtk_container_add(GTK_CONTAINER(tree_item), report_data);
  gtk_widget_show(report_data);
  
  gtk_tree_append(GTK_TREE(tree), tree_item);
  gtk_tree_item_expand(GTK_TREE_ITEM(tree_item));
  gtk_tree_item_collapse(GTK_TREE_ITEM(tree_item));
 
  gtk_widget_show(tree_item);
  arglist = arglist->next;
  }
 
 return tree;
}


static
GtkWidget * findings_to_tree_build_label(name, severity)
 char * name;
 int severity;
{
 GtkWidget * label;
 GtkWidget * hbox;
 
 hbox = gtk_hbox_new(FALSE,FALSE);
               
 label = gtk_label_new(name);
 gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 15);
 gtk_widget_show(label);
 return hbox;
}



static
GtkWidget * findings_to_tree(arglist, window)
 struct arglist * arglist;
 GtkWidget * window;
{
 int level = is_there_any_hole(arglist);
 GtkWidget * tree;
 GtkWidget * tree_item;
 GtkWidget * label;
 if(!level)
  return NULL;
 tree = gtk_tree_new();
 if(arg_get_value(arglist, "NOTE"))
 {
  GtkWidget * subtree;

  tree_item = gtk_tree_item_new();
  label = findings_to_tree_build_label("Security note", 1);
  gtk_container_add(GTK_CONTAINER(tree_item), label);
  gtk_widget_show(label);
  gtk_tree_append(GTK_TREE(tree), tree_item);
  subtree = data_to_tree(arg_get_value(arglist, "NOTE"));
  if(subtree)
  {
   gtk_tree_item_set_subtree(GTK_TREE_ITEM(tree_item), subtree);
   gtk_widget_show(subtree);
  }
  gtk_tree_item_expand(GTK_TREE_ITEM(tree_item));
  gtk_tree_item_collapse(GTK_TREE_ITEM(tree_item));
 
  gtk_widget_show(tree_item);
 }
 
 if(arg_get_value(arglist, "INFO"))
 {
  GtkWidget * subtree;
  tree_item = gtk_tree_item_new();
  label = findings_to_tree_build_label("Security warnings", 1);
  gtk_container_add(GTK_CONTAINER(tree_item), label);
  gtk_widget_show(label);
  gtk_tree_append(GTK_TREE(tree), tree_item);
  subtree = data_to_tree(arg_get_value(arglist, "INFO"));
  if(subtree)
  {
   gtk_tree_item_set_subtree(GTK_TREE_ITEM(tree_item), subtree);
   gtk_widget_show(subtree);
  }
  gtk_tree_item_expand(GTK_TREE_ITEM(tree_item));
  gtk_tree_item_collapse(GTK_TREE_ITEM(tree_item));
 
  gtk_widget_show(tree_item);
 }
 
 if(arg_get_value(arglist, "REPORT"))
 {
  GtkWidget * subtree;
  tree_item = gtk_tree_item_new();
  label = findings_to_tree_build_label("Security holes", 2);
  gtk_container_add(GTK_CONTAINER(tree_item), label);
  gtk_widget_show(label);
  gtk_tree_append(GTK_TREE(tree), tree_item);
  subtree = data_to_tree(arg_get_value(arglist, "REPORT"));
  if(subtree)
  {
   gtk_tree_item_set_subtree(GTK_TREE_ITEM(tree_item), subtree);
   gtk_widget_show(subtree);
  }
  gtk_tree_item_expand(GTK_TREE_ITEM(tree_item));
  gtk_tree_item_collapse(GTK_TREE_ITEM(tree_item));
  gtk_widget_show(tree_item);
 }
 
 return tree;  
}

static
GtkWidget * report_build_label(name, window, severity)
 char * name;
 GtkWidget * window;
 int severity;
{
 GtkWidget * label;
 GtkWidget * hbox;
 char ** pixdata = NULL;
 GdkPixmap * pixmap;
 GtkStyle * style;
 GdkBitmap * mask;
 GtkWidget * pixmapwid;
 switch(severity)
 {
  case HOLE_PRESENT :
  	pixdata = red_dot_xpm;
	break;
  case WARNING_PRESENT :
  	pixdata = orange_dot_xpm;
	break;
  case NOTE_PRESENT :
  	pixdata = yellow_dot_xpm;
	break;
  default :
  	pixdata = white_dot_xpm;
	break;
 }
 style = gtk_widget_get_style(window);
 pixmap = gdk_pixmap_create_from_xpm_d(window->window, &mask,
            &style->bg[GTK_STATE_NORMAL],(gchar **)pixdata); 
            
 pixmapwid = gtk_pixmap_new(pixmap, mask);
 hbox = gtk_hbox_new(FALSE,FALSE);
               
 label = gtk_label_new(name);
 gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
 gtk_box_pack_start(GTK_BOX(hbox), pixmapwid, FALSE, FALSE, 0);
 gtk_widget_show(pixmapwid);
 gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);
 gtk_widget_show(label);
 return hbox;
}


GtkWidget * report_to_tree(arglist, window)
  struct arglist * arglist;
  GtkWidget * window;
{
 GtkWidget * tree; 
 int count = MAX_ITEMS_IN_LIST; 
 tree = gtk_tree_new();
 

 if(arglist_length(arglist) > count)
  show_warning(TOO_MANY_ITEMS);

 while(arglist && arglist->next && count--)
 {
  GtkWidget * tree_item;
  GtkWidget * label;
  GtkWidget * subtree;
  
  
  tree_item = gtk_tree_item_new();
  
   /*
    * Make label here
    */
    
   label = report_build_label(arglist->name, window, is_there_any_hole(arglist->value));
   gtk_container_add(GTK_CONTAINER(tree_item), label);
   gtk_widget_show(label);
   gtk_tree_append(GTK_TREE(tree), tree_item);
   
   if((subtree = findings_to_tree(arglist->value, window)))
   {
    gtk_tree_item_set_subtree(GTK_TREE_ITEM(tree_item), subtree);
    gtk_widget_show(subtree);
   }
   gtk_tree_item_expand(GTK_TREE_ITEM(tree_item));
   gtk_tree_item_collapse(GTK_TREE_ITEM(tree_item));
 
   gtk_widget_show(tree_item);
   arglist = arglist->next;
 }
  return(tree);
}    
#endif

/* reports back the highest number */
int is_there_any_hole(arglist)
 struct arglist * arglist;
{
 int ret = 0;
 /* Pluto 25.6.00: with three level of return, real sort */
 while(arglist && arglist->next && (ret!=HOLE_PRESENT))
 {
  int tmp = 0;
  int tmp2 = 0;
  if(!arglist->name)
   {
    arglist = arglist->next;
    continue;
   }
  if(!strcmp(arglist->name, "REPORT"))tmp2 = HOLE_PRESENT;
  else if(!strcmp(arglist->name, "INFO"))tmp2 = WARNING_PRESENT;
  else if(!strcmp(arglist->name, "NOTE"))tmp2 = NOTE_PRESENT;
  /*
   * Check in the sublist
   */
  if(arglist->type == ARG_ARGLIST)tmp = is_there_any_hole(arglist->value);
  if(tmp >= tmp2)tmp2 = tmp;
  if(tmp2 >= ret)ret = tmp2;
  arglist = arglist->next;
 }
 return(ret);
}

#ifdef USE_GTK


/*
 *  Main function of the holes reporter
 */
void 
report_tests(hosts, interrupted_test)
 struct arglist * hosts;
 int interrupted_test;
{

  gtk_widget_show(arg_get_value(MainDialog, "WINDOW"));
#ifdef ENABLE_SAVE_TESTS
  if(comm_server_restores_sessions(Prefs))
	  {
	  harglst * oldSessions = Sessions;
	  Sessions = comm_get_sessions();
	  prefs_dialog_target_fill_sessions(arg_get_value(MainDialog, "TARGET"),
	  		                    Sessions);
	  if(oldSessions)harg_close_all(oldSessions);				    
	 }
#endif  
  hosts = sort_dangerous_hosts(hosts);
  create_report_window(hosts, interrupted_test);
}

/*
 * Opens the report
 */
void open_report(GtkWidget * dontcare, GtkWidget *nsr)
{
int be = backend_import_report((char*)gtk_file_selection_get_filename(GTK_FILE_SELECTION(nsr)));
if(be >= 0)report_tests_ng(be, 0);
}

/*
 * Menu selection to open the report
 */
void open_report_selectfile()
{
 GtkWidget * nsr;
 nsr = gtk_file_selection_new ("Load file");
 /*
  * CWD
  */
 gtk_file_selection_set_filename (GTK_FILE_SELECTION(nsr), ".");
 gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (nsr)->ok_button),
                               "clicked", (GtkSignalFunc) open_report,(void *) nsr );

 gtk_signal_connect_object (GTK_OBJECT (GTK_FILE_SELECTION(nsr)->ok_button),
   					  "clicked", GTK_SIGNAL_FUNC (gtk_widget_destroy),
   					  (gpointer) nsr);

 gtk_signal_connect_object (GTK_OBJECT (GTK_FILE_SELECTION(nsr)->cancel_button),
   					  "clicked", GTK_SIGNAL_FUNC (gtk_widget_destroy),
   					  (gpointer) nsr);

 gtk_widget_show(nsr);
}

/*
 * Saves the report
 */
static void 
save_report_ask(nul,menu)
  GtkWidget * nul;
  GtkWidget * menu;
{
 GtkWidget * active;
 GtkWidget * filew;
 char * filename;
 char * tmp;
 char * hostname;
 int value;
 char * suffixes[] = {".nsr", ".html", ".txt", ".tex", "", ".xml"};
 struct arglist * hosts;
 
 active = gtk_menu_get_active(GTK_MENU(menu));
 value = (int)gtk_object_get_data(GTK_OBJECT(active), "type");
 hosts = gtk_object_get_data(GTK_OBJECT(menu), "hosts");
 if(!hosts)
 {
  fprintf(stderr, "Error - NULL hosts in save_report_ask()\n");
  return ;
 }
 if(value < 0)value = 0;
 if(value > SAVE_MAX)value = SAVE_MAX;
 

 hostname = emalloc(strlen(hosts->name)+1);
 strncpy(hostname, hosts->name, strlen(hosts->name));
 
 while((tmp = strchr(hostname, '.')))tmp[0]='_';
 
 filename = emalloc(strlen(hosts->name)+7);
 sprintf(filename, "%s%s", hostname, suffixes[value]);
 efree(&hostname);
 
 filew = gtk_file_selection_new ("Save file");
 gtk_object_set_data(GTK_OBJECT(filew), "type", (void*)value);
 gtk_object_set_data(GTK_OBJECT(filew), "hosts", hosts);
 gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (filew)->ok_button),
                               "clicked", (GtkSignalFunc) save_report, filew );
           
 gtk_signal_connect /*_object*/ (GTK_OBJECT (GTK_FILE_SELECTION
           (filew)->cancel_button),
             "clicked", (GtkSignalFunc)close_window, (void *)filew);
 gtk_file_selection_set_filename (GTK_FILE_SELECTION(filew), filename);
           
 gtk_widget_show(filew);
}

/*
 * save_report
 *
 * this function is called when the user
 * clicks on the 'save' item of the file
 * menu...
 */
static void 
save_report(nul,filew)
    GtkWidget * nul;

    GtkWidget * filew;
{
 char * fname = (char*)gtk_file_selection_get_filename(GTK_FILE_SELECTION(filew));
 int type = (int)gtk_object_get_data(GTK_OBJECT(filew), "type");
 struct arglist * hosts = gtk_object_get_data(GTK_OBJECT(filew), "hosts");
 
 gtk_widget_hide(filew);
 hosts = sort_dangerous_hosts(hosts);
 switch(type)
 {
  case SAVE_HTML :
  	arglist_to_html(hosts, fname);
	break;
 case SAVE_XML :
	arglist_to_xml(hosts, fname);
	break;
  	
 case SAVE_LATEX :
 	arglist_to_latex(hosts, fname);
	break;
 case SAVE_TEXT :
 	arglist_to_text(hosts, fname);
	break;	
#ifndef _NO_PIES
 case SAVE_HTML_GRAPH :
 	arglist_to_html_graph(hosts, fname);
	break;
#endif /* _NO_PIES */
 case SAVE_NSR:
 default :
  	arglist_to_file(hosts, fname);
	break;
 }
 arg_free(hosts);
 gtk_widget_destroy(filew);
}
#endif
