/* Nessus
 * Copyright (C) 1998 - 2003 Renaud Deraison
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
 * Modified by Axel Nennker <axel@nennker.de> to simplify the code 
 * and to stop "gcc -Wall" from whining. 20020306
 */  
 
 /*
  * report_ng is the new generation of GUI reporter
  *
  *
  * ISSUES :
  *	- "save/export" menu
  *	- when sort keys are changed, parent->selection should
  *	  be used to refill the current list
  *
  */

#include <includes.h>
#ifdef USE_GTK
#include <gtk/gtk.h>
#include "xstuff.h"
#include "globals.h"

#include "xpm/computer.xpm"
#include "xpm/network.xpm"
#include "xpm/warning_small.xpm"
#include "xpm/info_small.xpm"
#include "xpm/error_small.xpm"
#include "xpm/nothing.xpm"
#include "error_dialog.h"

#include "data_mining.h"
#include "report_save.h"

#include "backend.h"

#define _(x) x
#define n(x) (x ? x:"")

static GtkWidget * Lists[5];


static void subnets_fill(int, GtkWidget *);
static void subnets_empty(GtkWidget*);


static void hosts_fill(int, GtkWidget*);
static void hosts_empty(GtkWidget*);

static void ports_fill(int, GtkWidget*);
static void ports_empty(GtkWidget*);

static void severity_fill(int, GtkWidget*);
static void severity_empty(GtkWidget*);

static void reports_fill(int, GtkWidget*);
static void reports_empty(GtkWidget*);


static GtkWidget * create_label(int, GtkWidget*, struct subset*);


/*---------------------------------------------------------------------
			UTILITIES
-----------------------------------------------------------------------*/

static void 
replace_data(obj, key, value)
 GtkObject* obj;
 char * key;
 char * value;
{
 char * old = gtk_object_get_data(obj, key);
 if(old)efree(&old);
 gtk_object_set_data(obj, key, value);
}

/* 
 * Our sort functions
 */
static int 
cmp_hosts(a, b)
 char * a, * b;
{
 struct in_addr ia, ib;
 
 if(!a && !b)return 0;
 
 if(!a)
  return 1;
 if(!b)
   return -1;
  
 
 if(inet_aton(a, &ia) == 0)
  return strcmp(a, b);
 
 if(inet_aton(b, &ib) == 0)
 {
  return strcmp(a, b);
 }
 
 return -(ntohl(ia.s_addr) - ntohl(ib.s_addr));
}

static int
cmp_vulns(a, b)
 char * a, * b;
{
 int level_a, level_b;
 

 if(!a) 
  return -1;
 else if(!b)
  return 1;
  
 if(strstr(a, "Hole"))level_a = 3;
 else if(strstr(a, "Warning"))level_a = 2;
 else if(strstr(a, "Note"))level_a = 1;
 else level_a = 0;
 
 
 if(strstr(b, "Hole"))level_b = 3;
 else if(strstr(b, "Warning"))level_b = 2;
 else if(strstr(b, "Note"))level_b = 1;
 else level_b = 0;
 
 return level_a - level_b; 
}


/*
 * Converts a multiple subset (with field AND severity) to 
 * a sorted, uniq'ed one.
 *
 * The function name is set to 'x' just to simplify its use 
 * throughout the code
 */
static struct subset *
x(subset)
 struct subset * subset;
{ 
 cmp_func_t cmps[] = {cmp_hosts, cmp_vulns};
 return subset_uniq(subset_sort(subset, 0, 1, cmps), 0);
}


/*---------------------------------------------------------------------
			       CALLBACKS
 ----------------------------------------------------------------------*/

typedef void (*func_empty_t)(GtkWidget*);
typedef void (*func_fill_t)(int, GtkWidget*);
 
static void
on_menu_item_subnet_selected 		(GtkMenuItem * item,
					 GtkWidget  * list)
{
 char * old_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 char * new_key = gtk_object_get_data(GTK_OBJECT(item), "sort_key");
 char * k;
 
 int idx_list = -1, idx_this_list = -1;
 int i;
 
 if(!strcmp(old_key, new_key))
  {
  return;
  }

  
  
 for(i=0;i<5;i++)
 {
  if(Lists[i] == list){
  	idx_this_list = i;
	break;
	}
 }
 
 
 
 for(i=0;i<5;i++)
 {
  k = gtk_object_get_data(GTK_OBJECT(Lists[i]), "sort_key"); 
  if((new_key != NULL) && (k != NULL) && (strcmp(new_key, k) == 0))
   {
   idx_list = i;
   break;
   }
 }
 

 
  if(idx_list >= 0)
  {
   func_fill_t fill_a, fill_b;
   func_empty_t empty_a, empty_b;
   int min;
   int be;
   GtkWidget * optionmenu;
   GtkWidget * t;
   gtk_object_set_data(GTK_OBJECT(Lists[idx_this_list]), "sort_key", new_key);
   gtk_object_set_data(GTK_OBJECT(Lists[idx_list]), "sort_key", old_key);


   min = idx_this_list > idx_list ? idx_list:idx_this_list;
   fill_a  = (func_fill_t)gtk_object_get_data(GTK_OBJECT(Lists[idx_this_list]), "fill");
   empty_a = (func_empty_t)gtk_object_get_data(GTK_OBJECT(Lists[idx_this_list]), "empty");
   fill_b  = (func_fill_t)gtk_object_get_data(GTK_OBJECT(Lists[idx_list]), "fill");
   empty_b = (func_empty_t)gtk_object_get_data(GTK_OBJECT(Lists[idx_list]), "empty");
   be    = (int)gtk_object_get_data(GTK_OBJECT(Lists[min]), "be");
   
   
  /* printf("Changing option for %d\n", idx_list); */
   optionmenu = gtk_object_get_data(GTK_OBJECT(Lists[idx_list]), "optionmenu");
  
   gtk_option_menu_set_history(GTK_OPTION_MENU(optionmenu),
   					     idx_this_list);
					     
   
   
   if(empty_b)empty_b(Lists[idx_list]);
   if(empty_a)empty_a(Lists[idx_this_list]);
   if(fill_a)fill_a(be, Lists[idx_this_list]);
   if(fill_b)fill_b(be, Lists[idx_list]);
   
   
   t = Lists[idx_list];
   Lists[idx_list] = Lists[idx_this_list];
   Lists[idx_this_list] = t;
   
  }
}		



			 
static void
on_subnets_list_selection_changed      (GtkList         *list,
                                        int be)
{
  char * sort_value;
  GtkWidget * hosts = gtk_object_get_data(GTK_OBJECT(list), "hosts_list");
  char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
  
  
  hosts_empty(hosts);
  
  if(list->selection)
  {
  sort_value = gtk_object_get_data(GTK_OBJECT(list->selection->data), sort_key);
  replace_data(GTK_OBJECT(hosts), "restriction_1_key", estrdup(sort_key));
  replace_data(GTK_OBJECT(hosts), "restriction_1_value", estrdup(sort_value));
  if(sort_value)hosts_fill(be, hosts);
  }
}


static void
on_hosts_list_selection_changed        (GtkList         *list,
                                        int         be)
{
  char * sort_value;
  char * sort_key     = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
  GtkWidget * ports = gtk_object_get_data(GTK_OBJECT(list), "ports_list");
  char * restriction_1_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
  char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value");
  
  ports_empty(ports);
  if(list->selection)
  {
  sort_value = gtk_object_get_data(GTK_OBJECT(list->selection->data), sort_key);
  /* printf("host> set restriction1 = %s (%s)\n", restriction_1_key,restriction_1_value); */
  
  replace_data(GTK_OBJECT(ports), "restriction_1_key", estrdup(restriction_1_key));
  replace_data(GTK_OBJECT(ports), "restriction_1_value", estrdup(restriction_1_value));
  
  replace_data(GTK_OBJECT(ports), "restriction_2_key", estrdup(sort_key));
  replace_data(GTK_OBJECT(ports), "restriction_2_value", estrdup(sort_value));
  if(sort_value)ports_fill(be, ports);
  }
}

static void
on_ports_list_selection_changed (GtkList * list,
				 int be)
{
  char * sort_value;
  char * sort_key     = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
  GtkWidget * severity = gtk_object_get_data(GTK_OBJECT(list), "severity_list");
  char * restriction_1_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
  char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value");
  char * restriction_2_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_key");
  char * restriction_2_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_value");
  
  severity_empty(severity);
  if(list->selection)
  {
  sort_value = gtk_object_get_data(GTK_OBJECT(list->selection->data), sort_key);
  replace_data(GTK_OBJECT(severity), "restriction_1_key", estrdup(restriction_1_key));
  replace_data(GTK_OBJECT(severity), "restriction_1_value", estrdup(restriction_1_value));
 
  replace_data(GTK_OBJECT(severity), "restriction_2_key", estrdup(restriction_2_key));
  replace_data(GTK_OBJECT(severity), "restriction_2_value", estrdup(restriction_2_value));
  
   
  replace_data(GTK_OBJECT(severity), "restriction_3_key", estrdup(sort_key));
  replace_data(GTK_OBJECT(severity), "restriction_3_value", estrdup(sort_value));
  if(sort_value)severity_fill(be, severity);
  }
  
}

static void
on_severity_list_selection_changed (GtkList * list,
				 int be)
{
  char * sort_value;
  char * sort_key     = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
  GtkWidget * reports = gtk_object_get_data(GTK_OBJECT(list), "reports_list");
  char * restriction_1_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
  char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value");
  char * restriction_2_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_key");
  char * restriction_2_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_value");
  char * restriction_3_key = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_key");
  char * restriction_3_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_value");
  
  reports_empty(reports);
  if(list->selection)
  {
  sort_value = gtk_object_get_data(GTK_OBJECT(list->selection->data), sort_key);
  replace_data(GTK_OBJECT(reports), "restriction_1_key", estrdup(restriction_1_key));
  replace_data(GTK_OBJECT(reports), "restriction_1_value", estrdup(restriction_1_value));
 
  replace_data(GTK_OBJECT(reports), "restriction_2_key", estrdup(restriction_2_key));
  replace_data(GTK_OBJECT(reports), "restriction_2_value", estrdup(restriction_2_value));
  
  replace_data(GTK_OBJECT(reports), "restriction_3_key", estrdup(restriction_3_key));
  replace_data(GTK_OBJECT(reports), "restriction_3_value", estrdup(restriction_3_value));
  
  
  replace_data(GTK_OBJECT(reports), "restriction_4_key", estrdup(sort_key));
  replace_data(GTK_OBJECT(reports), "restriction_4_value", estrdup(sort_value));
  if(sort_value)reports_fill(be, reports);
  }
  
  
}
		 

/*----------------------------------------------------------------------
 			INIT FUNCTIONS
------------------------------------------------------------------------*/

static void
subnets_empty(list)
 GtkWidget * list;
{
 GList * items = GTK_LIST(list)->children;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");

 
 if(items)
 {
 while(items)
 {
  char * ptr = gtk_object_get_data(GTK_OBJECT(items->data), sort_key);
  gtk_object_remove_data(GTK_OBJECT(items->data), sort_key);
  efree(&ptr);
  items = items->next;
 }
 gtk_list_remove_items(GTK_LIST(list), GTK_LIST(list)->children);
 }
}





void
subnets_fill(be, list)
 int be;
 GtkWidget * list;
{
 char  * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 struct subset * subset = x(query_backend(be, "SELECT %s,severity FROM results", sort_key ));
 struct subset * walk;
 GList * glist = NULL;
 

 walk = subset;
 while(walk)
 {
  GtkWidget * item = create_label(be, list, walk);
  glist = g_list_append(glist, item);
  gtk_widget_show(item);
  gtk_object_set_data(GTK_OBJECT(item), sort_key, estrdup(subset_value(walk)));
  walk = subset_next(walk);
 }
 gtk_list_append_items(GTK_LIST(list), glist); 
 subset_free(subset);
}



/*-----------------------------------------------------------------------------------------------*/
static void
hosts_fill(be, list)
 int be;
 GtkWidget * list;
{
 char * restriction_1_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
 char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value"); 
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 struct subset * subset = x(query_backend(be, "SELECT %s,severity FROM results WHERE %s = '%s'",
 					 sort_key, n(restriction_1_key), n(restriction_1_value)));
 struct subset * walk = subset;
 GList* glist = NULL;
 
 
 while(walk)
 {
  GtkWidget * item = create_label(be, list, walk);
  glist = g_list_append(glist, item);
  gtk_widget_show(item);
  gtk_object_set_data(GTK_OBJECT(item), sort_key, estrdup(subset_value(walk)));
  walk = subset_next(walk);
 }
 gtk_list_append_items(GTK_LIST(list), glist);
 subset_free(subset);
}

static void
hosts_empty(list)
 GtkWidget * list;
{
 GList * items = GTK_LIST(list)->children;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 
 
 if(items)
 {
 while(items)
 {
  char * ptr = gtk_object_get_data(GTK_OBJECT(items->data), sort_key);
  gtk_object_remove_data(GTK_OBJECT(items->data), sort_key);
  efree(&ptr);
  items = items->next;
 }
 gtk_list_remove_items(GTK_LIST(list), GTK_LIST(list)->children);
 }
}

/*-----------------------------------------------------------------------------------------------*/
static void
ports_fill(be, list)
 int be;
 GtkWidget * list;
{
 char * restriction_1_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
 char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value"); 
  char * restriction_2_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_key");
 char * restriction_2_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_value"); 
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 struct subset * subset = x(query_backend(be, "SELECT %s,severity FROM results WHERE %s = '%s'  AND %s = '%s'", 
 					sort_key, 
					n(restriction_1_key), n(restriction_1_value),
					n(restriction_2_key), n(restriction_2_value)));
 struct subset * walk = subset;
 GList* glist = NULL;
 
 
 while(walk)
 {
  GtkWidget * item = create_label(be, list, walk);
  glist = g_list_append(glist, item);
  gtk_widget_show(item);
  gtk_object_set_data(GTK_OBJECT(item), sort_key, estrdup(subset_value(walk)));
  walk = subset_next(walk);
 }
 gtk_list_append_items(GTK_LIST(list), glist);
 subset_free(subset);
}

static void
ports_empty(list)
 GtkWidget * list;
{
 GList * items = GTK_LIST(list)->children;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 
 
 
 if(items)
 {
 while(items)
 {
  char * ptr = gtk_object_get_data(GTK_OBJECT(items->data), sort_key);
  gtk_object_remove_data(GTK_OBJECT(items->data), sort_key);
  efree(&ptr);
  items = items->next;
 }
 gtk_list_remove_items(GTK_LIST(list), GTK_LIST(list)->children);
 }
}





/*-----------------------------------------------------------------------------------------------*/
static void
severity_fill(be, list)
 int be;
 GtkWidget * list;
{
 char * restriction_1_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
 char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value"); 
 char * restriction_2_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_key");
 char * restriction_2_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_value");
 char * restriction_3_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_key");
 char * restriction_3_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_value");
  
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 struct subset * subset = x(query_backend(be, "SELECT %s,severity FROM results WHERE %s = '%s' AND %s = '%s' AND %s = '%s'", 
 					sort_key, 
					n(restriction_1_key), n(restriction_1_value),
					n(restriction_2_key), n(restriction_2_value),
					n(restriction_3_key), n(restriction_3_value)));
 struct subset * walk = subset;
 GList* glist = NULL;
 
 
 while(walk)
 {
  GtkWidget * item = create_label(be, list, walk);
  glist = g_list_append(glist, item);
  gtk_widget_show(item);
  gtk_object_set_data(GTK_OBJECT(item), sort_key, estrdup(subset_value(walk)));
  walk = subset_next(walk);
 }
 gtk_list_append_items(GTK_LIST(list), glist);
 subset_free(subset);
}


static void
severity_empty(list)
 GtkWidget * list;
{
 GList * items = GTK_LIST(list)->children;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 

 if(items)
 {
 while(items)
 {
  char * ptr = gtk_object_get_data(GTK_OBJECT(items->data), sort_key);
  gtk_object_remove_data(GTK_OBJECT(items->data), sort_key);
  efree(&ptr);
  items = items->next;
 }
 gtk_list_remove_items(GTK_LIST(list), GTK_LIST(list)->children);
 }
}


/*-----------------------------------------------------------------------------------------------*/
static void
reports_fill(be, list)
 int be;
 GtkWidget * list;
{
 char * restriction_1_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_key");
 char * restriction_1_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_1_value"); 
 char * restriction_2_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_key");
 char * restriction_2_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_2_value");
 char * restriction_3_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_key");
 char * restriction_3_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_3_value");
 char * restriction_4_key   = gtk_object_get_data(GTK_OBJECT(list), "restriction_4_key");
 char * restriction_4_value = gtk_object_get_data(GTK_OBJECT(list), "restriction_4_value");
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 struct subset * subset = x(query_backend(be, "SELECT %s,severity FROM results WHERE %s = '%s' AND %s = '%s' AND %s = '%s' AND %s = '%s'", 
 					sort_key, 
					n(restriction_1_key), n(restriction_1_value),
					n(restriction_2_key), n(restriction_2_value),
					n(restriction_3_key), n(restriction_3_value),
					n(restriction_4_key), n(restriction_4_value)));
 struct subset * walk = subset;
 GList* glist = NULL;
 
 
 while(walk)
 {
  GtkWidget * item = create_label(be, list, walk);
  glist = g_list_append(glist, item);
  gtk_widget_show(item);
  gtk_object_set_data(GTK_OBJECT(item), sort_key, estrdup(subset_value(walk)));
  walk = subset_next(walk);
  if(walk)
  {
   GtkWidget *widget = gtk_list_item_new();
   GtkWidget * sep;
   sep = gtk_hseparator_new();
   gtk_container_add(GTK_CONTAINER(widget), sep);
   gtk_widget_show(sep);
   gtk_widget_show(widget);
   glist = g_list_append(glist, widget);
  }
 }
 gtk_list_append_items(GTK_LIST(list), glist);
 subset_free(subset);
}


static void
reports_empty(list)
 GtkWidget * list;
{
 GList * items = GTK_LIST(list)->children;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 
 
 if(items)
 {
 while(items)
 {
  char * ptr = gtk_object_get_data(GTK_OBJECT(items->data), sort_key);
  gtk_object_remove_data(GTK_OBJECT(items->data), sort_key);
  efree(&ptr);
  items = items->next;
 }
 gtk_list_remove_items(GTK_LIST(list), GTK_LIST(list)->children);
 }
}



/*=======================================================================


		SAVING THE CURRENT REPORT
		
		
========================================================================*/





/* 
 * Ask if the user wants to save, not save or cancel
 */


/*
 * Saving the report
 */
int
report_close_window(window, event, data)
 GtkWidget * window;
 GdkEvent * event;
 gpointer data;
{
 return 0;
}

int
report_delete_window(window, event, data)
 GtkWidget * window;
 GdkEvent * event;
 gpointer data;
{
 int saved = (int)gtk_object_get_data(GTK_OBJECT(window), "report_saved");
 
 if(saved)
 {
  int be = (int)gtk_object_get_data(GTK_OBJECT(window), "be");
  gtk_widget_hide(window);
  backend_dispose(be);
  return 0;
 }
 else
 {
  dialog_close_setup(window);
  return 1;
 }
}


static int 
cb_report_delete_window(u, w)
 GtkWidget * u, *w;
{
 return report_delete_window(w, NULL, NULL);
}


/*-------------------------------------------------------------------*/

static char **
select_severity_pixmap(severity)
 char * severity;
{
  if(severity)
  {
    if(!strcmp(severity, "Security Note"))return info_small_xpm;
    else if(!strcmp(severity, "Security Warning"))return warning_small_xpm;
    else if(!strcmp(severity, "Security Hole")) return error_small_xpm;
  }
  return nothing_xpm;
} /* select_severity_pixmap */


GtkWidget *
create_label(be, list, obj)
 int be;
 GtkWidget * list;
 struct subset * obj;
{
 char * name = subset_nth_value(obj, 0);
 char * severity = subset_nth_value(obj, 1);
 GtkWidget *widget = gtk_list_item_new();
 GtkWidget * box = gtk_hbox_new(FALSE, 3);
 GtkWidget * hostname;
 GtkWidget *pixmap;
 char * sort_key = gtk_object_get_data(GTK_OBJECT(list), "sort_key");
 char ** cat = NULL;
 char ** level;
 char * t;
  
 
 
 gtk_container_add(GTK_CONTAINER(widget), box);
 gtk_widget_show(box);
 
 
 if(!strcmp(sort_key, "host"))cat  = (char**)computer_xpm;
 else if(!strcmp(sort_key, "subnet"))cat = (char**)network_xpm;
 
 if(cat)
 {
   pixmap = make_pixmap(list, NULL, cat);
   gtk_box_pack_start(GTK_BOX(box), pixmap, FALSE, FALSE, 5);
   gtk_widget_show(pixmap);
 }
 
 if((level = select_severity_pixmap(severity)))
 {
   pixmap = make_pixmap(list, NULL, level);
   gtk_box_pack_start(GTK_BOX(box), pixmap, FALSE, FALSE, 5);
   gtk_widget_show(pixmap);
 }
 
 t = strchr(name, '\r');
 while(t != NULL)
 {
  t[0] = ' ';
  t = strchr(t + 1, '\r');
 }
 
 hostname = gtk_label_new(name);
 gtk_label_set_justify(GTK_LABEL(hostname), GTK_JUSTIFY_LEFT); 
 gtk_widget_show(hostname);
 gtk_box_pack_start(GTK_BOX(box), hostname, FALSE, FALSE, 5);
 gtk_widget_show(hostname);
 
 return widget;
}



GtkWidget*
create_report_window (be)
 int be;
{
  GtkWidget *report_window;
  GtkWidget *hpaned1;
  GtkWidget *vpaned1;
  GtkWidget *vbox2;
  GtkWidget *subnet;
  GtkWidget *subnet_menu;
  GtkWidget *glade_menuitem;
  GtkWidget *scrolled_window_subnet;
  GtkWidget *viewport1;
  GtkWidget *list_subnets;
  GtkWidget *vbox3;
  GtkWidget *optionmenu2;
  GtkWidget *optionmenu2_menu;
  GtkWidget *hosts_scrolled_window;
  GtkWidget *viewport2;
  GtkWidget *list_hosts;
  GtkWidget *vpaned2;
  GtkWidget *hpaned2;
  GtkWidget *vbox4;
  GtkWidget *optionmenu3;
  GtkWidget *optionmenu3_menu;
  GtkWidget *scrolledwindow3;
  GtkWidget *viewport3;
  GtkWidget *list_ports;
  GtkWidget *vbox5;
  GtkWidget *optionmenu4;
  GtkWidget *optionmenu4_menu;
  GtkWidget *scrolledwindow4;
  GtkWidget *viewport4;
  GtkWidget *list_severity;
  GtkWidget *vbox6;
  GtkWidget *scrolledwindow5;
  GtkWidget *viewport5;
  GtkWidget *list_reports;
  GtkWidget *vbox, *hbox;
  GtkWidget *save_button, *close_button;

  Lists[0] = list_subnets = gtk_list_new ();
  Lists[1] = list_hosts   = gtk_list_new ();
  Lists[2] = list_ports   = gtk_list_new ();
  Lists[3] = list_severity= gtk_list_new ();
  Lists[4] = list_reports = gtk_list_new ();
  
  report_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data(GTK_OBJECT(report_window), "be", (void*)be);
  
  gtk_signal_connect(GTK_OBJECT(report_window), "destroy", 
     	GTK_SIGNAL_FUNC(report_close_window), report_window);
  gtk_signal_connect(GTK_OBJECT(report_window), "delete_event", 
  	GTK_SIGNAL_FUNC(report_delete_window), report_window);
	

#if GTK_VERSION > 10
  gtk_window_set_default_size(GTK_WINDOW(report_window), 640,
  							 480);
#else
  gtk_widget_set_usize(GTK_WIDGET(report_window), 640, 480);
#endif

  gtk_object_set_data (GTK_OBJECT (report_window), "report_window", report_window);
  gtk_container_border_width (GTK_CONTAINER (report_window), 10);
  gtk_window_set_title (GTK_WINDOW (report_window), _("Nessus \"NG\" Report"));

  vbox = gtk_vbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(report_window), vbox);
  gtk_widget_show(vbox);
  
  hpaned1 = gtk_hpaned_new ();
  gtk_widget_ref (hpaned1);
#if GTK_VERSION > 10
  gtk_paned_set_position(GTK_PANED(hpaned1), 200);
#endif
  gtk_object_set_data_full (GTK_OBJECT (report_window), "hpaned1", hpaned1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hpaned1);
  gtk_box_pack_start(GTK_BOX(vbox), hpaned1, TRUE, TRUE, 0);


  hbox = gtk_hbox_new(TRUE, 10);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 0);
  gtk_widget_show(hbox);
  
  save_button = gtk_button_new_with_label("Save report...");
  gtk_signal_connect(GTK_OBJECT(save_button), "clicked", 
  			GTK_SIGNAL_FUNC(report_save_cb),
			report_window);
			
  gtk_box_pack_start(GTK_BOX(hbox), save_button, FALSE, TRUE, 0);
  gtk_widget_show(save_button);
  
  
  close_button = gtk_button_new_with_label("Close window");
  gtk_signal_connect(GTK_OBJECT(close_button), "clicked", 
  			GTK_SIGNAL_FUNC(cb_report_delete_window),
			report_window);
			
  gtk_box_pack_start(GTK_BOX(hbox), close_button, FALSE, TRUE, 0);
  gtk_widget_show(close_button);
  
  vpaned1 = gtk_vpaned_new ();
  gtk_widget_ref (vpaned1);
#if GTK_VERSION > 10
  gtk_paned_set_position(GTK_PANED(vpaned1), 200);
#endif
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vpaned1", vpaned1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vpaned1);
  gtk_container_add (GTK_CONTAINER (hpaned1), vpaned1);
  

  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox2);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vbox2", vbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox2);
  gtk_container_add (GTK_CONTAINER (vpaned1), vbox2);

  subnet = gtk_option_menu_new ();
  gtk_widget_ref (subnet);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "subnet", subnet,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (subnet);
  gtk_box_pack_start (GTK_BOX (vbox2), subnet, FALSE, FALSE, 0);
  subnet_menu = gtk_menu_new ();
  glade_menuitem = gtk_menu_item_new_with_label (_("Subnet"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("subnet"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_subnets);


  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (subnet_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Host"));
   gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("host"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_subnets);

  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (subnet_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Port"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("port"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_subnets);    
  gtk_widget_show (glade_menuitem);
  
  gtk_menu_append (GTK_MENU (subnet_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Severity"));
   gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("severity"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_subnets);
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (subnet_menu), glade_menuitem);

  gtk_option_menu_set_menu (GTK_OPTION_MENU (subnet), subnet_menu);

  scrolled_window_subnet = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolled_window_subnet);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "scrolled_window_subnet", scrolled_window_subnet,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolled_window_subnet);
  gtk_box_pack_start (GTK_BOX (vbox2), scrolled_window_subnet, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window_subnet), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  viewport1 = gtk_viewport_new (NULL, NULL);
  gtk_widget_ref (viewport1);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "viewport1", viewport1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (viewport1);
  gtk_container_add (GTK_CONTAINER (scrolled_window_subnet), viewport1);

  
  gtk_object_set_data(GTK_OBJECT(list_subnets), "empty", (void*)subnets_empty);
  gtk_object_set_data(GTK_OBJECT(list_subnets), "fill", (void*)subnets_fill);
  gtk_object_set_data(GTK_OBJECT(list_subnets), "optionmenu", (void*)subnet);
  gtk_object_set_data(GTK_OBJECT(list_subnets), "be", (void*)be);
  
  gtk_widget_ref (list_subnets);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "list_subnets", list_subnets,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (list_subnets);
  gtk_container_add (GTK_CONTAINER (viewport1), list_subnets);

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox3);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vbox3", vbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox3);
  gtk_container_add (GTK_CONTAINER (vpaned1), vbox3);

  optionmenu2 = gtk_option_menu_new ();
  gtk_widget_ref (optionmenu2);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "optionmenu2", optionmenu2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (optionmenu2);
  gtk_box_pack_start (GTK_BOX (vbox3), optionmenu2, FALSE, FALSE, 0);
  optionmenu2_menu = gtk_menu_new ();
  glade_menuitem = gtk_menu_item_new_with_label (_("Subnet"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("subnet"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_hosts); 
		      
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Host"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("host"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_hosts); 
		      
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Port"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("port"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_hosts); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Severity"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("severity"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_hosts); 
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
 
  gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu2), optionmenu2_menu);
  gtk_option_menu_set_history (GTK_OPTION_MENU (optionmenu2), 1);

  hosts_scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (hosts_scrolled_window);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "hosts_scrolled_window", hosts_scrolled_window,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hosts_scrolled_window);
  gtk_box_pack_start (GTK_BOX (vbox3), hosts_scrolled_window, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (hosts_scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  viewport2 = gtk_viewport_new (NULL, NULL);
  gtk_widget_ref (viewport2);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "viewport2", viewport2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (viewport2);
  gtk_container_add (GTK_CONTAINER (hosts_scrolled_window), viewport2);

 
  gtk_object_set_data(GTK_OBJECT(list_hosts), "empty", (void*)hosts_empty);
  gtk_object_set_data(GTK_OBJECT(list_hosts), "fill", (void*)hosts_fill);
  gtk_object_set_data(GTK_OBJECT(list_hosts), "optionmenu", (void*)optionmenu2);
  gtk_object_set_data(GTK_OBJECT(list_hosts), "be", (void*)be);
  gtk_widget_ref (list_hosts);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "list_hosts", list_hosts,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (list_hosts);
  gtk_container_add (GTK_CONTAINER (viewport2), list_hosts);

  vpaned2 = gtk_vpaned_new ();
  gtk_widget_ref (vpaned2);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vpaned2", vpaned2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vpaned2);
  gtk_container_add (GTK_CONTAINER (hpaned1), vpaned2);
  
  hpaned2 = gtk_hpaned_new ();
  gtk_widget_ref (hpaned2);
#if GTK_VERSION > 10
  gtk_paned_set_position(GTK_PANED(hpaned2), 200);
#endif
  gtk_object_set_data_full (GTK_OBJECT (report_window), "hpaned2", hpaned2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hpaned2);
  gtk_container_add (GTK_CONTAINER (vpaned2), hpaned2);
  

  vbox4 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox4);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vbox4", vbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox4);
  gtk_container_add (GTK_CONTAINER (hpaned2), vbox4);

  optionmenu3 = gtk_option_menu_new ();
  gtk_widget_ref (optionmenu3);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "optionmenu3", optionmenu3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (optionmenu3);
  gtk_box_pack_start (GTK_BOX (vbox4), optionmenu3, FALSE, FALSE, 0);
  optionmenu3_menu = gtk_menu_new ();
  glade_menuitem = gtk_menu_item_new_with_label (_("Subnet"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("subnet"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_ports); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Host"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("host"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_ports); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Port"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("port"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_ports); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Severity"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("severity"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_ports); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);

  gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu3), optionmenu3_menu);
  gtk_option_menu_set_history (GTK_OPTION_MENU (optionmenu3), 2);

  scrolledwindow3 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow3);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "scrolledwindow3", scrolledwindow3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow3);
  gtk_box_pack_start (GTK_BOX (vbox4), scrolledwindow3, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow3), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  viewport3 = gtk_viewport_new (NULL, NULL);
  gtk_widget_ref (viewport3);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "viewport3", viewport3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (viewport3);
  gtk_container_add (GTK_CONTAINER (scrolledwindow3), viewport3);

  
  gtk_object_set_data(GTK_OBJECT(list_ports), "empty", (void*)ports_empty);
  gtk_object_set_data(GTK_OBJECT(list_ports), "fill", (void*)ports_fill);
  gtk_object_set_data(GTK_OBJECT(list_ports), "optionmenu", (void*)optionmenu3);
  gtk_object_set_data(GTK_OBJECT(list_ports), "be", (void*)be);
  gtk_widget_ref (list_ports);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "list_ports", list_ports,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (list_ports);
  gtk_container_add (GTK_CONTAINER (viewport3), list_ports);

  vbox5 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox5);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vbox5", vbox5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox5);
  gtk_container_add (GTK_CONTAINER (hpaned2), vbox5);

  optionmenu4 = gtk_option_menu_new ();
  gtk_widget_ref (optionmenu4);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "optionmenu4", optionmenu4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (optionmenu4);
  gtk_box_pack_start (GTK_BOX (vbox5), optionmenu4, FALSE, FALSE, 0);
  optionmenu4_menu = gtk_menu_new ();
  glade_menuitem = gtk_menu_item_new_with_label (_("Subnet"));
  gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("subnet"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_severity); 
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Host"));
   gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("host"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_severity); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Port"));
   gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("port"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_severity); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
  glade_menuitem = gtk_menu_item_new_with_label (_("Severity"));
   gtk_object_set_data(GTK_OBJECT(glade_menuitem), "sort_key", ("severity"));
  gtk_signal_connect (GTK_OBJECT (glade_menuitem), "activate",
                      GTK_SIGNAL_FUNC (on_menu_item_subnet_selected),
                      list_severity); 
		      
  gtk_widget_show (glade_menuitem);
  gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
 
  gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu4), optionmenu4_menu);
  gtk_option_menu_set_history (GTK_OPTION_MENU (optionmenu4), 3);

  scrolledwindow4 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow4);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "scrolledwindow4", scrolledwindow4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow4);
  gtk_box_pack_start (GTK_BOX (vbox5), scrolledwindow4, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow4), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  viewport4 = gtk_viewport_new (NULL, NULL);
  gtk_widget_ref (viewport4);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "viewport4", viewport4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (viewport4);
  gtk_container_add (GTK_CONTAINER (scrolledwindow4), viewport4);

  
  gtk_object_set_data(GTK_OBJECT(list_severity), "empty", (void*)severity_empty);
  gtk_object_set_data(GTK_OBJECT(list_severity), "fill", (void*)severity_fill);
  gtk_object_set_data(GTK_OBJECT(list_severity), "optionmenu", (void*)optionmenu4);
  gtk_object_set_data(GTK_OBJECT(list_severity), "be", (void*)be);
  gtk_widget_ref (list_severity);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "list_severity", list_severity,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (list_severity);
  gtk_container_add (GTK_CONTAINER (viewport4), list_severity);

  vbox6 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox6);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "vbox6", vbox6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox6);
  gtk_container_add (GTK_CONTAINER (vpaned2), vbox6);


  scrolledwindow5 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow5);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "scrolledwindow5", scrolledwindow5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow5);
  gtk_box_pack_start (GTK_BOX (vbox6), scrolledwindow5, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow5), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  viewport5 = gtk_viewport_new (NULL, NULL);
  gtk_widget_ref (viewport5);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "viewport5", viewport5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (viewport5);
  gtk_container_add (GTK_CONTAINER (scrolledwindow5), viewport5);

  
  gtk_object_set_data(GTK_OBJECT(list_reports), "empty", (void*)reports_empty);
  gtk_object_set_data(GTK_OBJECT(list_reports), "fill", (void*)reports_fill);
  gtk_object_set_data(GTK_OBJECT(list_reports), "be", (void*)be);
  
  gtk_widget_ref (list_reports);
  gtk_object_set_data_full (GTK_OBJECT (report_window), "list_reports", list_reports,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (list_reports);
  gtk_container_add (GTK_CONTAINER (viewport5), list_reports);


  gtk_object_set_data(GTK_OBJECT(list_subnets), "sort_key", estrdup("subnet"));
  gtk_object_set_data(GTK_OBJECT(list_subnets), "hosts_list", list_hosts);
  gtk_signal_connect (GTK_OBJECT (list_subnets), "selection_changed",
                      GTK_SIGNAL_FUNC (on_subnets_list_selection_changed),
                      (void*)be);
  subnets_fill(be, list_subnets);
  replace_data(GTK_OBJECT(list_subnets), "restriction_1_key", estrdup("subnet"));
  replace_data(GTK_OBJECT(list_subnets), "restriction_1_value", estrdup("not_selected"));
  
  
  gtk_object_set_data(GTK_OBJECT (list_hosts), "sort_key", estrdup("host"));
  gtk_object_set_data(GTK_OBJECT (list_hosts), "ports_list", list_ports);
  gtk_signal_connect (GTK_OBJECT (list_hosts), "selection_changed",
                      GTK_SIGNAL_FUNC (on_hosts_list_selection_changed),
                      (void*)be);
		      

  gtk_object_set_data(GTK_OBJECT (list_ports), "sort_key", estrdup("port"));
  gtk_object_set_data(GTK_OBJECT (list_ports), "severity_list", list_severity);
  gtk_signal_connect (GTK_OBJECT (list_ports), "selection_changed",
                      GTK_SIGNAL_FUNC (on_ports_list_selection_changed),
                      (void*)be);

  gtk_object_set_data(GTK_OBJECT (list_severity), "sort_key", estrdup("severity"));
  gtk_object_set_data(GTK_OBJECT (list_severity), "reports_list", list_reports);
  gtk_signal_connect (GTK_OBJECT (list_severity), "selection_changed",
                      GTK_SIGNAL_FUNC (on_severity_list_selection_changed),
                      (void*)be);
 
  gtk_object_set_data(GTK_OBJECT (list_reports), "sort_key", estrdup("report"));
 
 
 
  return report_window;
}

int report_tests_ng(be, interrupted)
 int be, interrupted;
{
 GtkWidget  * window;
 
 gtk_widget_show(arg_get_value(MainDialog, "WINDOW"));
 if(backend_empty(be) <= 0)
 {
  struct arglist * sprefs = arg_get_value(Prefs, "SERVER_PREFS");
  char * opt;
  if((opt = arg_get_value(sprefs, "detached_scan")))
  {
   if(!strcmp(opt, "yes"))
   {
    struct arglist * ctrls = arg_get_value(MainDialog, "AUTH");
    
 
    gtk_widget_show(arg_get_value(ctrls, "BUTTON_LOG_IN"));
    gtk_widget_hide(arg_get_value(ctrls, "BUTTON_LOG_OUT"));
    gtk_widget_hide(arg_get_value(ctrls, "CONNECTED"));
    
    
    show_info("nessusd is now scanning the network in background");
    close_stream_connection(GlobalSocket);
    GlobalSocket = -1;
    
    return 0;
   }
  }
  show_error("nessusd returned an empty report");
  return -1;
 }
 window = create_report_window(be);
 gtk_widget_show(window);
#ifdef TEST_QUERY_LANGUAGE
 {
 char buffer[2048];
 
 fprintf(stdout, "*** TEST THE QUERY LANGUAGE\n");
 for(;;)
 {
  struct subset * subset;
  fprintf(stdout, "> ");
  bzero(buffer, sizeof(buffer));
  fgets(buffer, sizeof(buffer) - 1, stdin);
  buffer[strlen(buffer) -  1] = '\0';
  if(!strlen(buffer))
   break;
  subset = query_backend(be, "%s", buffer);
  subset_dump(subset);
  subset_free(subset);
 }
}
#endif 
 return 0;
}






#endif /* USE_GTK */  
