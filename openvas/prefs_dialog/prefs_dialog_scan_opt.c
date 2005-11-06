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
#include "../plugin_infos.h"
#include "../error_dialog.h"
#include "prefs_dialog_scan_opt.h"
#include "globals.h"

static void  scanner_infos_cb(GtkWidget *, struct arglist *);
     
     
 
struct arglist * prefs_dialog_scan_opt()
{
 GtkWidget * frame;
 GtkWidget * table;
 GtkWidget * ping_hosts;
 GtkWidget * optimize_test;
 GtkWidget * safe_checks;
 GtkWidget * use_mac_addr;
 GtkWidget * reverse_lookup;
 GtkWidget * box;
 GtkWidget * label;
 GtkWidget * port_range;
 GtkWidget * unscanned_as_closed;
 GtkWidget * entry;
 GtkWidget * scanners_window;
 GtkWidget * list;
 
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 
 frame = gtk_frame_new("Scan options");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
 gtk_widget_show(frame);
 
 
 box = gtk_vbox_new(FALSE, 10);
 
 gtk_container_add(GTK_CONTAINER(frame), box);
 gtk_container_border_width(GTK_CONTAINER(box), 10);
 gtk_widget_show(box);
 
 
 ping_hosts = gtk_check_button_new_with_label("Determine if hosts are alive before testing them");
 arg_add_value(ctrls, "PING_HOSTS", ARG_PTR, -1, ping_hosts);
 /*gtk_box_pack_start(GTK_BOX(box), ping_hosts, FALSE, FALSE, 0);
 gtk_widget_show(ping_hosts);*/
 

 
 table = gtk_table_new(5, 2, FALSE);
 gtk_box_pack_start(GTK_BOX(box), table, FALSE, FALSE, 0);
 gtk_widget_show(table);
 

 gtk_table_set_row_spacing(GTK_TABLE(table), 0, 10);
 label = gtk_label_new("Port range : ");
 gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 0,1);
 gtk_widget_show(label);
 
 port_range = gtk_entry_new();
 gtk_table_attach_defaults(GTK_TABLE(table), port_range, 1,2,0,1);
 gtk_widget_show(port_range);
 arg_add_value(ctrls, "PORT_RANGE", ARG_PTR, -1, port_range);
 
 unscanned_as_closed = gtk_check_button_new_with_label("Consider unscanned ports as closed");
 arg_add_value(ctrls, "UNSCANNED_CLOSED", ARG_PTR, -1, unscanned_as_closed);
 gtk_table_attach_defaults(GTK_TABLE(table), unscanned_as_closed, 0,2,1,2);
 gtk_widget_show(unscanned_as_closed);
 
 
 
 
 
 gtk_table_set_row_spacing(GTK_TABLE(table), 1, 10);
 label = gtk_label_new("Number of hosts to test at the same time : ");
 gtk_table_attach_defaults(GTK_TABLE(table), label, 0,1,2,3);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,2,3);
 gtk_widget_show(entry);
 arg_add_value(ctrls, "MAX_HOSTS", ARG_PTR, -1, entry);
 
 gtk_table_set_row_spacing(GTK_TABLE(table), 2, 10);
 label = gtk_label_new("Number of checks to perform at the same time : ");
 gtk_table_attach_defaults(GTK_TABLE(table), label, 0,1,3,4);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,3,4);
 gtk_widget_show(entry);
 arg_add_value(ctrls, "MAX_CHECKS", ARG_PTR, -1, entry);
 
 

 label = gtk_label_new("Path to the CGIs : ");
 gtk_table_attach_defaults(GTK_TABLE(table), label, 0,1,4,5);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 gtk_table_attach_defaults(GTK_TABLE(table), entry, 1,2,4,5);
 gtk_widget_show(entry);
 arg_add_value(ctrls, "CGI_PATH", ARG_PTR, -1, entry);
 
 
 reverse_lookup = gtk_check_button_new_with_label("Do a reverse lookup on the IP before testing it");
 arg_add_value(ctrls, "REVERSE_LOOKUP", ARG_PTR, -1, reverse_lookup);
 gtk_box_pack_start(GTK_BOX(box), reverse_lookup, FALSE, FALSE, 0);
 gtk_widget_show(reverse_lookup);
 
 optimize_test = gtk_check_button_new_with_label("Optimize the test");
 arg_add_value(ctrls, "OPTIMIZE_TEST", ARG_PTR, -1, optimize_test);
 gtk_box_pack_start(GTK_BOX(box), optimize_test, FALSE, FALSE, 0);
 gtk_widget_show(optimize_test);
 
 
 safe_checks = gtk_check_button_new_with_label("Safe checks");
 arg_add_value(ctrls, "SAFE_CHECKS", ARG_PTR, -1, safe_checks);
 gtk_box_pack_start(GTK_BOX(box), safe_checks, FALSE, FALSE, 0);
 gtk_widget_show(safe_checks);
 
 use_mac_addr = gtk_check_button_new_with_label("Designate hosts by their MAC address");
 arg_add_value(ctrls, "USE_MAC_ADDR", ARG_PTR, -1, use_mac_addr);
 gtk_box_pack_start(GTK_BOX(box), use_mac_addr, FALSE, FALSE, 0);
 gtk_widget_show(use_mac_addr);
 

#ifdef ENABLE_SAVE_KB
#if 0
 opt = gtk_check_button_new_with_label("Detached scan");
 arg_add_value(ctrls, "DETACHED_SCAN", ARG_PTR, -1, opt);
 gtk_box_pack_start(GTK_BOX(box), opt, FALSE, FALSE, 0);
 gtk_widget_show(opt);
 gtk_signal_connect(GTK_OBJECT(opt),
		     "clicked",
		     GTK_SIGNAL_FUNC(detached_cb),
		     ctrls);
 
 hbox = gtk_hbox_new(TRUE, TRUE);
 /*gtk_container_set_border_width(GTK_CONTAINER(hbox), 5); */
 gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 0);
 gtk_widget_show(hbox);
 label = gtk_label_new("Send results to this email address : ");
 arg_add_value(ctrls, "EMAIL_ADDR_LABEL", ARG_PTR, -1, label);
 gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
 gtk_widget_set_sensitive(label, FALSE);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 arg_add_value(ctrls, "EMAIL_ADDR", ARG_PTR, -1, entry);
 gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
 gtk_widget_set_sensitive(entry, FALSE);
 gtk_widget_show(entry);
 
 
 opt = gtk_check_button_new_with_label("Continuous scan");
 arg_add_value(ctrls, "CONTINUOUS_SCAN", ARG_PTR, -1, opt);
 gtk_box_pack_start(GTK_BOX(box), opt, FALSE, FALSE, 0);
 gtk_widget_set_sensitive(opt, FALSE);
 gtk_widget_show(opt);
 gtk_signal_connect(GTK_OBJECT(opt),
		     "clicked",
		     GTK_SIGNAL_FUNC(continuous_cb),
		     ctrls);
 
 hbox = gtk_hbox_new(TRUE, TRUE);
 /*gtk_container_set_border_width(GTK_CONTAINER(hbox), 5); */
 gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 0);
 gtk_widget_show(hbox);
 
 
 label = gtk_label_new("Delay between two scans : ");
 arg_add_value(ctrls, "DELAY_LABEL", ARG_PTR, -1, label);
 gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
 gtk_widget_set_sensitive(label, FALSE);
 gtk_widget_show(label);
 
 
 opt = gtk_entry_new();
 arg_add_value(ctrls, "DELAY",  ARG_PTR, -1, opt);
 gtk_box_pack_start(GTK_BOX(hbox), opt, TRUE, TRUE, 0);
 gtk_widget_set_sensitive(opt, FALSE);
 gtk_widget_show(opt);
#endif
#endif
 scanners_window = gtk_scrolled_window_new(NULL,NULL);
 gtk_container_border_width(GTK_CONTAINER(scanners_window), 0);
 gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scanners_window),	
  			 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
 gtk_box_pack_end(GTK_BOX(box), scanners_window, TRUE, TRUE, 0);
 gtk_widget_show(scanners_window); 
 
 label = gtk_label_new("Port scanner : ");
 gtk_box_pack_end(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 list = gtk_list_new();
 arg_add_value(ctrls, "SCANNERS_LIST", ARG_PTR, -1, list);
#if GTK_VERSION < 11
 gtk_container_add(GTK_CONTAINER(scanners_window), list);
#else
 gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scanners_window), list);
#endif
 gtk_signal_connect(GTK_OBJECT(list),
		     "selection_changed",
		     GTK_SIGNAL_FUNC(scanner_infos_cb),     
		     ctrls);   
                     
                     
 gtk_widget_show(list);
 fill_scanner_list(ctrls);
 arg_add_value(ctrls, "SCANNERS_NUM", ARG_INT, sizeof(int), (void *)ScannersNum);
 return(ctrls);
}

static 
void prefs_scanner_list_toggle_callback(w, scanner)
     GtkWidget * w;
     struct arglist * scanner;
{
  int state = GTK_TOGGLE_BUTTON(w)->active;
  plug_set_launch(scanner,state);
  pluginset_reload(Plugins, Scanners);
}

void 
fill_scanner_list(ctrls)
 struct arglist * ctrls;
{
 GtkTooltips * tooltips;
 struct arglist * scans = Scanners;
 GList * dlist = NULL;

 dlist = arg_get_value(ctrls, "DLIST");
 if(dlist)gtk_list_remove_items(GTK_LIST(arg_get_value(ctrls, "SCANNERS_LIST")),
 				dlist);
 dlist = NULL;				
 tooltips = gtk_tooltips_new();
 while(scans && scans->next)
   {
     GtkWidget * item;
     GtkWidget * box;
     GtkWidget * button;
     GtkWidget * label;
    
     item = gtk_list_item_new();
     if(arg_get_value(scans->value, "SUMMARY"))
	    gtk_tooltips_set_tip(tooltips, item, 
				 (gchar *)arg_get_value(scans->value, "SUMMARY"),"");
     button = gtk_check_button_new();
     gtk_widget_set_usize(button, 15, 15);
     gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), 
				 plug_get_launch(scans->value));
     label = gtk_label_new(scans->name);
     box = gtk_hbox_new(FALSE,5);
     gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
     gtk_widget_show(label);
     gtk_box_pack_end(GTK_BOX(box), button, FALSE, FALSE,0);
	
     gtk_container_add(GTK_CONTAINER(item), box);
     gtk_signal_connect(GTK_OBJECT(button),
			"clicked",
			GTK_SIGNAL_FUNC(prefs_scanner_list_toggle_callback),
			scans->value);
     
     gtk_widget_show(button);
     gtk_widget_show(box);
     gtk_widget_show(item);
     dlist = g_list_append(dlist, item);
     gtk_object_set_data(GTK_OBJECT(item),
			 "list_item_data",
			  scans->name);
     scans = scans->next;
   }
   gtk_tooltips_enable(tooltips);
   if(arg_get_type(ctrls, "DLIST")<0)
    arg_add_value(ctrls, "DLIST", ARG_PTR, -1, dlist);
   else
    arg_set_value(ctrls, "DLIST", -1, dlist);
    
   gtk_list_append_items(GTK_LIST(arg_get_value(ctrls, "SCANNERS_LIST")), dlist);
}

int prefs_scanner_redraw(w, dumb, ctrls)
 GtkWidget * w;
 void * dumb;
 struct arglist * ctrls;
{
 int num;
 
 num = (int)arg_get_value(ctrls, "SCANNERS_NUM");
 if(num != ScannersNum){
  fill_scanner_list(ctrls);
  arg_set_value(ctrls, "SCANNERS_NUM", sizeof(int), (void *)ScannersNum);
  }
 return 0;
}


static void 
scanner_infos_cb(widget, ctrls)
     GtkWidget * widget;
     struct arglist * ctrls;
{
  GtkObject * list_item;
  char * scanner;
  GList * dlist;
  GtkWidget * list = arg_get_value(ctrls, "SCANNERS_LIST");
  
  dlist = GTK_LIST(list)->selection;
  if(!dlist)return;
  
  list_item = GTK_OBJECT(dlist->data);
  scanner = gtk_object_get_data(list_item,"list_item_data");
  plugin_info_window_setup(Scanners, scanner);             
}
#endif
