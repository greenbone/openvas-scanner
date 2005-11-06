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
 *
 * This code deals with the 'save report' dialog.
 */  
 
 
#include <includes.h>
#ifdef USE_GTK
#include <gtk/gtk.h>
#include "gtk-compat.h"
#include "xstuff.h"
#include "xpm/warning.xpm"

#include "backend.h"
#include "nsr_output.h"
#include "html_output.h"
#include "report_utils.h"
#include "error_dialog.h"
#include "latex_output.h"
#include "text_output.h"
#include "xml_output.h"
#include "xml_output_ng.h"
#include "html_graph_output.h"
#include "nbe_output.h"

#include "report_ng.h"


#define SAVE_NBE 	0
#define SAVE_NSR 	1
#define SAVE_HTML 	2
#define SAVE_TEXT 	3
#define SAVE_LATEX 	4
#define SAVE_HTML_GRAPH 5
#define SAVE_XML 	6
#define SAVE_XML_NG 	7
#define SAVE_MAX SAVE_XML_NG


/*------------------------------------------------------------------------*/

static int file_dialog_hide(filedialog)
 GtkWidget * filedialog;
{
 gtk_widget_hide(filedialog);
 gtk_widget_destroy(filedialog);
 return 0;
}

static int file_save_ok_callback(widget, filedialog)
 GtkWidget * widget;
 GtkWidget * filedialog;
{
 char * fname = (char*)gtk_file_selection_get_filename(GTK_FILE_SELECTION(filedialog));
 int type;
 struct arglist * hosts = NULL;
 GtkWidget * menu    = gtk_object_get_data(GTK_OBJECT(filedialog), "menu");
 GtkWidget * window  = gtk_object_get_data(GTK_OBJECT(filedialog), "window");
 GtkWidget * active;
 char * suffixes[] = {".nbe", ".nsr", ".html", ".txt", ".tex", "", ".xml", ".xml"};
#define MAX_SUFFIX_LEN 5 /* .html */ 
 int be = (int)gtk_object_get_data(GTK_OBJECT(filedialog), "be");
 
 gtk_object_set_data(GTK_OBJECT(window), "report_saved", (void*)1);
 gtk_widget_hide(filedialog);

 
 
 active = gtk_menu_get_active(GTK_MENU(menu));
 type = (int)gtk_object_get_data(GTK_OBJECT(active), "type");

 
 
 /* 
  * Add a default extension
  */
 if(strrchr(fname, '.'))
  fname = estrdup(fname);
 else
 {
  char * s;
  s = emalloc(strlen(fname) + MAX_SUFFIX_LEN + 1);
  strcat(s, fname);
  strcat(s, suffixes[type]);
  fname = s;
 }
 
 
 
 

 switch(type)
 {
  case SAVE_HTML :
   hosts = backend_convert(be);
   arglist_to_html(hosts, fname);
   break;
  case SAVE_XML :
   hosts = backend_convert(be);
   arglist_to_xml(hosts, fname);
   break;
  case SAVE_XML_NG :
   backend_to_xml_ng(be, fname);
   break;
  case SAVE_LATEX :
   hosts = backend_convert(be);
   arglist_to_latex(hosts, fname);
   break;
  case SAVE_TEXT:
    hosts = backend_convert(be);
    arglist_to_text(hosts, fname);
    break;
#ifndef _NOPIE
  case SAVE_HTML_GRAPH:
    hosts = backend_convert(be);
    arglist_to_html_graph(hosts,fname);
    break;
#endif
 case SAVE_NSR:
    backend_to_nsr(be, fname);
    break;
 case SAVE_NBE:
 default:
    backend_to_nbe(be, fname);
    break;
  }
 efree(&fname);
 if(hosts)arg_free_all(hosts);
 gtk_widget_destroy(filedialog);
 if(gtk_object_get_data(GTK_OBJECT(window), "dont_close"))
  gtk_object_remove_data(GTK_OBJECT(window), "dont_close");
 else
  report_delete_window(window, NULL);
 return 0;
}

/*
 *  "inspired" from the Gimp 1.2.2
 * See gimp/app/fileops.c for a cleaner function
 */
static void
file_dialog_setup(window)
 GtkWidget * window;
{
 GtkWidget *filesave;
 GtkWidget *frame;
 GtkWidget *hbox;
 GtkWidget *label;
 GtkWidget *option_menu;
 GtkWidget *menu;
 GtkWidget *save_options;
 GtkWidget *type;
 
 filesave = gtk_file_selection_new("Save Report");
 gtk_object_set_data(GTK_OBJECT(filesave), "window", window);
 gtk_object_set_data(GTK_OBJECT(filesave), "be",
 gtk_object_get_data(GTK_OBJECT(window),  "be"));
 
 gtk_window_set_wmclass(GTK_WINDOW(filesave), "save_report", "Nessus");
#if GTK_VERSION > 10
 gtk_window_set_position(GTK_WINDOW(filesave), GTK_WIN_POS_MOUSE);
#endif
 gtk_object_set_data(GTK_OBJECT(filesave), "be",
 gtk_object_get_data(GTK_OBJECT(window),  "be"));
 
 gtk_container_border_width(GTK_CONTAINER(filesave), 2);
 gtk_container_border_width(GTK_CONTAINER(
 		GTK_FILE_SELECTION(filesave)->button_area), 2);

 gtk_signal_connect_object (GTK_OBJECT (GTK_FILE_SELECTION (filesave)->cancel_button),
				 "clicked",
				 GTK_SIGNAL_FUNC (file_dialog_hide),
				 GTK_OBJECT (filesave));
 gtk_signal_connect (GTK_OBJECT (filesave), "delete_event",
			  GTK_SIGNAL_FUNC (file_dialog_hide),
			  NULL);
 gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (filesave)->ok_button),
			  "clicked",
			  GTK_SIGNAL_FUNC (file_save_ok_callback),
			  filesave);
 gtk_quit_add_destroy (1, GTK_OBJECT (filesave));	
 
 
 save_options = gtk_hbox_new (TRUE, 1);

 frame = gtk_frame_new ("Save Options");
 gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_ETCHED_IN);
 gtk_box_pack_start (GTK_BOX (save_options), frame, TRUE, TRUE, 4);

 hbox = gtk_hbox_new (FALSE, 4);
 gtk_container_border_width (GTK_CONTAINER (hbox), 4);
 gtk_container_add (GTK_CONTAINER (frame), hbox);
 gtk_widget_show (hbox);

 label = gtk_label_new ("Report file format : ");
 gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);
 gtk_widget_show (label);

 option_menu = gtk_option_menu_new ();
 gtk_box_pack_start (GTK_BOX (hbox), option_menu, TRUE, TRUE, 0);
 gtk_widget_show (option_menu);
 
 
 
 

 /*---------------------------------------------------------------*
  * 	We fill the dialog with the various export formats
  *	we know about
  *---------------------------------------------------------------*/
  menu = gtk_menu_new(); 
  gtk_object_set_data(GTK_OBJECT(filesave), "menu", menu);
  
  type = gtk_menu_item_new_with_label("NBE");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_NBE);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  
  
  type = gtk_menu_item_new_with_label("NSR (deprecated)");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_NSR);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
   
  type = gtk_menu_item_new_with_label ("XML");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_XML_NG);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  
  type = gtk_menu_item_new_with_label ("XML (old style - deprecated)");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_XML);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  
 
  type = gtk_menu_item_new_with_label("HTML");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_HTML);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  type = gtk_menu_item_new_with_label("LaTeX");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_LATEX);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
  
  type = gtk_menu_item_new_with_label("ASCII text");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_TEXT);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);

#ifndef _NO_PIES
  type = gtk_menu_item_new_with_label("HTML with Pies and Graphs");
  gtk_object_set_data(GTK_OBJECT(type), "type", (void*)SAVE_HTML_GRAPH);
  gtk_menu_append(GTK_MENU(menu), type);
  gtk_widget_show(type);
#endif  
 

 
 
 /*----------------------------------------------------------------*/ 
 gtk_option_menu_set_menu (GTK_OPTION_MENU (option_menu), menu);
 gtk_widget_show(menu);
 gtk_widget_show (frame);

 /* pack the containing save_options hbox into the save-dialog */
 gtk_box_pack_end (GTK_BOX (GTK_FILE_SELECTION (filesave)->main_vbox),
   		   save_options, FALSE, FALSE, 0); 
 gtk_widget_show(save_options);
 gtk_widget_show(filesave);
 
}


/*------------------------------------------------------------------------*/
static int
dialog_close_do_save(a, dialog)
 GtkWidget * a, * dialog;
{
 GtkWidget * window = gtk_object_get_data(GTK_OBJECT(dialog), "report");
 gtk_widget_hide(dialog);
 file_dialog_setup(window);
 return 0;
}

static int
dialog_close_dont_save(a, dialog)
 GtkWidget * a, * dialog;
{
 GtkWidget * window = gtk_object_get_data(GTK_OBJECT(dialog), "report");
 gtk_widget_hide(dialog);
 gtk_object_set_data(GTK_OBJECT(window), "report_saved", (void*)1);
 report_delete_window(window, NULL);
 return 0;
}

static int
dialog_close_cancel(a, dialog)
 GtkWidget * a, * dialog;
{
 gtk_widget_hide(dialog);
 return 0;
}





void
dialog_close_setup(window)
 GtkWidget * window;
{
  GtkWidget * dialog;
  GtkWidget * button;
  GtkWidget * vbox;
  GtkWidget * hbox;
  GtkWidget * label;
  GtkStyle  * style;
  GtkWidget * pixmapwid;
  GdkPixmap * pixmap;
  GdkBitmap * mask;
  GtkWidget * table;
  char *      name = "Save report";
  char *      error_text = 
  "This report was not saved.\nDo you want to save it ?";
  
  
  dialog = gtk_object_get_data(GTK_OBJECT(window), 
  				"save_dialog");

  if(dialog)
  {
   gtk_widget_show(dialog);
   return;
  }		
  
  dialog = gtk_window_new(WINDOW_DIALOG); 
  gtk_object_set_data(GTK_OBJECT(dialog), "report", window);
  gtk_object_set_data(GTK_OBJECT(window), "save_dialog", dialog);
  
  gtk_window_set_title(GTK_WINDOW(dialog), name);
  gtk_signal_connect (GTK_OBJECT (dialog), "delete_event",
		      GTK_SIGNAL_FUNC (delete_event), NULL); 
  gtk_window_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
  vbox = gtk_vbox_new(FALSE, 15);
  gtk_container_border_width(GTK_CONTAINER(dialog), 10);
  gtk_container_add(GTK_CONTAINER(dialog), vbox);
  gtk_widget_show(vbox);
  
  hbox = gtk_hbox_new(FALSE,5);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE,0);
  gtk_widget_show(hbox);

  label = gtk_label_new(error_text);
  gtk_label_set_justify (GTK_LABEL(label), GTK_JUSTIFY_LEFT);
  gtk_box_pack_end (GTK_BOX (hbox), label, TRUE, TRUE, 3);  
  gtk_widget_show(label);
 
  
  
  button = gtk_button_new_with_label ("Yes");
  gtk_signal_connect (GTK_OBJECT (button), "clicked",
		      GTK_SIGNAL_FUNC (dialog_close_do_save), dialog);
                      
  table = gtk_table_new(1,3, TRUE);
  gtk_box_pack_end(GTK_BOX(vbox), table, TRUE, TRUE, 0);
  gtk_widget_show(table);
  
  
  
  
  gtk_table_attach_defaults(GTK_TABLE(table), button, 0,1,0,1);
  GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
  gtk_widget_grab_default (button);
  gtk_widget_show (button); 
  gtk_widget_realize(dialog);
  
  
  button = gtk_button_new_with_label ("No");
  gtk_signal_connect (GTK_OBJECT (button), "clicked",
		      GTK_SIGNAL_FUNC (dialog_close_dont_save), dialog);
               
  
  
  
  gtk_table_attach_defaults(GTK_TABLE(table), button, 1,2,0,1);
  gtk_widget_show (button); 
  gtk_widget_realize(dialog);


  button = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect (GTK_OBJECT (button), "clicked",
		      GTK_SIGNAL_FUNC (dialog_close_cancel), dialog);
      
  
  gtk_table_attach_defaults(GTK_TABLE(table), button, 2,3,0,1);
  gtk_widget_show (button); 
  gtk_widget_realize(dialog);
  
  
   
  style = gtk_widget_get_style(dialog);
  pixmap = gdk_pixmap_create_from_xpm_d(dialog->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(char **)warning_xpm);
   pixmapwid = gtk_pixmap_new(pixmap, mask);   
  
  gtk_box_pack_start(GTK_BOX(hbox), pixmapwid, FALSE, TRUE,3);
  gtk_widget_show(pixmapwid);
  gtk_widget_show(dialog);
}

void
report_save_cb(w, window)
 GtkWidget * w, * window;
{
 gtk_object_set_data(GTK_OBJECT(window), "dont_close", (void*)1);
 file_dialog_setup(window);
}

#endif
