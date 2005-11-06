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
#include "globals.h"
#ifndef USE_GTK 

void 
show_dialog_and_wait
 (char * error_text, int type)
{
 fprintf(stderr, "*** %s\n", error_text);
 fprintf(stderr, "press 'enter' to continue\n");
 getchar();
}
void 
show_dialog
 (char * error_text, int type)
{
  fprintf (stderr, "*** %s\n", error_text);
}
#else /* USE_GTK */
#include "gtk-compat.h"
#include <gtk/gtk.h>
#include "xpm/error.xpm"
#include "xpm/warning.xpm"
#include "xpm/info.xpm"
#include "xstuff.h"
#include "error_dialog.h"
#include "globals.h"




/* 
 * show_error
 *
 * This function draws a dialog showing an error
 *
 */
 
 
void 
show_dialog(error_text, type)
  char * error_text;
  int type;
{
  if(F_quiet_mode)fprintf(stderr, "%s\n", error_text);
  else
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
  char *      name;

  switch(type)
  {
    case DIALOG_TYPE_INFO :
      	name = "Info";
	break;
    case DIALOG_TYPE_WARNING :
	name = "Warning";
	break;
    case DIALOG_TYPE_ERROR :
    default :
	name = "Error";
	break;
  }
  
  #if GTK_VERSION < 20 
    dialog = gtk_window_new(WINDOW_DIALOG);
  #else
    dialog = gtk_dialog_new();
  #endif
  gtk_window_set_title(GTK_WINDOW(dialog), name);
  gtk_signal_connect (GTK_OBJECT (dialog), "delete_event",
		      GTK_SIGNAL_FUNC (delete_event), NULL); 
  gtk_window_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
  #if GTK_VERSION < 20
    vbox = gtk_vbox_new(FALSE, 15);
    gtk_container_border_width(GTK_CONTAINER(dialog), 10);
    gtk_container_add(GTK_CONTAINER(dialog), vbox);
    gtk_widget_show(vbox);
  #else
    vbox = GTK_DIALOG(dialog)->vbox;
  #endif
  
  hbox = gtk_hbox_new(FALSE,5);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE,0);
  gtk_widget_show(hbox);

  label = gtk_label_new(error_text);
  gtk_label_set_justify (GTK_LABEL(label), GTK_JUSTIFY_LEFT);
  gtk_box_pack_end (GTK_BOX (hbox), label, TRUE, TRUE, 3);  
  gtk_widget_show(label);
 
  
  
  button = gtk_button_new_with_label ("OK");
  gtk_signal_connect (GTK_OBJECT (button), "clicked",
		      GTK_SIGNAL_FUNC (close_window), dialog);
                      
  table = gtk_table_new(1,3, TRUE);
  gtk_box_pack_end(GTK_BOX(vbox), table, TRUE, TRUE, 0);
  gtk_widget_show(table);
  
  
  gtk_table_attach_defaults(GTK_TABLE(table), button, 2,3,0,1);
  GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
  gtk_widget_grab_default (button);
  gtk_widget_show (button); 
  gtk_widget_realize(dialog);
 
  style = gtk_widget_get_style(dialog);
  if(F_show_pixmaps)
  {
   char** data;
   switch(type)
   {
    case DIALOG_TYPE_INFO :
       data = info_xpm;
         break;
    case DIALOG_TYPE_WARNING :
    	data = warning_xpm;
	break;
   case DIALOG_TYPE_ERROR :
   default :
   	data = error_xpm;
	break;
  }
   pixmap = gdk_pixmap_create_from_xpm_d(dialog->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(char **)data);
   pixmapwid = gtk_pixmap_new(pixmap, mask);   
  
   gtk_box_pack_start(GTK_BOX(hbox), pixmapwid, FALSE, TRUE,3);
   gtk_widget_show(pixmapwid);
  }
  gtk_widget_show(dialog);
  }
} 


static void show_dialog_and_wait_cb(gw, ok)
 GtkWidget* gw;
 int *ok;
{
 GtkWidget* dialog = gw->parent->parent->parent;
 gtk_grab_remove(dialog);
 close_window(NULL, dialog);
 gtk_widget_destroy(dialog);
 *ok = 1;
 gtk_main_quit();
}

void show_dialog_and_wait_build(int * ok, char * error_text, int type)
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
  char * name;   
  switch(type)
  {
    case DIALOG_TYPE_INFO :
      	name = "Info";
	break;
    case DIALOG_TYPE_WARNING :
	name = "Warning";
	break;
    case DIALOG_TYPE_ERROR :
    default :
	name = "Error";
	break;
  }
  dialog = gtk_window_new(WINDOW_DIALOG);
  gtk_widget_realize(dialog);
  gtk_window_set_title(GTK_WINDOW(dialog), name);
  gtk_signal_connect (GTK_OBJECT (dialog), "delete_event",
		      GTK_SIGNAL_FUNC (show_dialog_and_wait_cb), ok); 
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
 
  
  
  button = gtk_button_new_with_label ("OK");
  gtk_signal_connect (GTK_OBJECT (button), "clicked",
		      GTK_SIGNAL_FUNC (show_dialog_and_wait_cb), ok);
                      
  table = gtk_table_new(1,3, TRUE);
  gtk_box_pack_end(GTK_BOX(vbox), table, TRUE, TRUE, 0);
  gtk_widget_show(table);
  
  
  gtk_table_attach_defaults(GTK_TABLE(table), button, 2,3,0,1);
  GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
  gtk_widget_grab_default (button);
  gtk_widget_show (button); 
  gtk_widget_realize(dialog);
 
  style = gtk_widget_get_style(dialog);
  if(F_show_pixmaps)
  {
    char** data;
   switch(type)
   {
    case DIALOG_TYPE_INFO :
         data = info_xpm;
	 break;
    case DIALOG_TYPE_WARNING :
    	data = warning_xpm;
	break;
   case DIALOG_TYPE_ERROR :
   default :
   	data = error_xpm;
	break;
  }
   pixmap = gdk_pixmap_create_from_xpm_d(dialog->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(char **)data);
   pixmapwid = gtk_pixmap_new(pixmap, mask);   
  
   gtk_box_pack_start(GTK_BOX(hbox), pixmapwid, FALSE, TRUE,3);
   gtk_widget_show(pixmapwid);
  }
  gtk_widget_show(dialog);
  gtk_grab_add(dialog);
}

void show_dialog_and_wait(char * error, int type)
{
 int ok = 0;
 if(F_quiet_mode)fprintf(stderr, "%s\n", error);
 else
 {
  show_dialog_and_wait_build(&ok, error, type);
  gtk_main();
 }
}
                                
#endif
