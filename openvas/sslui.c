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
 * UI hooks for the SSL questions
 *
 */
#include <includes.h>

#ifdef USE_AF_UNIX
#undef NESSUS_ON_SSL
#endif
#ifdef NESSUS_ON_SSL
#include "globals.h"


#ifdef USE_GTK
#include "gtk-compat.h"
#include <gtk/gtk.h>
#include <xpm/lock.xpm>
#include "xstuff.h"
/*-------------------------------------------------------------------------*/

static void
sslui_paranoia_callback(w, ctrls)
	GtkWidget * w;
	struct arglist * ctrls;
{
	GSList * list = arg_get_value(ctrls, "LEVEL_RADIO");
	int value;
	if(list)
		while(list)
		{
			GtkWidget * button = list->data;
			if(GTK_TOGGLE_BUTTON(button)->active)
			{
				value = (int)gtk_object_get_data(GTK_OBJECT(button), "level");
				arg_add_value(ctrls, "LEVEL", ARG_INT,
				sizeof(value), (void*)value);
				gtk_grab_remove(arg_get_value(ctrls, "WINDOW"));
				close_window(NULL, arg_get_value(ctrls, "WINDOW"));
				gtk_widget_destroy(arg_get_value(ctrls, "WINDOW"));
				gtk_main_quit();
				return;
			}
			list = list->next;
		}
}
static void 
build_dialog(ctrls, prompt)
 struct arglist * ctrls;
 char * prompt;
{
 GtkWidget * w, * table, * ok;
 GtkStyle  * style;
 GtkWidget * pixmapwid;
 GdkPixmap * pixmap;
 GdkBitmap * mask;
 GtkWidget * hbox, * vbox, * label, *sep, *box;
 GtkWidget * button, * first_button;
 GtkWidget * otable;
 w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_window_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
 gtk_widget_realize(w);
 
 style = gtk_widget_get_style(w);
 pixmap = gdk_pixmap_create_from_xpm_d(w->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(char **)lock_xpm);
 pixmapwid = gtk_pixmap_new(pixmap, mask);   
 
 
 gtk_window_set_title(GTK_WINDOW(w), "SSL Setup");
 gtk_container_border_width(GTK_CONTAINER(w), 5);
 arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, w);
 
 
 vbox = gtk_vbox_new(FALSE, 5);
 hbox = gtk_hbox_new(FALSE, 5);
 
 
 
 gtk_container_add(GTK_CONTAINER(w), hbox);
 gtk_widget_show(hbox);
 
 gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);
 gtk_widget_show(vbox);
 
 gtk_box_pack_start(GTK_BOX(vbox), pixmapwid, FALSE, FALSE, 0);
 gtk_widget_show(pixmapwid);
 
 sep = gtk_vseparator_new();
 gtk_box_pack_start(GTK_BOX(hbox), sep, FALSE, FALSE, 5);
 gtk_widget_show(sep);
 
 vbox = gtk_vbox_new(FALSE, 5);
 gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);
 gtk_widget_show(vbox);
 
 box = gtk_hbox_new(FALSE, 5);
 gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 10);
 gtk_widget_show(box);
 
 label = gtk_label_new(prompt);
  gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 10);
 gtk_widget_show(label);
 
 table  = gtk_table_new(3,1,TRUE);
 gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, 5);
 gtk_container_border_width(GTK_CONTAINER(table), 10);
 gtk_widget_show(table);
 
 
 first_button = gtk_radio_button_new_with_label(
		 NULL,
		 "Display and remember the server certificate, do not care about the CA");

 gtk_object_set_data(GTK_OBJECT(first_button), "level", (void*)1);
 gtk_table_attach_defaults(GTK_TABLE(table), first_button,0,1,0,1);
 
 
 /*TABLE*/
 gtk_widget_show(first_button);
 button = gtk_radio_button_new_with_label(
		 gtk_radio_button_group(GTK_RADIO_BUTTON(first_button)),
		 "Trust the server certificate if and only if it is valid and certified by the CA");

 gtk_object_set_data(GTK_OBJECT(button), "level", (void*)2);
 gtk_table_attach_defaults(GTK_TABLE(table), button,0,1,1,2);
 /*TABLE*/
 gtk_widget_show(button);
 button = gtk_radio_button_new_with_label(
		 gtk_radio_button_group(GTK_RADIO_BUTTON(first_button)),
		 "Verify that the server certificate is valid *and* remember it");

 gtk_object_set_data(GTK_OBJECT(button), "level", (void*)3);
 gtk_table_attach_defaults(GTK_TABLE(table), button,0,1,2,3);
 /*TABLE*/
 gtk_widget_show(button);


 
 arg_add_value(ctrls, "LEVEL_RADIO", ARG_PTR,-1, gtk_radio_button_group(GTK_RADIO_BUTTON(first_button)));
 
 ok = gtk_button_new_with_label("Ok");
 gtk_signal_connect(GTK_OBJECT(ok), "clicked", 
 		    (GtkSignalFunc)sslui_paranoia_callback, 
		    (void*)ctrls);
		    
 
 otable = gtk_table_new(1,2, TRUE);
 gtk_table_attach_defaults(GTK_TABLE(table), otable, 0,1,5,6);
 gtk_widget_show(otable);
 gtk_table_attach_defaults(GTK_TABLE(otable), ok, 1,2,0,1);
 GTK_WIDGET_SET_FLAGS(ok, GTK_CAN_DEFAULT);
 gtk_widget_grab_default(ok);
 gtk_widget_show(ok);
 gtk_widget_show(w);
 gtk_grab_add(w);
}



/*-------------------------------------------------------------------------*/
#endif /* GTK_UI */




/*
 * Ask the level of paranoia the user wants to set.
 *
 * Returns :
 *	<-1>    : An error occured
 *	<0|1|2> : The level of paranoia selected by the user
 */ 
int
sslui_ask_paranoia_level()
{
	int ret;
	static char question[] = "\
Please choose your level of SSL paranoia (Hint: if you want to manage many\n\
servers from your client, choose 2. Otherwise, choose 1, or 3, if you are \n\
paranoid.\n";	
	
#ifdef USE_GTK
	if(!F_quiet_mode)
	{
	 struct arglist * ctrls = emalloc(sizeof(*ctrls));
	 build_dialog(ctrls, question);
	 gtk_main();
        ret =  (int)arg_get_value(ctrls, "LEVEL");
	arg_free(ctrls);
	return ret;
	}
  else
#endif

  do {
  printf("%s", question);
  ret = 0;
  }
  while(scanf("%d", &ret) == 0);
  if(ret >= 1 && ret <= 3)
   {
   return ret;
   }
  else 
   return -1;
}

/*-------------------------------------------------------------------------*/
#ifdef USE_GTK


static void
showcert_cb(w, ctrls, accept)
 GtkWidget * w;
 struct arglist * ctrls;
 int accept;
{
 gtk_widget_hide(arg_get_value(ctrls, "WINDOW"));
 gtk_widget_destroy(arg_get_value(ctrls, "WINDOW"));
 if(accept)
  arg_add_value(ctrls, "RESULT", ARG_INT, sizeof(int),(void*) 1);
 gtk_main_quit();
}


static void 
showcert_accept_cb(w, ctrls)
 GtkWidget* w;
 struct arglist *ctrls;
{
 showcert_cb(w,ctrls, 1);
}

static void
showcert_refuse_cb(w, ctrls)
 GtkWidget* w;
 struct arglist *ctrls;
{
 showcert_cb(w,ctrls, 0);
}




static struct arglist * 
sslui_showcert(cert)
 char * cert;
{
 struct arglist * ctrls = emalloc(sizeof(*ctrls));
 GtkWidget * w;
 GtkWidget * vbox, *hbox;
 GtkWidget * label, *text, *table, *vsb, *sep,*button;
 GtkAdjustment * vadj;
 w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_VERSION > 10
 gtk_window_set_default_size(GTK_WINDOW(w), 640, 480);
#else
 gtk_widget_set_usize(GTK_WIDGET(w), 640, 480);
#endif
 gtk_window_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
 gtk_widget_realize(w);
 arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, w);
 
 vbox = gtk_vbox_new(FALSE, 5);
 gtk_container_add(GTK_CONTAINER(w), vbox);
 gtk_widget_show(vbox);
 
 label = gtk_label_new("This certificate has never been shown before. \
Here it is : ");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 5);
 gtk_widget_show(label);
 
 vadj = GTK_ADJUSTMENT (gtk_adjustment_new (0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
 vsb = gtk_vscrollbar_new(vadj);
 table = gtk_table_new(1,2,FALSE);
 gtk_box_pack_start(GTK_BOX(vbox), table, TRUE, TRUE, 0);
 gtk_widget_show(table);
 
 text = gtk_text_new(NULL, vadj);
 gtk_table_attach(GTK_TABLE(table), vsb, 1, 2, 0, 1, 0,
 			GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0);
 gtk_table_attach(GTK_TABLE(table), text, 0,1,0,1,
 			GTK_EXPAND | GTK_SHRINK | GTK_FILL,
			GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0);
			
 gtk_container_border_width(GTK_CONTAINER(table), 2);
 gtk_widget_show(vsb);
 gtk_widget_realize(text);
 gtk_text_set_editable(GTK_TEXT(text), FALSE);
 gtk_text_set_word_wrap(GTK_TEXT(text), TRUE);
 gtk_text_insert(GTK_TEXT(text), NULL, NULL, NULL, cert, -1);
 gtk_widget_show(text);						
 
 sep = gtk_hseparator_new();
 gtk_box_pack_start(GTK_BOX(vbox), sep, FALSE, FALSE, 0);
 gtk_widget_show(sep);
 
 label = gtk_label_new("Do you accept this certificate ?");
 gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 

 
 hbox = gtk_hbox_new(FALSE, 5);
 gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
 gtk_widget_show(hbox);
 
 button = gtk_button_new_with_label("Yes");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect(GTK_OBJECT(button), "clicked",
 	GTK_SIGNAL_FUNC(showcert_accept_cb), ctrls);
 gtk_widget_show(button);
 
 button = gtk_button_new_with_label("No");
 gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
 gtk_signal_connect(GTK_OBJECT(button), "clicked",
 	GTK_SIGNAL_FUNC(showcert_refuse_cb), ctrls);
 gtk_widget_show(button);
 
 
 gtk_widget_show(w);
 gtk_window_set_modal(GTK_WINDOW(w), TRUE);
 return ctrls;
}


#endif /* USE_GTK */


/*
 * Shows the SSL certificate to the user.
 *
 * Input: 
 *	<ssl>   : the ssl connection
 *
 *
 * Output: 
 *	<0>  : the certificate is accepted
 *	<-1> : the certificate is invalid
 */ 
int
sslui_check_cert(ssl)
	SSL * ssl;
{
 char * ascii_cert;
 X509 * cert = SSL_get_peer_certificate(ssl);
 BIO * b;
 BUF_MEM * bptr;
 int x;
 
 b = BIO_new(BIO_s_mem());
 if(X509_print(b, cert) > 0)
 {
  BIO_get_mem_ptr(b, &bptr);
  ascii_cert = emalloc(1 + bptr->length);
  memcpy(ascii_cert, bptr->data, bptr->length);
 }
 else
 {
  ascii_cert = emalloc(1024);
  sprintf(ascii_cert, "This certificate has never been seen before and can't be shown\n");
 }
 BIO_free(b);
 
#ifdef USE_GTK 
 if(!F_quiet_mode)
 {
  int ret;
  struct arglist * ctrls = sslui_showcert(ascii_cert);
  efree(&ascii_cert);
  gtk_main();
  ret =  (int)arg_get_value(ctrls, "RESULT");
  arg_free(ctrls);
  if(ret) 
    return 0;
  else
    return -1;
 }
#endif
 printf("%s\n", ascii_cert);
 printf("Do you accept it ? (y/n) ");
 fflush(stdout);
 do {
  x = getchar();
 } while (x != EOF && x !='y' && x != 'n');
 
 return (x == 'y') ? 0:-1;
}
	
	

char*
sslui_ask_trusted_ca_path()
{
 return NULL;
}
#endif /* NESSUS_ON_SSL */
