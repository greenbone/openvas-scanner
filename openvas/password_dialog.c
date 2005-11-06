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

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif
#ifdef HAVE_SETJMP_H
# include <setjmp.h>
#endif

#ifdef USE_GTK
#include <gtk/gtk.h>
#include "xpm/lock.xpm"
#include "error_dialog.h"
#include "password_dialog.h"
#include "xstuff.h"
static void pass_build_dialog(struct arglist *, char *);
static void pass_dialog_callback(void *, struct arglist *);
#endif
#include "globals.h"

/* fixing the problem when nessus is started in the background while
   the user is requested to enter a pass phrase */

#define BLURB " --- better you start in the foreground.\n"

#ifdef SIGTTOU
/* this is the preferable soulution printing an error message
   and terminating nessus  */
static jmp_buf jenv;

static void
die_on_background_tty
  (int sig)
{
  signal (sig, SIG_IGN);
  fputs ("\n\nNo password dialogue possible" BLURB, stderr);
  longjmp (jenv, -1);
}

static char *
verify_tty_getpass
  (const char *prompt)
{
  /* when getpass tries to write the password prompt on the background,
     a stop-output signal will be risen, if available  */
  void (*fn)(int) = signal (SIGTTOU, die_on_background_tty);
  if (setjmp (jenv) == 0) {
    char *s = getpass (prompt);
    signal (SIGTTOU, fn);
    return s;
  }
  return (char*)-1;
}
#define getpass(s) verify_tty_getpass (s)
#else  /* SIGTTOU */

#ifdef TCION /* found in termios */

/* this is a fall back, only taking care that input can be 
   read  when getting back into the forground, again */
static char *
retrieve_tty_getpass
  (const char *prompt)
{
  int fd ;
  if ((fd = open ("/dev/tty", O_RDONLY)) < 0) {
    fprintf (stderr, "Cannot open tty (%s)" BLURB, strerror (errno)) ;
    exit (0);
  }
  /* this causes getpass() to retrieve the input properly once 
     it has been brought back in the foreground, again */
  if (tcflow (fd, TCION) < 0) {
    fprintf (stderr, "Cannot access tty (%s)" BLURB, strerror (errno)) ;
    exit (0);
  }
  close (fd);
  return getpass (prompt);
}
#define getpass(s) retrieve_tty_getpass (s)
#endif /* SIGTTOU */
#endif /* TCION */ 
#undef BLURB

#ifdef USE_GTK

static void
pass_build_dialog(ctrls, prompt)
 struct arglist * ctrls;
 char * prompt;
{
 GtkWidget * w, * table, * entry, * ok;
 GtkStyle  * style;
 GtkWidget * pixmapwid;
 GdkPixmap * pixmap;
 GdkBitmap * mask;
 GtkWidget * hbox, * vbox, * label, *sep, *box;
 w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_window_position(GTK_WINDOW(w), GTK_WIN_POS_CENTER);
 gtk_widget_realize(w);
 
 style = gtk_widget_get_style(w);
 pixmap = gdk_pixmap_create_from_xpm_d(w->window, &mask,
					&style->bg[GTK_STATE_NORMAL],
					(char **)lock_xpm);
 pixmapwid = gtk_pixmap_new(pixmap, mask);   
 
 
 gtk_window_set_title(GTK_WINDOW(w), "Password");
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
 
 table  = gtk_table_new(2,2,TRUE);
 gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, 5);
 gtk_container_border_width(GTK_CONTAINER(table), 10);
 gtk_widget_show(table);
 
 
 entry = gtk_entry_new();
 gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
 gtk_table_attach_defaults(GTK_TABLE(table), entry,0,2,0,1);
 gtk_widget_show(entry); 
 arg_add_value(ctrls, "PASSWORD", ARG_PTR, -1, entry);
 
 ok = gtk_button_new_with_label("Ok");
 gtk_signal_connect(GTK_OBJECT(ok), "clicked", 
 		    (GtkSignalFunc)pass_dialog_callback, 
		    (void*)ctrls);
		    
 gtk_table_attach_defaults(GTK_TABLE(table), ok, 1,2,1,2);
 GTK_WIDGET_SET_FLAGS(ok, GTK_CAN_DEFAULT);
 gtk_widget_grab_default(ok);
 gtk_widget_show(ok);
 gtk_widget_show(w);
 gtk_grab_add(w);
}


static void pass_dialog_callback(nul, ctrls)
 void * nul;
 struct arglist * ctrls;
{
 GtkWidget * pass = (GtkWidget *)arg_get_value(ctrls, "PASSWORD");
 char * pass_str;

 gtk_grab_remove(arg_get_value(ctrls, "WINDOW"));
 pass_str = (char*)gtk_entry_get_text(GTK_ENTRY(pass));
 if(!pass_str || !strlen(pass_str))
 	show_warning("You must enter a valid password");
 else {
    	char * s = estrdup(pass_str);
        close_window(NULL, arg_get_value(ctrls, "WINDOW"));
 	arg_add_value(ctrls, "PASSWORD_TEXT", ARG_STRING, strlen(s), s);
       }
}


char *
pass_dialog (int unused)
{
 struct arglist * ctrls;
 char * ret;
 
 ctrls = emalloc(sizeof(struct arglist));
 pass_build_dialog(ctrls, "Password required : ");
 while(!arg_get_value(ctrls, "PASSWORD_TEXT"))
  while(gtk_events_pending()){
  	gtk_main_iteration();
#if !defined(WIN32) && !defined(_WIN32)
	usleep(10000);
#endif
	}	
 ret = estrdup(arg_get_value(ctrls, "PASSWORD_TEXT"));
 arg_free(ctrls);
 return(ret);
}

char *
keypass_dialog (int unused)
{
 struct arglist * ctrls;
 char * ret;
 
 ctrls = emalloc(sizeof(struct arglist));
 pass_build_dialog(ctrls, "Pass phrase : ");
 while(!arg_get_value(ctrls, "PASSWORD_TEXT"))
  while(gtk_events_pending()){
    gtk_main_iteration();
#if !defined(WIN32) && !defined(_WIN32)
    usleep(10000);
#endif
  }
 ret = estrdup(arg_get_value(ctrls, "PASSWORD_TEXT"));
 arg_free(ctrls);
 return(ret);
}
#endif /* USE_GTK */

/* non GUI password dialogue */
char* 
cmdline_pass
  (int unused)
{
  return getpass ("Server password: "); 
}

 
/* used for private key activation */
static int __created_key = 0;

int /* return just-generated-private-key status */
created_private_key 
 (void)
{
  int n = __created_key ;
  __created_key = 0 ;
  return n;
}

char* 
get_pwd 
 (int mode) {
  char *s, *t ;

  switch (mode) {
  case 0:
    /* key activation mode */
    if(F_quiet_mode)return getpass("Pass phrase: ");
    else
#ifdef USE_GTK
    return keypass_dialog (0);
#else
    return getpass("Pass phrase: ");
#endif    
  case 2:
    __created_key ++ ;
#   ifdef FIRST_PWD_BLURB
    fflush (stderr);
    printf ("%s", FIRST_PWD_BLURB);
    fflush (stdout);
#   endif
  }

  if ((s = getpass ("New pass phrase: ")) == 0 || s == (char*)-1)
    return (char*)-1;
  s = estrdup (s);
  if ((t = getpass ("Repeat         : ")) == 0 || t == (char*)-1) {
    efree (&s);
    return (char*)-1;
  }
  if (strcmp (s, t) != 0)
    t = 0 ;
  efree (&s);
  if (t == 0)
    return (char*)-1;
  return t ;
}
 
 
 
