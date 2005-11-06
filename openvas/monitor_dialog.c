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
 */

#include <includes.h>

#include "backend.h"
#if USE_GTK 
#include <gtk/gtk.h>

#include "attack.h"
#include "xstuff.h"
#include "comm.h"
#include "auth.h"
#include "parser.h"             
#include "report.h"
#include "globals.h"
#include "error_dialog.h"
#include "xpm/computer.xpm"
#include "monitor_dialog.h"
#include "report_ng.h"

/*static char ** plugins_order_table = NULL;*/
static harglst * plugins_order_table = NULL;

static void monitor_input_callback(struct arglist *, int, int);
static void monitor_add_host(struct arglist *, char *, int);
static void monitor_stop_test(GtkWidget *, char *);
static void monitor_list_update(struct arglist *, char *, int);
static int monitor_stop_whole_test_destroy(void*, void*, struct arglist *);
static int monitor_stop_whole_test(GtkWidget * , struct arglist *);
static void build_plugins_order_table(char *);

struct gui_host {
	GtkWidget * gui;
	struct arglist * ctrls;
	struct gui_host * next;
};



static int 
is_server_present(soc)
	int soc;
{
	fd_set  rd;
	struct timeval tv = {2,0};
	int fd = nessus_get_socket_from_connection(soc);

	if(fd < 0 || fd >= FD_SETSIZE)
	{
	 fprintf(stderr, "is_server_present: fd(%d) out of range\n", fd);
	 return 0;
	}
	FD_ZERO(&rd);
	FD_SET(fd, &rd);
	if(select(fd+1, &rd, NULL, NULL, &tv) > 0)
	{
		int len = -1;
		ioctl(fd, FIONREAD, &len);
		if(!len){
			return 0;
			}
	}
	return 1;
}





/*
 * Function called when the UI is idle, which checks
 * whether the server sent us anything. We use this rather
 * than the traditional gdk input watcher, because it
 * works under Win32
 */
static int
idle_socket(struct arglist * ctrls)
{
  fd_set rd;
  struct timeval tv = {0,100};
  int n, soc;
  if(GlobalSocket < 0)
    {
      fprintf(stderr, "idle_socket: GlobalSocket=%d\n", GlobalSocket);
      return FALSE;
    }
  soc = nessus_get_socket_from_connection(GlobalSocket);
  if((soc < 0) || (soc >= FD_SETSIZE))
  {
   fprintf(stderr, "idle_server: soc(%d) out of range\n", soc);
   return -1;
  }
  FD_ZERO(&rd);
  FD_SET(soc, &rd);
  n = select(soc+1, &rd, NULL, NULL, &tv);
  if(FD_ISSET(soc, &rd)&& (n > 0))
    monitor_input_callback(ctrls, soc /* ? Not used */, 0);
  return TRUE;
}

/*
 * monitor_dialog_setup
 *
 * This function draws the window which will
 * show the attack status
 */
void 
monitor_dialog_setup(victim, restore)
     char * victim;
     int restore;
{
  struct arglist * ctrls = emalloc(sizeof(struct arglist));
  GtkWidget * scrolled_window; 
  GtkWidget * w, * box;
  char* window_title;
  char* host_name;
  int tag;
  int backend = backend_init(NULL);

  /* Could not create a backend */
  if( backend < 0 )
  {
    gtk_widget_show(arg_get_value(MainDialog, "WINDOW"));
    return;
  }
  

  arg_add_value(ctrls, "MONITOR_BACKEND", ARG_INT, -1, (void*)backend);
  
  w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_VERSION > 10
  gtk_window_set_default_size(GTK_WINDOW(w), 640,480);
#else
  gtk_widget_set_usize(GTK_WIDGET(w), 640, 480);
#endif

  gtk_widget_realize(w);
  gtk_signal_connect(GTK_OBJECT(w), "delete_event",
		     (GtkSignalFunc)monitor_stop_whole_test_destroy,ctrls);
		     
  host_name = arg_get_value(Prefs, "nessusd_host");
  if(host_name)window_title = emalloc(strlen(host_name) + 255);
  else window_title = emalloc(255);
  sprintf(window_title, "Scanning network from %s",
  	host_name?host_name:"some host");		     
  gtk_window_set_title(GTK_WINDOW(w), window_title);
  efree(&window_title);
  gtk_container_border_width(GTK_CONTAINER(w), 10);
  arg_add_value(ctrls, "WINDOW", ARG_PTR, -1, w);
  gtk_widget_show(w);
  
  box = gtk_vbox_new(FALSE,10);
  gtk_container_add(GTK_CONTAINER(w), box);
  gtk_widget_show(box);
  
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_container_border_width (GTK_CONTAINER (scrolled_window), 10);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
				  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
				
  gtk_container_border_width(GTK_CONTAINER(scrolled_window), 10);  
  gtk_box_pack_start(GTK_BOX(box), scrolled_window, TRUE, TRUE, 0);
  
  w = gtk_list_new();
#if GTK_VERSION < 11
  gtk_container_add(GTK_CONTAINER(scrolled_window), w);
#else
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window), w);
#endif
  gtk_widget_show(w);
  gtk_widget_show (scrolled_window);
  arg_add_value(ctrls, "LIST", ARG_PTR, -1, w);
                    

  
  tag = gtk_idle_add((GtkFunction)idle_socket, ctrls);
  
  arg_add_value(ctrls, "TAG", ARG_INT, sizeof(int), (void*)tag);
  w = gtk_button_new_with_label("Stop the whole test");
  gtk_signal_connect(GTK_OBJECT(w), "clicked",
		     (GtkSignalFunc)monitor_stop_whole_test,ctrls);
  gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 0);
  gtk_widget_show(w);
#if ENABLE_SAVE_TESTS
  if(restore)
   restore_attack(victim, Prefs);
  else
#endif
   attack_host(victim, Prefs);
}

/*
 * monitor_list_update
 *
 * Updates the progress bars
 */	
static void 
monitor_list_update(ctrls,msg, short_status)
	struct arglist * ctrls;
	char * msg;
	int short_status;
{
 char * hostname;
 char * action;
 char* current = NULL;
 int max;
 gfloat gmax;
 gfloat gcurrent;
 GList * dlist;
 GtkObject * item;
 GtkWidget * gtkw;
 char * list_hostname;
 int flag = 0;
 static harglst * hosts = NULL;
 int v = 1;
 
 if(!hosts)
 {
  hosts = harg_create(65000);
 }

 
 if(!short_status)
  parse_nessusd_status(msg, &hostname, &action, &current, &max);
 else
  parse_nessusd_short_status(msg, &hostname, &action, &current, &max);
 
 if(hostname)
 {
 v = harg_get_int(hosts, hostname);
 if(!v){
  harg_add_int(hosts, hostname, 1);
  v = 1;
  }
 else
  {
  v++;
  harg_set_int(hosts, hostname, v);
  }
 }
 
 gtkw = arg_get_value(ctrls, "LIST");
 dlist = GTK_LIST(gtkw)->children;
 while(dlist && !flag)
 {
  item = GTK_OBJECT(dlist->data);
  list_hostname = gtk_object_get_data(item, "hostname");
  if(!list_hostname){
  	fprintf(stderr, "Error ! Null hostname in the list\n");
  	/*exit(1);*/
	return;
  	}
  if(!strcmp(list_hostname, hostname))
  {
   GtkWidget * progress_bar;
   gfloat f;
   
   if( strcmp(action, "portscan") == 0 )
    progress_bar = gtk_object_get_data(item, "progress_bar_portscan");
   else
    progress_bar = gtk_object_get_data(item, "progress_bar_attack");
    
   gmax = max;
   gcurrent = atoi(current);
   f = (gcurrent/gmax);
   if(f>=1.0)f=1.0;
   if(f<=0.0)f=0.0;
   gtk_progress_bar_update (GTK_PROGRESS_BAR(progress_bar), f);

   flag = 1;
  }
  dlist = dlist->next;
 }
 
 if(!flag)
 {
 /* the host was not found, we must add one... */
 monitor_add_host(ctrls, estrdup(hostname), atoi(current));
 }
 
 efree(&hostname);
 efree(&action);
 if(current)efree(&current);
 
}
 
/*
 * monitor_remove_host
 */
static void
monitor_remove_host(ctrls, host)
 struct arglist * ctrls;
 char * host;
{
 GtkWidget * item;
 GList * list = NULL;
 item =  gtk_object_get_data(GTK_OBJECT(arg_get_value(ctrls, "LIST")),host);
 
 if(!item){
#ifndef ENABLE_SAVE_KB
	/*
	 * If this happens, then it's very likely that the server
	 * thinks the communication has been cut between the client
	 * and itself. Which is not a good thing.
	 */
 	fprintf(stderr, "warning. Could not find entry for %s\n", host);
	fprintf(stderr, "This may be a bug - please check the nessusd logfile\n");
	fprintf(stderr, "and if you see something about a lost connection,\n");
	fprintf(stderr, "or any odd message, please report it to deraison@cvs.nessus.org\n");
#endif	
	return;
	}
 
 if(item != (void*)-1)
 {
 list = g_list_append(list, item);
 gtk_list_remove_items(GTK_LIST(arg_get_value(ctrls, "LIST")), list);
 gtk_object_remove_data(GTK_OBJECT(arg_get_value(ctrls, "LIST")), host);
 g_list_free(list);
 }
}

 
 



/*
 * monitor_add_host
 *
 * this function adds a new hostname and progress bar in
 * the monitor window
 */
void 
monitor_add_host(ctrls,hostname,port)
	struct arglist * ctrls;
	char * hostname;
	int port;
{
 GtkWidget * progress_bar_portscan;
 GtkWidget * progress_bar_attack;
 GtkWidget * table;
 GtkWidget * label;
 GtkWidget * item;
 GtkWidget * button;
 GtkWidget * separator;
 GtkWidget * box, * hbox;
 GtkStyle  * style;
 GtkWidget * pixmapwid;
 GList * dlist;
 GtkWidget * window = arg_get_value(ctrls,"WINDOW");

 item = gtk_list_item_new();
 dlist = NULL;
 table = gtk_table_new(4, 3, FALSE);
 gtk_table_set_col_spacings(GTK_TABLE(table), 15);
 gtk_table_set_row_spacings(GTK_TABLE(table),  5);
 
 gtk_container_add(GTK_CONTAINER(item), table);
 
 hbox = gtk_hbox_new(FALSE,0);
 gtk_widget_show(hbox);
 
 gtk_table_attach_defaults(GTK_TABLE(table), hbox, 0,1,0,3); 
 
 
 /*
  * Host name
  */

    
 box = gtk_vbox_new(TRUE,0);
 gtk_widget_show(box);
 gtk_box_pack_start(GTK_BOX(hbox), box, FALSE, FALSE, 0);
 if(F_show_pixmaps)
 {
  style = gtk_widget_get_style(window);
  pixmapwid = make_pixmap(window, &style->bg[GTK_STATE_NORMAL], (gchar**)computer_xpm);
 
 gtk_box_pack_start(GTK_BOX(box), pixmapwid, FALSE, FALSE, 0);
 gtk_widget_show(pixmapwid);
 }
 label = gtk_label_new(hostname);
 gtk_object_set_data(GTK_OBJECT(item), "label", label);
 gtk_widget_set_usize(label, 150, 15);
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 /*
  * Portscan, Attack and Plugin labels
  */
 box = gtk_vbox_new(TRUE, 0);
 gtk_widget_show(box);
 gtk_box_pack_end(GTK_BOX(hbox), box, FALSE, FALSE, 0);
 
 label = gtk_label_new("Portscan : ");
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 label = gtk_label_new("Checks : ");
 gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
 gtk_widget_show(label);
 
 /*
  *  Progress bars
  */
 
 box = gtk_vbox_new(FALSE,0);
 gtk_table_attach_defaults(GTK_TABLE(table), box, 1,2,0,3); 
  gtk_widget_show(box);
 progress_bar_portscan = gtk_progress_bar_new();
 /*
 gtk_table_attach_defaults(GTK_TABLE(table),progress_bar_portscan, 1,2,0,1);
 */
 gtk_box_pack_start(GTK_BOX(box), progress_bar_portscan, TRUE, TRUE,0);
 gtk_widget_show(progress_bar_portscan);
 
 progress_bar_attack = gtk_progress_bar_new();
 /*
 gtk_table_attach_defaults(GTK_TABLE(table),progress_bar_attack, 1,2,1,2);
 */
 gtk_box_pack_start(GTK_BOX(box), progress_bar_attack, TRUE, TRUE,0);
 gtk_widget_show(progress_bar_attack);
 
 
 
 /*
  * Stop button
  */
 box = gtk_vbox_new(TRUE,0);
 gtk_table_attach_defaults(GTK_TABLE(table), box, 2,3,0,2);
 gtk_widget_show(box);
 
 button = gtk_button_new_with_label("Stop");
 gtk_signal_connect(GTK_OBJECT(button), "clicked",
		     (GtkSignalFunc)monitor_stop_test, hostname);
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 0);
 gtk_widget_show(button);
 
 separator = gtk_hseparator_new();
 gtk_table_attach_defaults(GTK_TABLE(table), separator, 0,3,3,4);
 gtk_widget_show(separator);


    

 gtk_object_set_data(GTK_OBJECT(item), "hostname", hostname);
 gtk_object_set_data(GTK_OBJECT(item), "progress_bar_attack", progress_bar_attack);
 gtk_object_set_data(GTK_OBJECT(item), "progress_bar_portscan", progress_bar_portscan);
 gtk_widget_show(table);
 gtk_widget_show(item);
 dlist = g_list_append(dlist, item);
 gtk_object_set_data(GTK_OBJECT(arg_get_value(ctrls, "LIST")), hostname,item);
 gtk_list_append_items(GTK_LIST(arg_get_value(ctrls, "LIST")), dlist);
 }
 
 
/*  
 * monitor_stop_test
 * 
 * This function will stop the connection between
 * nessusd and the client, and will report the results
 * to the screen
 */
 
static int
monitor_stop_whole_test_destroy(a,b,ctrls)
 void * a, * b;
 struct arglist * ctrls;
{
 return monitor_stop_whole_test(NULL, ctrls);
}
static int
monitor_stop_whole_test(w, ctrls)
 GtkWidget * w;
 struct arglist * ctrls;
{
 int type = 0, n;
 char * msg;
 char buf[32768];
 network_printf( "CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n");
 efree(&ArgSock);
 gtk_idle_remove((int)arg_get_value(ctrls, "TAG"));
 
 /*
  * Read the data remaining...
  */
 while(type != MSG_BYE)
 {
  buf[sizeof(buf) - 1] = '\0';
  network_gets_raw(buf, sizeof(buf) - 1);
   if( buf[0] == '\0') {
  	break;
	}
  if ((n = strlen (buf)) && buf [n-1] == '\n') buf [n-1] = '\0';
  msg  = emalloc(strlen(buf)+1);
  type = parse_server_message(buf, (int)arg_get_value(ctrls, "MONITOR_BACKEND"), msg);
  efree(&msg);
 }
  
 F_nessusd_running = 0;
 gtk_widget_hide(arg_get_value(ctrls, "WINDOW"));
 report_tests_ng((int)arg_get_value(ctrls, "MONITOR_BACKEND"), 0);
 return(FALSE);
}


/*
 * monitor_input_callback
 *
 * This function is called whenever there is new
 * data coming from the server. 
 */
void 
monitor_input_callback(ctrls, fd, condition)
    struct arglist * ctrls;
    int fd;
    int condition;
{
  int finished = 0;
  static char * buf = NULL;
  static int    bufsz = 0;
  static char * msg  = NULL;
  int n, type = -1;
  int interrupted = 0;

  if ( buf == NULL )
  {
   bufsz = 1024 * 1024;
   buf   = emalloc( bufsz );
   msg   = emalloc( bufsz );
  }
  network_gets_raw( buf, bufsz );
  if ((n = strlen (buf)) && buf [n-1] == '\n') buf [n-1] = '\0';

  if( buf[0] == '\0') {
  	if(!is_server_present(GlobalSocket))
	{
  	 interrupted++;
   	 goto scan_finished;
	}
        else return;
       }	

  type = parse_server_message(buf, (int)arg_get_value(ctrls, "MONITOR_BACKEND"), msg);
 
  switch(type)
  {
  	case MSG_BYE : 
		network_printf("CLIENT <|> BYE <|> ACK\n");
  		finished = 1;
  		break;
	case MSG_STAT2 : 
		monitor_list_update(ctrls,buf+2, 1);	
		break;
  	case MSG_STAT :
  	 	monitor_list_update(ctrls, msg, 0);
  		break;
        case MSG_PLUGINS_ORDER :
        	build_plugins_order_table(msg);
                break;
	case MSG_FINISHED :
		monitor_remove_host(ctrls, msg);
		break;	
  }
  buf[0] = '\0';
  msg[0] = '\0';
  
  if(finished)
    {
   scan_finished : 
      F_nessusd_running = 0;
      gtk_widget_hide(arg_get_value(ctrls, "WINDOW"));
      gtk_idle_remove((int)arg_get_value(ctrls, "TAG"));
      gtk_widget_destroy(arg_get_value(ctrls, "WINDOW"));
      report_tests_ng((int)arg_get_value(ctrls, "MONITOR_BACKEND"), interrupted);
    }
}
 
/*
 * monitor_stop_test
 *
 * this function stops one test
 */
void 
monitor_stop_test(w,hostname)
	GtkWidget * w;
	char * hostname;
{
 network_printf("CLIENT <|> STOP_ATTACK <|> %s <|> CLIENT\n", hostname);
}
 
static void build_plugins_order_table(order)
 char * order;
{
 int num = 0;
 char * t;
 int i = 0;
 int * plugins_order_table_int;
 t = order;

 if(plugins_order_table)
  harg_close(plugins_order_table);
 
 
 while((t = strchr(t+1, ';')))num++;
 plugins_order_table_int = emalloc((num+1)*sizeof(int));
 t = order;
 if(num)
 while(t)
 {
  char * next = strchr(t, ';');
  if(next)next[0]=0;
  plugins_order_table_int[i++] = atoi(t);
  if(next)next[0]=';';
  t = next+1;
  next = strchr(next+1, ';');
  if(!next)t = NULL;
 }
 
 /*
  * Now, create the names table
  */
  plugins_order_table = harg_create(num*3 + 1);
  
  for(i=0;i<num;i++)
  {
   struct arglist * plugs = Plugins;
   
   while(plugs && plugs->next && 
        ((int)(arg_get_value(plugs->value, "ID"))!=plugins_order_table_int[i]))
         plugs = plugs->next;
   if(!(plugs && plugs->next))
   {
    plugs = Scanners;
    while(plugs && plugs->next && 
        ((int)(arg_get_value(plugs->value, "ID"))!=plugins_order_table_int[i]))
         plugs = plugs->next;
   }
   if(plugs){
   	char * id = emalloc(20);
	sprintf(id, "%d", i+1);
   	harg_add_string(plugins_order_table, id, plugs->name);
	efree(&id);
	}
  }
  efree(&plugins_order_table_int);
}
#endif
