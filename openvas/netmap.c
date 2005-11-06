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
 ****************************************************************
 *
 *		THIS DOES NOT WORK YET. 
 *
 *	I need some help in the drawing of the hosts. Feel free
 *  to offer yours
 *
 *
 */
 
#include <includes.h>

#ifdef USE_GTK
#include <gtk/gtk.h>
#include "globals.h"

#ifdef NOT_READY

/* Private functions */


harglst * GTKNetMap; /* This one is linear */
struct netitem {
	GtkWidget * item;
	GtkWidget * parent;
	};
static GtkWidget * map_create_window(int, int);
static struct netitem * map_add_item(GtkWidget*, GtkWidget*, int, int, char *);
static harglst* map_add_items(GtkWidget *, GtkWidget*, harglst *, harglst*, int, int, int );



/*----------------------------------------------------------------------*
 *									*
 *   			Tree Management routines		        *
 *									*
 *----------------------------------------------------------------------*/
 
 
 
/*
 * Return the height of a tree
 *
 * ie :
 *			a
 *		b		c
 *			     d	   e
 *			   f
 *
 * Height : 4 (a to f)
 *
 */
int net_height(harglst * a)
{
 hargwalk * hw;
 int m = 0;
 char * key;
 
 if(!a)
  return 0;
  
 hw = harg_walk_init(a);
 while((key = harg_walk_next(hw)))
 {
  int h = net_height(harg_get_harg(a, key));
  if(h > m)m=h;
 }
 /*harg_walk_stop(hw);*/
 return 1+m;
}

/*
 * Return the width of a tree
 *
 * ie :
 *
 *			a
 *		b		c
 *			    d       e
 *
 * Width : 3 (b,d,e)
 *
 */
int net_width(harglst * a)
{
 hargwalk * hw;
 char* key;
 int sum = 0;
 int flag = 0; 
 if(!a)
   return 0;
 hw = harg_walk_init(a);
 while((key = harg_walk_next(hw)))
 {
  flag++;
  sum += net_width(harg_get_harg(a, key));
 }
 /*harg_walk_stop(hw);*/
 if(!flag)
   sum = 1;
 
 return sum;
}

/*
 * Return the number of brothers in a node
 *
 * ie :	
 *			   a
 *		     b   c   d   e
 *
 *   Returns 4 (b,c,d,e)
 */
int net_brothers_number(harglst * a)
{
 hargwalk * hw;
 char * key;
 int r = 0;
 if(!a)return 0;
 hw = harg_walk_init(a);
 while((key = harg_walk_next(hw)))r++;
 /*harg_walk_stop(hw);*/
 return r;
}
 

 



/*-----------------------------------------------------------------------*
 *                                                                       *
 *	       	          Data management routines                       *
 *									 *
 *-----------------------------------------------------------------------*/
 
 /*
  * These routines are called by the parser which detects the presence 
  * of the string 'Traceroute to' in the reports sent by the server
  */
  
/*
 * Insert a host in the Network map, by reading the
 * route sent by the server
 */
void netmap_add_data(data)
 char * data;
{
 harglst * nm = NetMap;
 harglst * l;
 char * dest;
 char *s, *t;
 char * last;
 GtkWidget * table;
 data = strdup(data);
 dest = data+strlen("Traceroute to ");
 s = strchr(dest, '\n');
 t = s+sizeof(char);
 if(!s)return;
 s-=3*sizeof(char);
 s[0]='\0';
 dest = strdup(dest);
 printf("dest : %s\n", dest);
 
 s = strchr(t, '\n');
 
 
 if(!nm)
 {
  NetMap = nm = harg_create(5000);
 }
 
 while(t)
 {
  harglst * sub;
  
  if(s)s[0]='\0';
  printf("Dealing w/ %s\n", t);
  sub = harg_get_harg(nm, t);
  if(!sub)
  {
   printf("Adding subnet %s\n", t);
   sub = harg_create(5000);
   harg_add_harg(nm, t, sub);
  } 
  else printf("%s already exists\n", t);
  nm = sub;
  last = t;
  if(!s)t = NULL;
  else
  {
   t = s+sizeof(char);
   if(!t[0])t = NULL;
   else s = strchr(t, '\n');
  }
 }
 
 if(strcmp(last, dest))
 {
  harglst * sub = harg_get_harg(nm, dest);
  if(!sub)
  {
   sub = harg_create(5000);
   harg_add_harg(nm, last, sub);
  }
 }
 free(dest);
 free(data);
 
 /* XXX - delete me */
 printf("Height of our tree : %d\n", net_height(NetMap));
 printf("Width of our tree : %d\n", net_width(NetMap));
 table = map_create_window(net_width(NetMap), net_height(NetMap));
 GTKNetMap = map_add_items(table, NULL, NetMap, NULL, 0, net_width(NetMap), 0);
 gtk_widget_realize(table);
 
 map_link(table, GTKNetMap);
}


/*---------------------------------------------------------------------*
 * 								       *
 *			       GTK routines			       *
 *                                                                     *
 *---------------------------------------------------------------------*/
 
 

/*
 * This is the first implementation. I should not keep it.
 * I just code it so that I got some visual output
 * and I'm willing to do things better
 *
 * We will create a table, and insert the element in there.
 *
 */ 


static struct netitem * gtk_create_computer(label, parent)
 char * label;
 GtkWidget * parent;
{
 struct netitem * ni = malloc(sizeof(*ni));
 GtkWidget * box = gtk_vbox_new(FALSE, FALSE);
 GtkWidget * l1, *l2;
 
 l1 = gtk_label_new("(replace me by a pixmap)");
 l2 = gtk_label_new(label);
 gtk_box_pack_start(GTK_BOX(box), l1, FALSE, FALSE, 0);
 gtk_widget_show(l1);
 
 gtk_box_pack_start(GTK_BOX(box), l2, FALSE, FALSE, 0);
 gtk_widget_show(l2);
 ni->item = box;
 ni->parent = parent;
 return ni;
}
 
static GtkWidget * map_create_window(x,y)
 int x,y;
{
 GtkWidget * window;
 GtkWidget * fixed;
 
 window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
 gtk_signal_connect(GTK_OBJECT(window), "destroy", 
     	GTK_SIGNAL_FUNC(close_window), window);
  gtk_signal_connect(GTK_OBJECT(window), "delete_event", 
  	GTK_SIGNAL_FUNC(delete_event), window);
 fixed = gtk_fixed_new();
 gtk_container_add(GTK_CONTAINER(window), fixed);
 gtk_widget_show(fixed);
 gtk_widget_show(window);
 return fixed;
}

static struct netitem * map_add_item(fixed, parent, x,y, name)
 GtkWidget * fixed;
 GtkWidget * parent; /* link to */
 int x,y;
 char * name;
{
 struct netitem * computer = gtk_create_computer(name, parent);
 printf("fixed_put(%d,%d)\n", x*80, y*80);
 gtk_fixed_put(GTK_FIXED(fixed), computer->item, x*80, y*80);
 computer->item->allocation.x = x*80+30;
 computer->item->allocation.y = y*80;
 if(parent)
 {
 /*
 gdk_draw_line(fixed->window, fixed->style->fg_gc[fixed->state],
 		GTK_WIDGET(parent)->allocation.x, x*80+30, 
		GTK_WIDGET(parent)->allocation.y, y*80);
*/
  gdk_draw_line(fixed->window, fixed->style->white_gc,
 		0, 0, 
		100,100);
 printf("Draw line : (%d,%d) -> (%d,%d)\n",
 		GTK_WIDGET(parent)->allocation.x,
		GTK_WIDGET(parent)->allocation.y,x*80+30,y*80);
 }
 
 gtk_widget_show(computer->item);
 return computer;
}


/*
 * Fill the table
 *
 */
static harglst *
 map_add_items(GtkWidget * fixed, GtkWidget * parent, harglst * n, harglst* all, int xmin, int xmax, int level)
{
 int brothers;
 int i;
 int max = xmax;
 hargwalk * hw;
 char * key;
 if(!n)
  return all;
 
 if(!all)
  all = harg_create(5000);
  
  
 hw  = harg_walk_init(n);
 brothers = net_brothers_number(n);
 if(!brothers)
  return all;
 printf("We have %d sons. Here are their position : \n", brothers);
 
 xmax = xmax / brothers;
 while((key = harg_walk_next(hw)))
 {
  struct netitem * new_parent;
  new_parent = map_add_item(fixed, parent, xmin+xmax/2, level, key);
  harg_add_ptr(all, key, new_parent);
  printf("Link (item) with sons\n");
  map_add_items(fixed, new_parent->item, harg_get_harg(n, key), all, xmin, xmax, level+1);
  xmin = xmax;
  xmax = xmin + (max / brothers);
 }
 return all;
}

void
map_link(GtkWidget * fixed, harglst *a)
{
 hargwalk * hw = harg_walk_init(a);
 char * key;
 while((key = harg_walk_next(hw)))
 {
  struct netitem * e = harg_get_ptr(a, key);
  if(e)
  {
  if(e->parent && e->item)
  {
  gdk_draw_line(fixed->window, fixed->style->black_gc,
 		GTK_WIDGET(e->parent)->allocation.x, GTK_WIDGET(e->item)->allocation.x, 
		GTK_WIDGET(e->parent)->allocation.y, GTK_WIDGET(e->item)->allocation.y);
  }
  else printf("%s has no parent / item (%d %d)\n",key, e->parent, e->item);
 }
 else printf("Could not find %s\n", key);
 }
}

#endif
#endif /* USE_GTK */
