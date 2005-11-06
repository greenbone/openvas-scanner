/* Nessus
 * Copyright (C) 1998 Renaud Deraison
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
#include <gtk/gtk.h>

#include "nessus.h"
#include "xstuff.h"
#include "globals.h"
#include "sighand.h"

int init_display(int *argc, char *** argv)
{
 gtk_init(argc, argv);
 return(0);
}

int close_window(GtkWidget * nul, GtkWidget * w)
{
	gtk_widget_hide(w);
	/* gtk_widget_destroy(w); */
	return(FALSE);
}
int delete_event(GtkWidget * nul, void * data)
{
 return(FALSE);
}
void close_display()
{
 gtk_main_quit();
 nessus_exit(0);
}

struct pixmap_and_mask
{
  GdkPixmap *pixmap;
  GdkBitmap *mask;
};

static void
pixmap_and_mask_destroy_notify(gpointer p)
{
  gdk_pixmap_unref(((struct pixmap_and_mask *) p)->pixmap);
  gdk_bitmap_unref(((struct pixmap_and_mask *) p)->mask);
  g_free(p);
}

GtkWidget *
make_pixmap
    (GtkWidget *widget,
     GdkColor  *transparent,
     char      **xpm_data)
{
  struct pixmap_and_mask *p;
  gchar name[64];
  GdkColormap *colormap;

  g_snprintf(name, sizeof(name), "N_PIXMAP_%lx", (long) xpm_data);
  p = gtk_object_get_data(GTK_OBJECT(widget), name);
  if (!p) {
    p = g_malloc(sizeof(*p));
    colormap = widget->window ? NULL : gtk_widget_get_colormap (widget);
    p->pixmap = gdk_pixmap_colormap_create_from_xpm_d
	(widget->window, colormap,
	 &p->mask, transparent, (gchar **) xpm_data);
    gtk_object_set_data_full
        (GTK_OBJECT(widget), name, p, &pixmap_and_mask_destroy_notify);
  }
  return gtk_pixmap_new (p->pixmap, p->mask);
}
#endif
