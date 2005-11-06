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
#ifdef USE_GTK
#include <gtk/gtk.h>
#endif

#include "families.h"
#include "filter.h"
#include "globals.h"

/*
 * family_init
 * 
 * initializes a set of plugin families
 */
struct plugin_families * 
family_init()
{
  struct plugin_families * ret;
  
  ret = emalloc(sizeof(struct plugin_families));
  return(ret);
}

/*
 * family_add
 *
 * add a family in the family list, after having
 * checked whether the family was not already present in
 * the list
 */
void 
family_add(families,pluginfos)
     struct plugin_families * families;
     struct arglist * pluginfos;
 
{
  char * name = arg_get_value(pluginfos, "FAMILY");
  struct plugin_families * l = families;
  int flag = 0;
  if(!name)return;
  if(l)
   while(l->next && !flag)
    {
      if(l->name)flag = !strcmp(l->name, name);
      l->enabled = 1;
      l = l->next;
    }
  if(!flag)
    {
      l->next = emalloc(sizeof(struct plugin_families));
      l->name = emalloc(strlen(name)+1);
      strncpy(l->name, name, strlen(name));
    }
}

/*
 * family_enable
 */
void 
family_enable(family, plugins, enable)
     char * family;
     struct arglist * plugins;
     int enable;
{
 if(!plugins)
  return;
  
  while(plugins->next)
    {
      char * pname = arg_get_value(plugins->value, "FAMILY");
      if(!strcmp(pname, family))
      	{ 
	  switch(enable)
	  {
	   case DISABLE_FAMILY :
	   	plug_set_launch(plugins->value, 0);
		break;
	   case ENABLE_FAMILY_BUT_DOS :
	   	{
		 char* category = arg_get_value(plugins->value, "CATEGORY");	
		 if(category && (
				!strcmp(category, "denial") ||
				!strcmp(category, "kill_host") ||
				!strcmp(category, "flood") ||
				!strcmp(category, "destructive_attack")
				)
		   )
		 	plug_set_launch(plugins->value, 0);
		else
		        {
			if(!filter_plugin(&Filter, plugins->value))
			 plug_set_launch(plugins->value, 1);
			else
			 plug_set_launch(plugins->value, 0);
			}
		break;
		}
	   case ENABLE_FAMILY :
	   	if(!filter_plugin(&Filter, plugins->value))
  	  	  plug_set_launch(plugins->value, 1);
		else 
		  plug_set_launch(plugins->value, 0);
		break;
	   default : /* nonsense */
	   	break;
	  }
	}
      plugins = plugins->next;
    }
}

int
family_enabled(family, plugins)
 char * family;
 struct arglist * plugins;
{
 if(!plugins)
  return 0;
  
 while(plugins->next)
    {
      char * pname =(char *)arg_get_value(plugins->value, "FAMILY");
      
      if(pname && !strcmp(pname, family))
  	  if(plug_get_launch(plugins->value))
	   return 1;
      plugins = plugins->next;
    }
 return 0;
}

int
family_empty(family, plugins)
 char * family;
 struct arglist * plugins;
{
 if(!plugins)
  return 1;
 
 while(plugins->next)
 {
  char * pname =(char *)arg_get_value(plugins->value, "FAMILY");
  if(pname && !strcmp(pname, family))
  {
   if(!filter_plugin(&Filter, plugins->value))
   return 0;
  }
  plugins = plugins->next;
 }
 return 1;
}

   

