/* OpenVAS
* $Id$
* Description: Performs various checks for requirements set in a given plugin.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

 
#include <includes.h>
#include "pluginscheduler.h"
#include "plugs_req.h"

/**********************************************************
 
 		   Private Functions
	
***********************************************************/
 
extern int kb_get_port_state_proto(struct kb_item **, struct arglist*, int, char*);
 
/*---------------------------------------------------------

  Returns whether a port in a port list is closed or not
 
 ----------------------------------------------------------*/
static int
get_closed_ports(kb, ports, preferences)
   struct kb_item ** kb;
   struct arglist * ports;
   struct arglist * preferences;
{

  if(ports == NULL)
   return -1;
  
  while(ports->next != NULL)
  {
   int iport = atoi(ports->name);			
   if(iport != 0)
   	{
      	if( kb_get_port_state_proto(kb, preferences, iport, "tcp") != 0 )
		return iport;
	}
      else 
        {
        
      	if( kb_item_get_int(kb, ports->name) > 0 )
		return 1; /* should be the actual value indeed ! */
	}   
    ports = ports->next;
  }
  return 0; /* found nothing */
}


/*-----------------------------------------------------------

  Returns whether a port in a port list is closed or not
 
 ------------------------------------------------------------*/
static int
get_closed_udp_ports(kb, ports, preferences)
   struct kb_item ** kb;
   struct arglist * ports;
   struct arglist * preferences;
{   
  if( ports == NULL )
  	return -1;
  else while( ports->next != NULL)
  {
      int iport = atoi(ports->name);				
      if(kb_get_port_state_proto(kb, preferences, iport, "udp"))return iport;
      ports = ports->next;
  }
  return 0; /* found nothing */
}


/*-----------------------------------------------------------
            
	     Returns the name of the first key
	     which is not in <kb>
	    
 -----------------------------------------------------------*/
static char * 
key_missing(kb, keys)
  struct kb_item ** kb;
  struct arglist * keys;
{
 if(kb == NULL || keys == NULL )
    return NULL;
 else {
   while( keys->next != NULL)
   {
     if( kb_item_get_single(kb, keys->name, 0) == NULL )
      return keys->name;
     else
      keys = keys->next;
   }
 }
 return NULL;
}

/*-----------------------------------------------------------
            
	    The opposite of the previous function
	    
 -----------------------------------------------------------*/
static char * key_present(kb, keys)
 struct kb_item ** kb;
 struct arglist * keys;
{
 if( kb == NULL || keys == NULL )
    return NULL;
 else {
   while( keys->next != NULL)
   {
     if(kb_item_get_single(kb, keys->name, 0) != NULL)
      return keys->name;
     else
      keys = keys->next;
   }
 }
 return NULL;
} 

/**********************************************************
 
 		   Public Functions
	
***********************************************************/	




/*------------------------------------------------------

  Returns <port> if the lists of the required ports between
  plugin 1 and plugin 2 have at least one port in common
 
 
 ------------------------------------------------------*/
struct arglist * 
requirements_common_ports(plugin1, plugin2)
 struct scheduler_plugin * plugin1, *plugin2;
{
 struct arglist * ret = NULL;
 struct arglist * req1;
 struct arglist * req2;
 
 
 if(!plugin1 || !plugin2) return 0;
 
 req1 = plugin1->required_ports;
 if ( req1 == NULL )
	return 0;

 req2 = plugin2->required_ports;
 if ( req2 == NULL )
	return 0;
 
 while(req1->next != NULL)
 {
  struct arglist * r = req2;
  if ( r != NULL  ) while( r->next != NULL )
  {
   if(req1->type == r->type)
   {
      if(r->name && req1->name && !strcmp(r->name, req1->name))
       {
       if(!ret)ret = emalloc(sizeof(struct arglist));
       arg_add_value(ret, r->name, ARG_INT, 0,(void*)1);
       }
   }  
   r = r->next;
  }
  req1 = req1->next;
 }
 return ret;
}


/*-------------------------------------------------------

	Determine if the plugin requirements are
	met.

	Returns NULL is everything is ok, or else
	returns an error message

---------------------------------------------------------*/

char *
requirements_plugin(kb, plugin, preferences)
 struct kb_item ** kb;
 struct scheduler_plugin * plugin;
 struct arglist * preferences;
{
  static char error[64];
  char * missing;
  char * present;
  struct arglist * tcp, * udp, * rkeys, * ekeys;
  char	* opti = arg_get_value(preferences, "optimization_level");

  /*
   * Check wether the good ports are open
   */
  error[sizeof(error) - 1] = '\0';  
  tcp = plugin->required_ports;
  if(tcp != NULL && (get_closed_ports(kb, tcp , preferences)) == 0)
     {
      strncpy(error, "none of the required tcp ports are open", sizeof(error) - 1);
      return error;
     }
      
   udp = plugin->required_udp_ports;
   if(udp != NULL && (get_closed_udp_ports(kb, udp , preferences)) == 0)
      {
      strncpy(error, "none of the required udp ports are open", sizeof(error) - 1);
      return error;
      }

   if (opti != NULL && (strcmp(opti, "open_ports") == 0 || atoi(opti) == 1))
     return NULL;

  /*
   * Check wether a key we wanted is missing
   */
  rkeys = plugin->required_keys;
  if((missing = key_missing(kb, rkeys)))
  {
     snprintf(error,sizeof(error), "because the key %s is missing", missing);
     return error;
  }
  
  if (opti != NULL && (strcmp(opti, "required_keys") == 0 || atoi(opti) == 2))
     return NULL;

  /*
   * Check wether a key we do not want is present
   */
  ekeys = plugin->excluded_keys;
  if((present = key_present(kb, ekeys)))
  {
   snprintf(error,sizeof(error), "because the key %s is present", present);
   return error;
  }
  return NULL;
}
