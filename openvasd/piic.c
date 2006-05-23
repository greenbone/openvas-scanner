/* OpenVAS
* $Id$
* Description: Reads from plugin output pipe, writes to arglist.
*
* Authors: - Laban Mwangi <labeneator@gmail.com> (initial version)
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
#include "log.h"
#include "save_kb.h"
#include "utils.h"
#include "piic.h"


void kb_parse(int soc, struct arglist * globals, struct kb_item ** kb, char * buf, int msg )
{
 char * t;
 int type;
 char *c;
 int buf_len;
 char * copy;
 char * name;
 char * value;
 
 if( buf == NULL || kb == NULL )
  return;

 if ( msg & INTERNAL_COMM_KB_GET )
 { 
  struct kb_item * kitem = kb_item_get_single(kb, buf, 0);

  if ( kitem == NULL )
  {
   internal_send(soc, NULL, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_ERROR);
   return;
  }
 
  if ( kitem->type == KB_TYPE_STR  )
  {
   internal_send(soc, kitem->v.v_str, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_SENDING_STR);
   return;
  }
  else  if ( kitem->type == KB_TYPE_INT )
  {
   char buf[64];
   snprintf(buf, sizeof(buf), "%d", kitem->v.v_int);
   internal_send(soc, buf, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_SENDING_INT);
  }
  else 
   internal_send(soc, NULL, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_ERROR);
  return;	
 }
  
 if ( buf[0] == '\0' ) 
    return;
    
 buf_len = strlen(buf);
  
 if(buf[buf_len - 1]=='\n')
 	buf[ buf_len - 1 ]='\0';
	
 c = strrchr(buf, ';');
 if(c != NULL )
    c[0] = '\0';
    
 t = strchr(buf, ' ');
 if( t == NULL )
    return;
 
 t[0] = '\0';
 type = atoi(buf);
 t[0] = ' ';


  value = strchr(buf, '=');
    
  if( value == NULL )
        return;
        
  value[0]='\0';
  value++;
  
  name = t+1;
  
  if ( type == ARG_INT )
  { 
   int v = atoi(value);
   if ( msg & INTERNAL_COMM_KB_REPLACE )
   	kb_item_set_int(kb, name,v);
    else
	{
   	kb_item_add_int(kb, name,v);
   	if(save_kb(globals))save_kb_write_int(globals, arg_get_value(globals, "CURRENTLY_TESTED_HOST"), name,v);   
	}
  }
  else
  {
   copy = rmslashes(value);
   if ( msg & INTERNAL_COMM_KB_REPLACE )
   	kb_item_set_str(kb, name, copy);
   else
	{
   	kb_item_add_str(kb, name, copy);
   	if(save_kb(globals))save_kb_write_str(globals, arg_get_value(globals, "CURRENTLY_TESTED_HOST"), name, copy);
	}
   efree(&copy);
  }
}


