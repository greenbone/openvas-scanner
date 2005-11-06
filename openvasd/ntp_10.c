/* Nessus
 * Copyright (C) 1998 - 2004 Renaud Deraison
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
 *
 * Nessus Communication Manager -- it manages the NTP Protocol, version 1.0
 *
 */ 
 
#include <includes.h>

#include "ntp.h"
#include "comm.h"

int ntp_10_parse_input(globals, input)
 struct arglist * globals;
 char * input;
{
 char * strs[8];
 int good = 0;
 int i;
 int global_socket = (int)arg_get_value(globals, "global_socket");
 struct arglist * preferences = arg_get_value(globals, "preferences");
 
 for(i=0;i<8;i++)strs[i] = emalloc(strlen(input)+1);
 sscanf(input, "%s <|> %s <|> %s <|> %s <|> %s  <|> %s <|> %s <|> %s",
	     strs[0],strs[1],strs[2],strs[3],strs[4],strs[5],strs[6],strs[7]);
   

 if(!strncmp(strs[1], "QUIT", 4))
   {
#if 1
     fprintf(stderr, "ntp_10_parse_input: QUIT received\n");
#endif
        for(i=0;i<8;i++)efree(&strs[i]);
    	shutdown(global_socket,2);
    	EXIT(0);
      }

  if(!strcmp(strs[0], "CLIENT") && !strcmp(strs[1],"NEW_ATTACK") &&
	 !strcmp(strs[7], "CLIENT"))good = 1;
   if(good)
   {
    char * hostname;
    char * port_range;
    char * max_hosts;
    
    max_hosts = emalloc(strlen(strs[3])+1);
    strncpy(max_hosts, strs[3], strlen(strs[3]));
    
     
    if(arg_get_value(preferences, "max_hosts"))
     arg_set_value(preferences, "max_hosts", strlen(max_hosts), max_hosts);
    else 
     arg_add_value(preferences, "max_hosts", ARG_STRING, strlen(max_hosts), max_hosts);
    
   
    comm_setup_plugins(globals, strs[2]);
    hostname = emalloc(strlen(strs[6])+1);
    strncpy(hostname, strs[6], strlen(strs[6]));
    
    if(arg_get_value(preferences, "TARGET"))
     arg_set_value(preferences, "TARGET", strlen(hostname), hostname);
    else
     arg_add_value(preferences, "TARGET", ARG_STRING, strlen(hostname), hostname);
     
    port_range = emalloc(strlen(strs[5])+1);
    strncpy(port_range, strs[5], strlen(strs[5]));
    if(arg_get_value(preferences, "port_range"))
     arg_set_value(preferences, "port_range", strlen(port_range), port_range);
    else
     arg_add_value(preferences, "port_range", ARG_STRING, strlen(port_range), port_range);
    }
   for(i=0;i<8;i++)efree(&strs[i]);
   return(!good);
}
  
  
 
