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
#include "comm.h"
#include "auth.h"
#include "parser.h"
#include "attack.h"
#include "globals.h"
#include "error_dialog.h"
#include "preferences.h"

#ifdef ENABLE_CIPHER_LAYER
#include <peks/peks.h>
#endif
static void setup_plug_list(struct arglist *,struct arglist *, char *);


/*
 * restore_attack
 *
 * Restores a session
 *
 */
#ifdef ENABLE_SAVE_TESTS
void 
restore_attack(session_name, preferences)
 char * session_name;
 struct arglist * preferences;
{
  char * plug_list;
  struct arglist * scans = Scanners;
  struct arglist * plugs = Plugins;
  struct arglist * serv_prefs;
  int num_plug = 0;
  int num_scanners = 0;
  
  /* Count how many plugins we have */
  while(plugs && plugs->next){
    num_plug++;
    plugs = plugs->next;
  }
  
  while(scans && scans->next)
  {
   num_scanners++;
   scans = scans->next;
  }
  
  plugs = Plugins;
  scans = Scanners;
  
  
  /* 
   * Set up the plugin list, according to the
   * Nessus Transfer Protocol version 1.1
   */
  plug_list = emalloc(num_plug*50+1+num_scanners*50+1);
  setup_plug_list(Plugins, Scanners, plug_list);
  if(!strlen(plug_list))sprintf(plug_list, "0");
  
  serv_prefs = arg_get_value(preferences, "SERVER_PREFS");
  if(arg_get_value(serv_prefs, "plugin_set"))
   {
   arg_set_type(serv_prefs, "plugin_set", ARG_STRING);
   arg_set_value(serv_prefs, "plugin_set", strlen(plug_list)+1, plug_list);
   } 
  else
   arg_add_value(serv_prefs, "plugin_set", ARG_STRING, strlen(plug_list), plug_list);
  comm_send_preferences(preferences);
  comm_get_preferences_errors(preferences);
  preferences_save(Plugins);
  comm_send_rules(preferences);
  comm_restore_session(session_name);
/*  efree(&plug_list); */
}
#endif


/*
 * attack_host 
 *
 * This functions sends to the server (nessusd) the order
 * to start a new attack.
 *
 * Params :
 * 
 * hostname  : name of the host to test first
 * max_hosts : max number of hosts to test
 * recursive : unused
 * 
 */ 
void 
attack_host(hostname, preferences)
     char * hostname;
     struct arglist * preferences;
{
  char * plug_list;
  struct arglist * scans = Scanners;
  struct arglist * plugs = Plugins;
  struct arglist * serv_prefs;
  int num_plug = 0;
  int num_scanners = 0;
  
  /* Count how many plugins we have */
  while(plugs && plugs->next){
    num_plug++;
    plugs = plugs->next;
  }
  
  while(scans && scans->next)
  {
   num_scanners++;
   scans = scans->next;
  }
  
  plugs = Plugins;
  scans = Scanners;
  
  
  /* 
   * Set up the plugin list, according to the
   * Nessus Transfer Protocol version 1.1
   */
  plug_list = emalloc(num_plug*50+1+num_scanners*50+1);
  setup_plug_list(Plugins, Scanners, plug_list);
  if(!strlen(plug_list))sprintf(plug_list, "0");
  
  serv_prefs = arg_get_value(preferences, "SERVER_PREFS");
  if(arg_get_value(serv_prefs, "plugin_set"))
   {
   arg_set_type(serv_prefs, "plugin_set", ARG_STRING);
   arg_set_value(serv_prefs, "plugin_set", strlen(plug_list)+1, plug_list);
   } 
  else
   arg_add_value(serv_prefs, "plugin_set", ARG_STRING, strlen(plug_list), plug_list);
  comm_send_preferences(preferences);
  comm_get_preferences_errors(preferences);
  preferences_save(Plugins);
  comm_send_rules(preferences);
  network_printf("CLIENT <|> LONG_ATTACK <|>\n");
  network_printf("%d\n", strlen(hostname));
  {
   int len = strlen(hostname);
   int n = 0;
   /* send by packets of 1024 bytes */
   while(n < len)
   {
    int size = 1024;
    int m = 0;
    while(m < size)
    {
     int e;
     if((len - m - n) < size)size = len-m-n;
     e = nsend(GlobalSocket, &(hostname[n+m]), size, 0);
     if(e < 0)
     {
      perror("send ");
      return;
     }
     m+=e;
    }
    n+=m;
   }
/* network_printf("<|> CLIENT\n"); */
 /*
  network_printf("CLIENT <|> NEW_ATTACK <|> %s <|> CLIENT\n",
	       hostname);        
  */	      
  efree(&plug_list);	
 }     
}

/*
 * setup_plug_list
 *
 * convert the ids of the plugins wich are enabled
 * to a string (ie : '1;3;4')
 */
static void
setup_plug_list(plugs, scanners, plug_list)
 struct arglist * plugs;
 struct arglist * scanners;
 char * plug_list;
{
 struct arglist * w = NULL;
 int i = 0;
 
 for(i=0;i<2;i++)
 {
  if(!w)w = plugs;
  else {
  	w = scanners;
	}
  
while(w && w->next)
 {
  char * sp;
    
  if(plug_get_launch(w->value))
    {
     sp = emalloc(9);
     sprintf(sp, "%d", (int)arg_get_value(w->value, "ID"));
     strcat(plug_list, sp);
     efree(&sp);
     strcat(plug_list, ";");
    }
    w = w->next;
  }
 w = plugs;
 }
}
