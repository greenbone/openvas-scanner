 /* OpenVAS
* $Id$
* Description: Communication manager; it manages the NTP Protocol version 1.0 and 1.1.
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
#include <corevers.h>
#include <stdarg.h>
#include "auth.h"
#include "rules.h"
#include "comm.h" 
#include "sighand.h"
#include "ntp.h"
#include "ntp_10.h"
#include "ntp_11.h"
#include "log.h"
#include "plugs_hash.h"
#include "utils.h"
#include "nasl.h"
#ifdef ENABLE_SAVE_KB
#include "detached.h"
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

void
extract_extensions(caps, banner)
 ntp_caps * caps;
 char * banner;
{
 char * t;
 t = strchr(&(banner[1]), '<');
 if(!t)
  return;
 
 t++;
 if ( *t == '\0' ) return;
 t++;
 if ( *t == '\0' ) return;
 
 for(;;)
 {
  char * n = strchr(t, ' ');
  if(!n)
   return;
  n[0] = '\0';
  
  /*
   * MD5 caching of the plugins on the client side
   */
  if(!strcmp(t, "md5_caching"))
   caps->md5_caching = 1;
   
  else if(!strcmp(t, "md5_by_name"))
   caps->md5_by_name = 1;
  
  /*
   * We send the plugins versions to the client
   */
  else if(!strcmp(t, "plugins_version"))
   caps->plugins_version = 1;
   
  /* 
   * We send the CVE id 
   */
  else if(!strcmp(t, "plugins_cve_id"))
   caps->plugins_cve_id = 1;
   
  /*
   * We send the Bugtraq ID
   */
  else if(!strcmp(t, "plugins_bugtraq_id"))
   caps->plugins_bugtraq_id = 1;
   
  else if(!strcmp(t, "plugins_xrefs"))
   caps->plugins_xrefs = 1; 
 
  /*
   * We send timestamps to the client
   */
  else if(!strcmp(t, "timestamps"))
   caps->timestamps = 1;

  /*
   * We send the name of the host AND its IP
   */
  else if(!strcmp(t, "dns"))
    caps->dns = 1;
    
  /*
   * We show the plugins dependencies through the use
   * of the DEPENDENCIES message
   */
  else if(!strcmp(t, "dependencies"))
    caps->dependencies = 1;

  /* 
   * Immediately jump to the wait order
   */
  else if(!strcmp(t, "fast_login"))
    caps->fast_login = 1;
    
  n[0] = ' ';
  t = &(n[1]);
  if(!t[0])break;
  if(t[0] == '>')break;
 }
}

/*
 * comm_init() :
 * Initializes the communication between the
 * server (us) and the client.
 */
ntp_caps* comm_init(soc)
     int soc;
{  
  char buf[1024];
  ntp_caps* caps = emalloc(sizeof(ntp_caps));
  int n;

  /* We must read the version of the NTP the client
     wants us to use */
  n = recv_line(soc, buf, sizeof(buf) - 1);
  if(n <= 0) 
   EXIT(0);
   
  buf[sizeof(buf) - 1] = '\0';
  extract_extensions(caps, buf);
  if(!strncmp(buf, "< NTP/1.0 >", 11))
    {
      caps->ntp_version = NTP_10;
      caps->ciphered = FALSE;
      caps->ntp_11 = FALSE;
      caps->scan_ids = FALSE;
      caps->pubkey_auth = FALSE;
      nsend(soc, "< NTP/1.0 >\n",12,0);
    }
  else if(!strncmp(buf, "< NTP/1.1 >", 11))
    {
      caps->ntp_version = NTP_11;
      caps->ciphered = FALSE;
      caps->ntp_11 = TRUE;
      caps->scan_ids = FALSE;
      caps->pubkey_auth = FALSE;
      nsend(soc, "< NTP/1.1 >\n", 12, 0);
    }  
  else if(!strncmp(buf, "< NTP/1.2 >", 11))
    {
      caps->ntp_version = NTP_12;
      caps->ciphered = FALSE;
      caps->ntp_11 = TRUE;
      caps->scan_ids = TRUE;
      caps->pubkey_auth = FALSE;
      nsend(soc, "< NTP/1.2 >\n", 12, 0);
    }
  /*ENABLE_CRYPTO_LAYER*/
  else
    {
#ifndef OPENVAS_ON_SSL
      shutdown(soc, 2);
#endif
      EXIT(0);
    }
  log_write("Client requested protocol version %d.\n", caps->ntp_version);
  return(caps);
}


/*
 * This function must be called at the end
 * of a session. 
 */
void 
comm_terminate(globals)
 struct arglist * globals;
{
  auth_printf(globals, "SERVER <|> BYE <|> BYE <|> SERVER\n");
  /*
  auth_gets(globals, buf, 199);
  if(!strlen(buf))EXIT(0);
  efree(&buf); 
  */
}


/*
 * Sends the list of plugins that the server
 * could load to the client, using the 
 * NTP format
 */
void 
send_plug_info(globals, plugins)
 struct arglist * globals;
 struct arglist * plugins;
{
  int i=1,j;
  static const char * categories[] =
    {"init", "scanner", "settings" , "infos", "attack", "mixed", "destructive_attack", "denial", "kill_host", "flood", "end", "unknown" };
#define CAT_MAX	(sizeof(categories) / sizeof(categories[0]))
  struct arglist * args;
  char * t;
  const char *a, *b, *d, *e = NULL;
  char * desc = NULL;
  ntp_caps * caps = arg_get_value(globals, "ntp_caps");
  
      args = plugins->value;
      if(plug_get_id(args) == 0)
        plug_set_id(args, i);
       
      t = plug_get_description(args);
      
      if(t != NULL){
      		desc = t = estrdup(t);
      		while((t=strchr(t,'\n')))t[0]=';';
		}
      j = plug_get_category(args);
      if(j >= CAT_MAX || j < ACT_FIRST)	j = CAT_MAX - 1;

      if(caps->plugins_version)
       {
       e = plug_get_version(args);
       if(!e)e = "?";
       }
       
      if ((a = plug_get_name(args)) == NULL      ||
	  (b = plug_get_copyright(args)) == NULL ||
	  desc == NULL 			         ||
	  (d = plug_get_summary(args)) == NULL) {
	if (a == 0)
	  a = "unknown NAME" ;
	log_write ("Inconsistent data: %s - not applying this plugin\n", a);
      } else
      {
       char * str;
       if(strchr(a, '\n') != NULL ){
       	fprintf(stderr, "ERROR - %d %s\n", plug_get_id(args), a);
	}
	
	if(strchr(b, '\n') != NULL ){
       	fprintf(stderr, "ERROR - %d %s\n", plug_get_id(args), b);
	
	}
	
	if(strchr(desc, '\n') != NULL ){
       	fprintf(stderr, "ERROR - %d %s\n", plug_get_id(args), desc);
	
	}
	
	if(strchr(d, '\n')){
       	fprintf(stderr, "ERROR - %d %s\n", plug_get_id(args), d);
	}
	
       str = emalloc(strlen(a) + strlen(b) + strlen(desc) + strlen(d) +
      		  strlen(plug_get_family(args))+ 1024);
       sprintf(str, "%d <|> %s <|> %s <|> %s <|> %s <|> %s <|> %s",
      		  plug_get_id(args), a,
		  categories[j],
		  b, desc, d,
		  plug_get_family(args));
     
      if(caps->plugins_version != 0)
        {
       	 strcat(str, " <|> ");
	 strcat(str,  e);  
	}
	
     if(caps->plugins_cve_id)
     {
        char * id = plug_get_cve_id(args);
	if(id == NULL)id = "NOCVE";
     	strcat(str, " <|> ");
	strcat(str, id);
     }
     
     if(caps->plugins_bugtraq_id)
     {
       char * bid = plug_get_bugtraq_id(args);
       if(bid == NULL)bid = "NOBID";
       strcat(str, " <|> ");
       strcat(str, bid);
     }
     
     if(caps->plugins_xrefs)
     {
       char * xref = plug_get_xref(args);
       if(xref == NULL)xref = "NOXREF";
       strcat(str, " <|> ");
       strcat(str, xref);
     }
	
		  
      auth_printf(globals, "%s\n", str);	
      efree(&str);	  
      }
      
      if(desc != NULL)efree(&desc);
    
}


void
plugin_send_infos(globals, id)
 struct arglist * globals;
 int id;
{
 struct arglist * plugins = arg_get_value(globals, "plugins");

 if(!id)
  return;
 if(!plugins)
  return;

 while(plugins->next)
 {
  struct arglist * args = plugins->value;
  if(args)
  {
   int p_id = plug_get_id(args);
   if(p_id == id)break;
  }
  plugins = plugins->next;
  }
  
  if(plugins->next)
  {
   send_plug_info(globals, plugins);
  }
}



/*
 * Sends the list of plugins that the server
 * could load to the client, using the 
 * NTP format
 */
void 
comm_send_pluginlist(globals)
 struct arglist * globals;
{
  struct arglist * plugins = arg_get_value(globals, "plugins");
 
  
  auth_printf(globals, "SERVER <|> PLUGIN_LIST <|>\n");
  while(plugins && plugins->next)
    {
      send_plug_info(globals, plugins);
      plugins = plugins->next;
    }
  auth_printf(globals, "<|> SERVER\n");
}

/*
 * Sends the rules of the user
 */
void
comm_send_rules(globals)
 struct arglist * globals;
{
 
 auth_printf(globals, "SERVER <|> RULES <|>\n");
#ifdef USELESS_AS_OF_NOW
 struct openvas_rules * rules = arg_get_value(globals, "rules");
 while(rules && rules->next)
 {
  char c = 0;
  if(rules->rule == RULES_ACCEPT)
     auth_printf(globals, "accept %c%s/%d\n",  rules->not?'!':'', 
     				            inet_ntoa(rules->ip),
	 				    rules->mask);
  else
      auth_printf(globals, "reject %c%s/%d\n", rules->not?'!':'', 
      				             inet_ntoa(rules->ip),
	  				    rules->mask);
  rules = rules->next;
 }
#endif
 auth_printf(globals, "<|> SERVER\n");
}

/*
 * Sends the preferences of the server
 */
void
comm_send_preferences(globals)
 struct arglist * globals;
{
 struct arglist * prefs = arg_get_value(globals, "preferences");
 
 /* We have to be backward compatible with the NTP/1.0 */
 auth_printf(globals, "SERVER <|> PREFERENCES <|>\n");

 while(prefs && prefs->next)
 {
  if (prefs->type == ARG_STRING) 
   {
     /*
      * No need to send openvasd-specific preferences
      */
     if( strcmp(prefs->name, "logfile")           &&
         strcmp(prefs->name, "config_file")       &&
         strcmp(prefs->name, "plugins_folder")    &&
	 strcmp(prefs->name, "dumpfile")          &&
	 strcmp(prefs->name, "users")             &&
	 strcmp(prefs->name, "rules")             &&
	 strncmp(prefs->name, "peks_", 5)         &&
	 strcmp(prefs->name, "negot_timeout")     &&
	 strcmp(prefs->name, "cookie_logpipe")    &&
	 strcmp(prefs->name, "force_pubkey_auth") &&
	 strcmp(prefs->name, "log_while_attack")  &&
	 strcmp(prefs->name, "ca_file")		  &&
	 strcmp(prefs->name, "key_file")	  &&
	 strcmp(prefs->name, "cert_file")	  &&
	 strcmp(prefs->name, "be_nice")		  &&
	 strcmp(prefs->name, "log_plugins_name_at_load") &&
	 strcmp(prefs->name, "admin_user") &&
	 strcmp(prefs->name, "nasl_no_signature_check")	)  
    		auth_printf(globals, "%s <|> %s\n", prefs->name, (const char *) prefs->value);
  }
  prefs = prefs->next;
 }
#ifdef ENABLE_SAVE_TESTS
 auth_printf(globals, "ntp_save_sessions <|> yes\n");
 auth_printf(globals, "ntp_detached_sessions <|> yes\n");
 auth_printf(globals, "server_info_openvasd_version <|> %s\n", OPENVAS_VERSION);
 auth_printf(globals, "server_info_libnasl_version <|> %s\n", nasl_version());
 auth_printf(globals, "server_info_libnessus_version <|> %s\n", nessuslib_version());
#ifdef USE_FORK_THREADS
  auth_printf(globals, "server_info_thread_manager <|> fork\n");
#endif
  auth_printf(globals, "server_info_os <|> %s\n", OVS_OS_NAME);
  auth_printf(globals, "server_info_os_version <|> %s\n", OVS_OS_VERSION);
#endif
  auth_printf(globals, "<|> SERVER\n");
}


/*
 * This function waits for the attack order
 * of the client
 * Meanwhile, it processes all the messages the client could
 * send
 */
void
comm_wait_order(globals)
	struct arglist * globals;
{
  ntp_caps* caps = arg_get_value(globals, "ntp_caps");
  int soc        = (int)arg_get_value(globals, "global_socket");

  for (;;) {
    static char str [2048] ;
    int n;
   
    n = recv_line (soc, str, sizeof (str)-1);
    if(n < 0){
    	log_write("Client closed the communication\n");
	EXIT(0);
	}
    if (str [0] == '\0') {
      if(!is_client_present(soc)) EXIT(0);
    }
   
    if(caps->ntp_11) {
      if (ntp_11_parse_input (globals, str) == 0) break ;
      continue ;
    }
    if (ntp_10_parse_input (globals, str) == 0) break ;
    
  }

}


/*-------------------------------------------------------------------------------*/
static int qsort_cmp( const void * a, const void * b )
{
 struct arglist ** plugin_a = (struct arglist**) a;
 struct arglist ** plugin_b = (struct arglist**) b;

 int id_a = plug_get_id((*plugin_a)->value);
 int id_b = plug_get_id((*plugin_b)->value);

 return id_a - id_b;
}

static struct arglist * _get_plug_by_id(struct arglist ** array, int id, int start, int end, int rend )
{
  int mid;
  int plugin_id;

  if ( start >= rend ) 
	return NULL;

  if ( start == end )
  {
  plugin_id = plug_get_id(array[start]->value);
   if ( plugin_id == id ) 
        return array[start];
   else 
        return NULL;
  }

  mid = ( start + end ) / 2;
  plugin_id = plug_get_id(array[mid]->value);
  if ( plugin_id > id ) 
	return _get_plug_by_id(array, id, start, mid, rend );
  else if ( plugin_id < id )
	return _get_plug_by_id(array, id, mid + 1, end, rend );

  return array[mid];
}


static struct arglist * get_plug_by_id(struct arglist ** array, int id, int num_plugins )
{
 return _get_plug_by_id(array, id, 0, num_plugins, num_plugins); 
}

/*-------------------------------------------------------------------------------*/


/* 
 * Enable the plugins which have been selected by the user 
 */
void comm_setup_plugins( struct arglist * globals, char * list )
{
  int id;
  int num_plugins=0;
  struct arglist * plugins = arg_get_value(globals, "plugins");
  struct arglist * p = plugins;
  struct arglist ** array;
  char * t;
  int i;
  int enable = 0;
  
  if ( p == NULL ) return;
  if ( list == NULL ) list = "-1;";

  if ( atoi(list) == -1 ) enable = LAUNCH_RUN;
  /* Disable every plugin */
  while( p->next != NULL )
    {
     num_plugins++;
     plug_set_launch(p->value, enable);
     p = p->next;
    }

  if ( num_plugins == 0 || enable != 0  )
	return;

  

  /* Store the plugins in an array for quick access */
  p = plugins;
  i = 0;
  array = emalloc ( num_plugins * sizeof(struct arglist ** ));
  while ( p->next != NULL ) 
  {
   array[i++] = p;
   p = p->next;
  }
 
  qsort( array, num_plugins, sizeof(struct arglist * ), qsort_cmp);
 
  t = list;
  while ( t[0] == ';' ) t ++;

  /* Read the list provided by the user and enable the plugins accordingly */
  for ( ;; )
    {
       id = atoi(t);
       if ( id != 0 )
	{
         p = get_plug_by_id(array, id, num_plugins);
         if ( p != NULL ) plug_set_launch(p->value, LAUNCH_RUN);
#ifdef DEBUG
	 else printf("PLUGIN ID %d NOT FOUND!!!\n", id);
#endif
	}

	t = strchr(t + 1, ';');
	if ( t != NULL ) t ++;
	else break;
    }


  efree(&array);
}

void
comm_send_md5_plugins(globals)
 struct arglist * globals;
{
 char * md5;
 char buf[2048];

 md5 = plugins_hash(globals);
 auth_printf(globals, "SERVER <|> PLUGINS_MD5 <|> %s <|> SERVER\n", md5);
 efree(&md5); 


 for(;;)
 {
  bzero(buf, sizeof(buf));
 auth_gets(globals, buf, sizeof(buf)  - 1);
 if(strstr(buf, "COMPLETE_LIST"))
   comm_send_pluginlist(globals);
 else  
   if(strstr(buf, "SEND_PLUGINS_MD5")) {
	plugins_send_md5(globals);
	}
  else
   if(strstr(buf, "PLUGIN_INFO")) {
        char * t = strstr(buf, " <|> ");
	char * s;
	if(!t)continue;
	t = strstr(t + 5, " <|> ");
	if(!t)continue;
	s = t + 5;
	t = strchr(s, ' ');
	if(!t)continue;
	t[0] = '\0';
	plugin_send_infos(globals, atoi(s));
   }
  else break;
 }
}

