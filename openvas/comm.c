/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
 *
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
 * Nessus Communication Manager -- it manages the NTP Protocol, version 1.1
 *
 */ 
 
#include <includes.h>

#include "auth.h"
#include "comm.h" 
#include "preferences.h"
#include "parser.h"
#include "globals.h"
#include "error_dialog.h"

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif


extern int F_quiet_mode;

int comm_send_file(char*);

/*
 * Parses a plugin description message, and returns an arglist with the
 * plugin in it.
 */
static struct arglist * 
parse_plugin(buf)
 char * buf;
{
  char * str;
  char * t;
  struct arglist * plugin;
  int id;
  size_t l;
	
  plugin = emalloc(sizeof(struct arglist));
  sscanf(buf, "%d", &id);
  
  arg_add_value(plugin, "ID", ARG_INT, sizeof(int), (void *)id);
  str = emalloc(20);
  sprintf(str, "%d", id);
  arg_add_value(plugin, "ASC_ID", ARG_STRING, strlen(str), str);
	
  l = strlen(str);
  
  str = parse_separator(buf);if(!str)return NULL;
  arg_add_value(plugin, "NAME", ARG_STRING, strlen(str), estrdup(str));

	
  l   += strlen(str) + 5;
 
  str =  parse_separator(buf+l);if(!str)return NULL;
  arg_add_value(plugin, "CATEGORY", ARG_STRING, strlen(str),estrdup(str));
	
  l += strlen(str) + 5;
  str =  parse_separator(buf+l);if(!str)return NULL;
  arg_add_value(plugin, "COPYRIGHT", ARG_STRING, strlen(str), estrdup(str));
	
  l+= strlen(str) + 5;
	
  
  str = parse_separator(buf+l);if(!str)return  NULL;
  t = str;
  while((t=strchr(t, ';')))t[0]='\n';
  arg_add_value(plugin, "DESCRIPTION", ARG_STRING, strlen(str), estrdup(str));
  l+= strlen(str) + 5;
	
  str = parse_separator(buf+l);if(!str)return NULL;
  arg_add_value(plugin, "SUMMARY", ARG_STRING, strlen(str), estrdup(str));
	
  l+= strlen(str) + 5;
	
   str = parse_separator(buf+l);if(!str)return NULL;
   arg_add_value(plugin, "FAMILY", ARG_STRING, strlen(str), estrdup(str));
   
   
   l+= strlen(str) + 5;
   str = parse_separator(buf+l);
   if(str){
   arg_add_value(plugin, "VERSION", ARG_STRING, strlen(str), estrdup(str));
  
   
   l+= strlen(str) + 5;
   str = parse_separator(buf+l);
   if(str != NULL)
    {
    arg_add_value(plugin, "CVE_ID", ARG_STRING, strlen(str), estrdup(str));
    l += strlen(str) + 5;
   
    str = parse_separator(buf + l);
    if(str != NULL)
     { 
     arg_add_value(plugin, "BUGTRAQ_ID", ARG_STRING, strlen(str), estrdup(str));
     l += strlen(str) + 5;
     str = parse_separator(buf + l);
     if( str != NULL )arg_add_value(plugin, "XREFS", ARG_STRING, strlen(str), estrdup(str));
     }
   }
   
   
 
  }
	
   /*
    * Say that it is enabled by default
    */
   if((!strcmp(arg_get_value(plugin, "CATEGORY"), "denial")) ||
      (!strcmp(arg_get_value(plugin, "CATEGORY"), "kill_host")) ||
	! strcmp(arg_get_value(plugin, "CATEGORY"), "flood") ||
	   (!strcmp(arg_get_value(plugin, "CATEGORY"), "destructive_attack"))||
	!strcmp(arg_get_value(plugin, "CATEGORY"), "scanner") )
	 arg_add_value(plugin, "ENABLED", ARG_INT, sizeof(int), (void*)0);
    else
	  arg_add_value(plugin, "ENABLED", ARG_INT, sizeof(int), (void *)1);
	  
	  
   return plugin;
}


#if 0
/* 
 * comm_plugins_update
 *
 * For each plugins in the supplied list, the client will ask information
 * about the remote plugin (and will update the plugins cache accordingly)
 *
 * Arguments :
 *    <list> : the list of plugins to update (only the <name> field is used)
 *
 * Returns :
 *    <0>    : no error
 */
static int
comm_plugins_update(list)
 struct arglist * list;
{
 char buf[16384];
 if(!list)
  return -1;
  
 while(list->next)
 {
  char * t;
  char * name;
  
  network_printf("CLIENT <|> PLUGIN_INFO <|> %s <|> CLIENT\n", list->name);
  network_gets(buf, 16384);
  t  = strchr(buf, ' ');
  if(!t){
      list = list->next;
      continue;
      }
  t[0] = '\0';
  name = strdup(buf);
  t[0] = ' ';
  efree(&name);
  list = list->next;
 }
 return 0;
}
#endif


/*
 * comm_plugin_upload
 *
 * This function uploads a local plugin on the server
 *
 * Arguments :
 *    <fname> : local name of the file to upload.
 *
 * Returns : 
 *    <-1>    : an error occured
 *    <0>     : upload went well
 *
 *
 *  XXX To do : make sure that, according to its extension, this file will
 *  XXX 	not be discarded by the server
 *
 */
int
comm_plugin_upload(fname)
 char * fname;
{
 int fd;
 struct stat stt;
 size_t tot = 0;
 char buff[2048];
 char *content;
 char *e;
 int len;
 
 e = strrchr(fname, '/');
 if(!e)e = fname;
 else e++;
 fd = open(fname, O_RDONLY);

 if(fd < 0)
 {
  char	msg[1024];
  snprintf(msg, sizeof(msg), "%s: %s\n", fname, strerror(errno));
  show_error(msg);
  return -1;
 }
 
 fstat(fd, &stt);
 len = (int)stt.st_size;
 network_printf("CLIENT <|> ATTACHED_PLUGIN\n");
 network_printf("name: %s\n", e);
 network_printf("content: octet/stream\n");
 network_printf("bytes: %d\n", len);
 content = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
 if(content == MAP_FAILED)
  {
   show_error(strerror(errno));
   close(fd);
   return -1;
  }
  
  
 while(tot != len)
 {
  int e;
  e = write_stream_connection(GlobalSocket, content + tot, len - tot);
  if(e < 0)
  {
   show_error(strerror(errno));
   munmap(content, len);
   close(fd);
   return -1;
  }
  tot += e;
 }
 
 munmap(content, len);
 close(fd);
 network_gets(buff, sizeof(buff) - 1); /* Confirmation message */
 return 0;
}








/*
 * comm_init
 *
 * This function initializes the communication between 
 * the server and the client.
 * Its role is to check that the remote server is using NTP/1.1
 * 
 * Arguments :
 *  soc : a socket connected to the remote server
 * Returns :
 *  0 if the remote server is using NTP/1.1
 * -1 if it's not
 */

int 
comm_init(soc, proto_name)
	int soc;
        char * proto_name;
{  
  char * buf;
  int n = strlen(proto_name);
 
  /* What shall I do if it fails? */
  (void) write_stream_connection(soc, proto_name, n);

  buf = emalloc(15);
  recv_line(soc, buf, 14);
  if(strncmp(buf, proto_name, 11))
  	{
	efree(&buf);
	return(-1);
	}
  efree(&buf);
  return(0);
}



/*
 * Get the server prefs. Note that when using the cli, the data
 * is not stored the same way in memory
 */
int
cli_comm_get_preferences(prefs)
 struct arglist * prefs;
{
 char buf[32768];
 int finished = 0;
 struct arglist * serv_prefs, * serv_infos,* plugs_prefs;
 
 
 Sessions_saved = 0;
 Detached_sessions_saved = 0;


  serv_prefs = arg_get_value(prefs, "SERVER_PREFS");
  plugs_prefs = arg_get_value(prefs, "PLUGINS_PREFS");
  
  if ( serv_prefs == NULL )
  {
  	serv_prefs = emalloc(sizeof(struct arglist));
	arg_add_value(prefs, "SERVER_PREFS", ARG_ARGLIST, -1, serv_prefs);
  }
  
  if ( plugs_prefs == NULL)
  {
  	plugs_prefs = emalloc(sizeof(struct arglist));
	arg_add_value(prefs, "PLUGINS_PREFS", ARG_ARGLIST, -1, plugs_prefs);
  }
  
 
  serv_infos = emalloc(sizeof(struct arglist));
  if(arg_get_value(prefs, "SERVER_INFO") == NULL)
    arg_add_value(prefs, "SERVER_INFO", ARG_ARGLIST, -1, serv_infos);
  else
   arg_set_value(prefs, "SERVER_INFO", -1, serv_infos);
   
   
 bzero(buf, sizeof(buf));
 network_gets(buf, sizeof(buf) - 1 );
 if(!strncmp(buf, "SERVER <|> PREFERENCES <|>", 26))
 {
  while(!finished)
  {
   bzero(buf, sizeof(buf));
   network_gets(buf, sizeof(buf));;
   if( buf[strlen(buf)-1] == '\n' )
   	buf[strlen(buf)-1] = 0;
	
   if(strncmp(buf, "<|> SERVER", 10) == 0)
   {
   	finished = 1;
   }
   else
   {
    char * pref;
    char * value;
    char * v;
    char * a = NULL , *b = NULL, *c = NULL;
    
    pref = buf;
    v = strchr(buf, '<');
    if(!v)
	    continue;
    v-=1;
    v[0] = 0;
    
    value = v + 5;
    v = emalloc(strlen(value)+1);
    strncpy(v, value, strlen(value));
    a = strchr(pref, '[');
    if(a)b=strchr(a, ']');
    if(b)c=strchr(b,':');
    if((!a)||(!b)||(!c)){
    	if(!strcmp(pref, "ntp_save_sessions"))
		Sessions_saved = 1;
	else
	 if(!strcmp(pref, "ntp_detached_sessions"))
	 	Detached_sessions_saved = 1;
	 else
	 if(strncmp(pref, "server_info_", strlen("server_info_")) == 0)
	 {
	  arg_add_value(serv_infos, pref, ARG_STRING, strlen(v), v);
	 }
	 else
	  {
	    /* 
	     * Don't set the value if set already
	     */
	    if(arg_get_type(serv_prefs, pref) < 0)
    	 	arg_add_value(serv_prefs, pref, ARG_STRING, strlen(v), v);
	 }
       }
    else
    {
     if(arg_get_type(plugs_prefs, pref) < 0)
      {
      char * x = strchr(v, ';');
      if(!ListOnly && x )x[0] = '\0';
      arg_add_value(plugs_prefs, pref, ARG_STRING, strlen(v), v);
      }
     }
   }
  }
 }
 return(0); 
}



/*
 * Retrieves the server preferences
 * we must make a difference between the prefs of the 
 * server itself, and the prefs of the plugins
 */
int
comm_get_preferences(prefs)
 struct arglist * prefs;
{
 char * buf;
 int finished = 0;
 struct arglist * serv_prefs, * serv_infos;
 struct arglist * plugin = NULL;
 
#ifdef ENABLE_SAVE_TESTS
 Sessions_saved = 0;
 Detached_sessions_saved = 0;
#endif

 
 serv_prefs = arg_get_value(prefs, "SERVER_PREFS");
 if(!serv_prefs)serv_prefs = emalloc(sizeof(struct arglist));
 
 serv_infos = emalloc(sizeof(struct arglist));
 buf = emalloc(32768);
 network_gets(buf, 32768);
 if(!strncmp(buf, "SERVER <|> PREFERENCES <|>", 26))
 {
  while(!finished)
  {
   bzero(buf, 32768);
   network_gets(buf, 32768);;
   if(buf[strlen(buf)-1]=='\n')buf[strlen(buf)-1]=0;
   if(!strncmp(buf, "<|> SERVER", 10))finished = 1;
  else
   {
    char * pref;
    char * value;
    char * v;
    char * a = NULL , *b = NULL, *c = NULL;
    
    pref = buf;
    v = strchr(buf, '<');
    if(!v)
	    continue;
    v-=1;
    v[0] = 0;
    
    value = v + 5;
    v = emalloc(strlen(value)+1);
    strncpy(v, value, strlen(value));
    a = strchr(pref, '[');
    if(a)b=strchr(a, ']');
    if(b)c=strchr(b,':');
    if(F_quiet_mode || (!a)||(!b)||(!c)){
#ifdef ENABLE_SAVE_TESTS
    	if(!strcmp(pref, "ntp_save_sessions"))
		Sessions_saved = 1;
	else
	 if(!strcmp(pref, "ntp_detached_sessions"))
	 	Detached_sessions_saved = 1;
	 else
#endif
	 if(!strncmp(pref, "server_info_", strlen("server_info_")))
	 {
	  arg_add_value(serv_infos, pref, ARG_STRING, strlen(v), v);
	 }
	 else
	  {
	   if(arg_get_type(serv_prefs, pref) < 0)
    	 	arg_add_value(serv_prefs, pref, ARG_STRING, strlen(v), v);
	  }
       }
    else
    {
     /* the format of the pref name is xxxx[xxxx] : this is a plugin pref */
     char * plugname;
     char * type;
     char * name;
     struct arglist * pprefs, *prf;
     char* fullname = strdup(pref);
     
     while(fullname[strlen(fullname)-1]==' ')fullname[strlen(fullname)-1]='\0';
     a[0]=0;
     plugname = emalloc(strlen(pref)+1);
     strncpy(plugname, pref, strlen(pref));
     
     a[0]='[';
     a++;
     b[0]=0;
     type = emalloc(strlen(a)+1);
     strncpy(type, a, strlen(a));
     b[0]=']';
     c++;
     name = emalloc(strlen(c)+1);
     strncpy(name, c, strlen(c));
     
     plugin = arg_get_value(Plugins, plugname);
     if(!plugin){
      plugin = arg_get_value(Scanners, plugname);
      if(!plugin)
       {
       fprintf(stderr, "Error : we received a preference for the plugin %s\n", plugname);
       fprintf(stderr, "but apparently the server has not loaded it\n");
       }
      }
     pprefs = arg_get_value(plugin, "plugin_prefs");
     if(!pprefs)
     {
      pprefs = emalloc(sizeof(struct arglist));
      arg_add_value(plugin, "plugin_prefs", ARG_ARGLIST, -1, pprefs);
     }
     prf = emalloc(sizeof(struct arglist));
     
     /*
      * No default value for files to upload (we don't want the
      * server to suggest we upload /etc/shadow ;)
      */
    
     if(!strcmp(type, PREF_FILE))
       arg_add_value(prf, "value", ARG_STRING,0, strdup(""));
     else
       arg_add_value(prf, "value", ARG_STRING,strlen(v), v);
     
     arg_add_value(prf, "type", ARG_STRING, strlen(type), type);
     arg_add_value(prf, "fullname", ARG_STRING, strlen(fullname), fullname);
     arg_add_value(pprefs, name, ARG_ARGLIST, -1, prf);
   }
   }
  }
  if(!arg_get_value(prefs, "SERVER_PREFS"))
   arg_add_value(prefs, "SERVER_PREFS", ARG_ARGLIST, sizeof(serv_prefs), serv_prefs);
 
  if(!arg_get_value(prefs, "SERVER_INFO"))
   arg_add_value(prefs, "SERVER_INFO", ARG_ARGLIST, sizeof(serv_infos), serv_infos);
  else
   arg_set_value(prefs, "SERVER_INFO", sizeof(serv_infos), serv_infos);
 }
 efree(&buf);
 return(0); 
}


static int
cli_send_prefs_arglist(pref, upload, pprefs)
 struct arglist * pref;
 harglst** upload;
 int pprefs;
{
 if(!pref)
  return -1;
 
 while(pref->next)
 {
   if(pref->type == ARG_STRING)
    {
    	if(strstr(pref->name, "["PREF_FILE"]:"))
   	{
     	if(!*upload)*upload = harg_create(50);
     	harg_add_int(*upload, pref->value, 1);
   	}
	
 	if ( pprefs == 0 )	network_printf("%s <|> %s\n", pref->name, pref->value);
	else if ( strchr(pref->value, ';') != NULL )
	{
	 char * p;
	 p = strchr(pref->value, ';');
	 p[0] = '\0';
	 network_printf("%s <|> %s\n", pref->name, pref->value);
	 p[0] = ';';
	}
        else network_printf("%s <|> %s\n", pref->name, pref->value);
    }
   else if(pref->type == ARG_INT)
    {
     	network_printf("%s <|> %s\n", pref->name, pref->value?"yes":"no");
    }
   pref = pref->next;
 }
 return 0;
}


static int 
cli_comm_send_preferences(preferences)
 struct arglist * preferences;
{
  harglst * files_to_send = NULL;
 struct arglist * pref = arg_get_value(preferences, "SERVER_PREFS");
 struct arglist * pprefs = arg_get_value(preferences, "PLUGINS_PREFS");
 
 network_printf("CLIENT <|> PREFERENCES <|>\n");
 /*
  * workaround to use new features while keeping
  * backward compatibility
  */
 network_printf("ntp_opt_show_end <|> yes\n");
 network_printf("ntp_keep_communication_alive <|> yes\n");
 network_printf("ntp_short_status <|> yes\n");
 network_printf("ntp_client_accepts_notes <|> yes\n");
 network_printf("ntp_escape_crlf <|> yes\n");
 if(pref)cli_send_prefs_arglist(pref, &files_to_send, 0);
 if(pprefs)cli_send_prefs_arglist(pprefs, &files_to_send, 1);
 network_printf("<|> CLIENT\n");
 if(files_to_send)
 { 
  hargwalk * hw;
  char * key;

  hw = harg_walk_init(files_to_send);
  while((key = (char*)harg_walk_next(hw)))
  {
   comm_send_file(key);
  }
  harg_close_all(files_to_send); /* frees memory */
 }
 return(0);
}



static int 
gui_comm_send_preferences(preferences)
 struct arglist * preferences;
{
 harglst * files_to_send = NULL;
 struct arglist * pref = arg_get_value(preferences, "SERVER_PREFS");
 struct arglist * plugins[2];
 struct arglist * pprefs = arg_get_value(preferences, "PLUGINS_PREFS");
 int i;
 
 
 plugins[0] = Plugins;
 plugins[1] = Scanners;
 
 if(!pprefs)
 {
  pprefs = emalloc(sizeof(struct arglist));
  arg_add_value(preferences, "PLUGINS_PREFS", ARG_ARGLIST, -1, pprefs);
 }
 network_printf("CLIENT <|> PREFERENCES <|>\n");
 /*
  * workaround to use new features while keeping
  * backward compatibility
  */
 network_printf("ntp_opt_show_end <|> yes\n");
 network_printf("ntp_keep_communication_alive <|> yes\n");
 network_printf("ntp_short_status <|> yes\n");
 network_printf("ntp_client_accepts_notes <|> yes\n");
 network_printf("ntp_escape_crlf <|> yes\n");
 while(pref && pref->next)
  {
   if(pref->type == ARG_STRING)
    {
    	network_printf("%s <|> %s\n", pref->name, pref->value);
    }
   else if(pref->type == ARG_INT)
    {
     	network_printf("%s <|> %s\n", pref->name, pref->value?"yes":"no");
    }
   pref = pref->next;
   }
 
 /* send the plugins prefs back to the server */
 for(i=0;i<2;i++)
 {
  struct arglist * plugs = plugins[i];
  while(plugs && plugs->next)
  {
   struct arglist * plugin_prefs = arg_get_value(plugs->value, "plugin_prefs");
   while(plugin_prefs && plugin_prefs->next)
   {
    char * name = plugin_prefs->name;
    char * type = arg_get_value(plugin_prefs->value, "type");
    char * value = arg_get_value(plugin_prefs->value, "value");
    char * fullname = arg_get_value(plugin_prefs->value, "fullname");
 
    
    if((arg_get_type(pprefs, fullname))>=0)
     {
      if((arg_get_type(pprefs, fullname))==ARG_INT)
       {
        if(!strcmp(value, "yes"))
	 arg_set_value(pprefs, fullname, sizeof(int), (void*)1);
	else
	 arg_set_value(pprefs, fullname, sizeof(int), NULL);
       }
       else
         arg_set_value(pprefs, fullname, strlen(value), strdup(value));
      }
    else
     {
       if(!strcmp(value, "yes"))
        arg_add_value(pprefs, fullname, ARG_INT, sizeof(int), (void*)1);
      else if(!strcmp(value, "no"))
        arg_add_value(pprefs, fullname, ARG_INT, sizeof(int), NULL);
      else
        arg_add_value(pprefs, fullname, ARG_STRING, strlen(value), strdup(value));
     }
    network_printf("%s[%s]:%s <|> %s\n", plugs->name, type, name, value);
    if(!strcmp(type, PREF_FILE))
    {
     if(!files_to_send)files_to_send = harg_create(50);
     harg_add_int(files_to_send, value, 1);
    } 
    plugin_prefs =   plugin_prefs->next;
    }
    plugs = plugs->next;
   }
 }
 network_printf("<|> CLIENT\n");
 if(files_to_send)
 { 
  hargwalk * hw;
  char * key;

  hw = harg_walk_init(files_to_send);
  while((key = (char*)harg_walk_next(hw)))
  {
   comm_send_file(key);
  }
  harg_close_all(files_to_send); /* frees memory */
 }
 return(0);
}
 int len;



int 
comm_send_preferences(preferences) 
 struct arglist * preferences;
{
 if(F_quiet_mode)
  return cli_comm_send_preferences(preferences);
 else
  return gui_comm_send_preferences(preferences);
}

int
comm_send_file(fname)
 char * fname;
{ 
 int fd = open(fname, O_RDONLY);
 struct stat stt;
 long tot = 0;
 char buff[1024];
 int len;
 
 if(!fname || !strlen(fname))
  return 0;
  
 if(fd < 0)
 {
  char	msg[1024];
  snprintf(msg, sizeof(msg), "%s: %s", fname, strerror(errno));
  return -1;
 }
 
 fstat(fd, &stt);
 len = (int)stt.st_size;
 network_printf("CLIENT <|> ATTACHED_FILE\n");
 network_printf("name: %s\n", fname);
 network_printf("content: octet/stream\n");
 network_printf("bytes: %d\n", len);
 tot = len;
 while(tot > 0)
 {
  int m = 0, n;
  bzero(buff, sizeof(buff));
  n = read(fd, buff, MIN(tot, sizeof(buff)));
  while(m < n)
  { 
   int e;
   e = nsend(GlobalSocket, buff + m, n - m, 0);
   if(e < 0)
    {
     show_error(strerror(errno));
     close(fd);
     return -1;
    }
   else m+=e;
  }
  tot -= n;
 }
 network_gets(buff, sizeof(buff) - 1);
 return 0;
}

int
comm_send_rules(preferences)
 struct arglist * preferences;
{
 struct arglist * serv_prefs = arg_get_value(preferences, "SERVER_PREFS");
 struct arglist * rules = arg_get_value(serv_prefs, "RULES");
 network_printf("CLIENT <|> RULES <|>\n");
 while(rules && rules->next)
 {
  network_printf("%s\n", rules->value);
  rules = rules->next;
 }
 network_printf("<|> CLIENT\n");
 return(0);
}


void
comm_get_preferences_errors(preferences)
 struct arglist * preferences;
{
 char * buf = emalloc(512);
 network_gets(buf, 512);
 network_gets(buf, 512);
 efree(&buf);
}


/*
 * Retrieves the server rules and store them in
 * a subcategory in the preferences
 */
int
comm_get_rules(prefs)
  struct arglist * prefs;
{
 struct arglist * serv_prefs = arg_get_value(prefs, "SERVER_PREFS");
 struct arglist * rules = NULL;
 char * buf = emalloc(32768);
 int finished = 0;
 
 rules = arg_get_value(prefs, "RULES");
 if(!rules)rules = arg_get_value(serv_prefs, "RULES");
 
 if(!rules){
 	rules = emalloc(sizeof(struct arglist));
        arg_add_value(prefs, "RULES", ARG_ARGLIST, -1, rules);
        }
 
 network_gets(buf, 32768);
 if(!strncmp(buf, "SERVER <|> RULES <|>", 20))
 {
  while(!finished)
  {
#ifdef USELESS_AS_OF_NOW
   char * rule, * name;
#endif
   network_gets(buf, 32768);
   if(strstr(buf, "<|> SERVER"))finished = 1;
   else
   {
#ifdef USELESS_AS_OF_NOW
    struct arglist * t = rules;
    int ok = 1;
    int i = 0;
    rule = emalloc(strlen(buf));
    strncpy(rule, buf, strlen(buf)-1);
    while(t && t->next && ok)
    	{
        if(!strcmp(t->value, rule))ok = 0;     
        t = t->next;
        }
    if(ok)
    {
     name = emalloc(10);
     sprintf(name, "%d", ++i);
     arg_add_value(rules, name, ARG_STRING, strlen(rule),rule); 
     efree(&name);
    }
    else efree(&rule);
#endif
   }
  }
 if(!arg_get_value(serv_prefs, "RULES"))
   arg_add_value(serv_prefs, "RULES", ARG_ARGLIST, -1, rules);
 else
   arg_set_value(serv_prefs, "RULES", -1, rules);
 }
 efree(&buf);
 return(0);
} 



int
comm_get_plugins()
{
  char * buf;
  int bufsz;
  int flag = 0;
  int num = 0;
  int num_2 = 0;
  struct arglist * plugin_set;
  struct arglist * scanner_set;
  int ret;
 
 /* arg_free_all(Plugins);
  arg_free_all(Scanners);
  */
  Plugins = emalloc(sizeof(struct arglist));
  Scanners = emalloc(sizeof(struct arglist));
  plugin_set = arg_get_value(Prefs, "PLUGIN_SET");
  scanner_set = arg_get_value(Prefs, "SCANNER_SET");
  
  bufsz = 1024 * 1024;
  buf = emalloc(bufsz);
  network_gets(buf, 27);
  if(strncmp(buf, "SERVER <|> PLUGIN_LIST <|>", 26))return(-1);
  while(!flag)
    {
      network_gets(buf, bufsz);
      if ( buf[0] == '\0' ) 
	{
	  show_error("The daemon shut down the communication");
	  break;
	}
      if(!strncmp(buf, "<|> SERVER", 10))flag = 1;
      else
	{
	 struct arglist * plugin = parse_plugin(buf);
	
	 if(!plugin)
	 {
	  fprintf(stderr, "Could not parse %s\n", buf);
	  continue;
	 } 
         
          if(!strcmp(arg_get_value(plugin, "CATEGORY"), "scanner"))
          {
           num_2++;
	   num++;
           if(!arg_get_value(Scanners, arg_get_value(plugin, "NAME")))
            arg_add_value(Scanners,  arg_get_value(plugin, "NAME"), ARG_ARGLIST,
            		-1, plugin);
           else
             arg_set_value(Scanners,  arg_get_value(plugin, "NAME"), -1, plugin); 
            if(scanner_set && 
              ((int)arg_get_type(scanner_set, plugin_asc_id(plugin))<0)) arg_add_value(scanner_set, plugin_asc_id(plugin), ARG_INT, sizeof(int),arg_get_value(plugin, "ENABLED"));
           }
          else
          {
           num++;
	
           if(!arg_get_value(Plugins,  arg_get_value(plugin, "NAME")))
	    arg_add_value(Plugins,  arg_get_value(plugin, "NAME"), ARG_ARGLIST,
			-1, plugin);
           else
             arg_set_value(Plugins,  arg_get_value(plugin, "NAME"), -1, plugin);
              
           if(plugin_set &&
             ((int)arg_get_type(plugin_set, plugin_asc_id(plugin))<0))
              arg_add_value(plugin_set, plugin_asc_id(plugin), ARG_INT, sizeof(int),arg_get_value(plugin, "ENABLED"));
            
           }
	}
    }
   ret = pluginset_apply(Plugins, "PLUGIN_SET");
   if((pluginset_apply(Scanners, "SCANNER_SET")) || ret)
       {
        /* warn the user that the tests won't be complete */
        show_warning("\
The plugins that have the ability to crash remote services or hosts\n\
have been disabled. You should activate them if you want your security\n\
audit to be complete");
       }
  PluginsNum = num;
  ScannersNum = num_2;
  
  return(0);
}








/*-------------------------------------------------------------------------

			Sessions management
			
---------------------------------------------------------------------------*/

/*
 * Does the server support sessions saving ?
 */
int 
comm_server_restores_sessions(prefs)
 struct arglist * prefs;
{
#ifdef ENABLE_SAVE_TESTS
 return Sessions_saved;
#else
 return 0;
#endif
}

int 
comm_server_detached_sessions(prefs)
 struct arglist * prefs;
{
#ifdef ENABLE_SAVE_TESTS
 return Detached_sessions_saved;
#else
 return 0;
#endif
}

harglst * 
comm_get_sessions()
{
 char buff[32768];
 harglst * ret = NULL;
 network_printf("CLIENT <|> SESSIONS_LIST <|> CLIENT\n");
 network_gets(buff, sizeof(buff));
 if(!strcmp(buff, "SERVER <|> SESSIONS_LIST\n"))
 {
  ret = harg_create(15000);
  while(!strstr(buff, "<|> SERVER"))
  {
   char * t;
  
   network_gets(buff, sizeof(buff));
   t = strchr(buff, ' ');
   if(t && !strstr(buff, "<|> SERVER"))
    {
     if(buff[strlen(buff)-1]=='\n')buff[strlen(buff)-1]='\0';
     t[0]=0;t++;
     harg_add_string(ret, buff, t);
    }
   }
  }
 return ret;
}


void
comm_delete_session(name)
 char * name;
{
 network_printf("CLIENT <|> SESSION_DELETE <|> %s <|> CLIENT\n",name);
}

void
comm_restore_session(name)
 char * name;
{
 network_printf("CLIENT <|> SESSION_RESTORE <|> %s <|> CLIENT\n", name);
}

void
comm_stop_detached_session(name)
 char * name;
{
 network_printf("CLIENT <|> STOP_DETACHED <|> %s <|> CLIENT\n", name);
}

harglst *
comm_get_detached_sessions()
{
 char buff[32768];
 harglst * ret = NULL;
 
 network_printf("CLIENT <|> DETACHED_SESSIONS_LIST <|> CLIENT\n");
 network_gets(buff, sizeof(buff));
 if(!strcmp(buff, "SERVER <|> DETACHED_SESSIONS_LIST\n"))
 {
  ret = harg_create(15000);
  while(!strstr(buff, "<|> SERVER"))
  {
   char * t;
   network_gets(buff, sizeof(buff));
   t = strchr(buff, ' ');
   if(t && !strstr(buff, "<|> SERVER"))
    {
     if(buff[strlen(buff)-1]=='\n')buff[strlen(buff)-1]='\0';
     t[0]=0;t++;
     harg_add_string(ret, buff, t);
    }
   }
  }
 return ret;
}





int
comm_get_dependencies()
{
 char buff[32768];
 bzero(buff, sizeof(buff));
 network_gets(buff, sizeof(buff)-1);
 if(Dependencies)
 	arg_free_all(Dependencies);
 Dependencies = emalloc(sizeof(struct arglist));
 if(!strcmp(buff, "SERVER <|> PLUGINS_DEPENDENCIES\n"))
 {
   network_gets(buff, sizeof(buff)-1);
   while(strcmp(buff, "<|> SERVER\n"))
   {
    struct arglist * deps;
    char * name;
    char * t = strstr(buff, " <|> ");
    char * s;
    if(t)
    {
     s = t + 5;
     t[0] = '\0';
     name = buff;
     deps = emalloc(sizeof(struct arglist));
     while(s)
     {
      t = strstr(s, " <|> ");
      if(t)
      { 
      t[0] = '\0';
      arg_add_value(deps, s, ARG_INT, (sizeof(int)), (void*)1);
      s = t + 5;
      }
      else s = NULL;
     }
     arg_add_value(Dependencies, name, ARG_ARGLIST, -1, deps);
    }
    network_gets(buff, sizeof(buff)-1);
   }
 }
 return 0;
}
