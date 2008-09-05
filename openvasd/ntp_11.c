/* OpenVAS
* $Id$
* Description: OpenVAS Communication Manager; it manages the OpenVAS Transfer Protocol,
* version 1.1 and 1.2.
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

#include "ntp.h"
#include "ntp_11.h"
#include "otp_1_0.h"
#include "comm.h"
#include "auth.h"
#include "rules.h"
#include "log.h"
#include "users.h"
#include "utils.h"
#include "save_tests.h"
#include "preferences.h"
#include "hosts.h"

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x):(y))
#endif


#ifndef DEBUG_SSL
# define DEBUG_SSL	1
#endif


static int ntp_11_prefs(struct arglist *);
static int ntp_11_read_prefs(struct arglist *);
static void ntp_11_send_prefs_errors(struct arglist *);
static int ntp_11_rules(struct arglist *);
static int ntp_11_long_attack(struct arglist *, char *);
static int ntp_11_recv_file(struct arglist*);

#ifdef ENABLE_SAVE_TESTS
static int ntp_11_list_sessions(struct arglist*);
static int ntp_11_delete_session(struct arglist*, char*);
static int ntp_11_restore_session(struct arglist*, char*);
#endif
/*
 * Parses the input sent by the client before
 * the NEW_ATTACK message.
 */
int ntp_11_parse_input(globals, input)
   struct arglist * globals;
   char * input;
{
 char * str;
 int input_len = strlen(input);
 char * orig = emalloc(input_len + 1);
 int result = 1; /* default return value is 1 */

 strncpy(orig, input, input_len);
 
 str = strstr(input, " <|> ");
 if( str == NULL )
	{
 	efree(&orig);
	return 1;
	}

 str[0] = '\0';
 if( strcmp(input, "CLIENT") == 0 )
 {
  input = str + 5;
  str = strchr(input, ' ');
  if(str != NULL )
	str[0] = '\0';

  if(input[strlen(input) - 1] == '\n')
	input[strlen(input) - 1] = '\0';

  switch(otp_1_0_get_client_request(input)) {
    case CREQ_ATTACHED_FILE:
      ntp_11_recv_file(globals);
      break;

    case CREQ_LONG_ATTACK:
      result = ntp_11_long_attack(globals, orig);
      break;

    case CREQ_OPENVAS_VERSION:
      otp_1_0_server_openvas_version(globals);
      break;

    case CREQ_PLUGIN_INFO: {
      char * t, *s;
      t = strstr(&(str[1]), " <|> ");
      if( t == NULL ) {
        result = -1;
        break;
      }
      s = t + 5;
      plugin_send_infos(globals, atoi(s));
      break;
      }

    case CREQ_PREFERENCES:
      ntp_11_prefs(globals);
      break;

    case CREQ_RULES:
      ntp_11_rules(globals);
      break;

#ifdef ENABLE_SAVE_TESTS
    case CREQ_SESSIONS_LIST:
      ntp_11_list_sessions(globals);
      break;

    case CREQ_SESSION_DELETE:
      ntp_11_delete_session(globals, orig);
      break;

    case CREQ_SESSION_RESTORE:
      result = ntp_11_restore_session(globals, orig);
      break;
#endif

    case CREQ_STOP_WHOLE_TEST:
      log_write("Stopping the whole test (requested by client)");
      hosts_stop_all();
      result = NTP_STOP_WHOLE_TEST;
      break;

    case CREQ_STOP_ATTACK: {
      char * t, *s;
      char * user = (char*)arg_get_value(globals, "user");
      s = str + 5;	
      t = strstr(s, " <|> ");
      if(t == NULL) {
        result = -1;
        break;
      }
      t[0] = '\0';
      log_write("user %s : stopping attack against %s\n",  user, s);
      hosts_stop_host(globals, s);
      ntp_1x_timestamp_host_scan_interrupted(globals, s);
      ntp_11_show_end(globals, s, 0);
      break;
      }

    case CREQ_UNKNOWN:
      break;
  }
 }

 efree(&orig);
 return(result);
}

static int 
ntp_11_long_attack(globals, orig)
 struct arglist * globals;
 char * orig;
{
 struct arglist * preferences = arg_get_value(globals, "preferences");
 int soc = (int)arg_get_value(globals, "global_socket");
 char input[16384];
 int size;
 char * target;
 char * plugin_set;
 int n;
 
  n = recv_line(soc, input, sizeof(input) - 1);
  if(n <= 0)
   return -1;
   
#if DEBUGMORE
  printf("long_attack :%s\n", input);
#endif
  if(!strncmp(input, "<|> CLIENT", sizeof("<|> CLIENT")))
   return 1; 
  size = atoi(input);
  target = emalloc(size+1);
  
  n = 0;
  while(n < size)
  {
   int e;
   e = nrecv(soc, target+n, size-n, 0);
   if(e > 0)n+=e;
   else return -1;
  }
 plugin_set = arg_get_value(preferences, "plugin_set");
 if(!plugin_set || plugin_set[0] == '\0' )
 {
  plugin_set = emalloc(3);
  sprintf(plugin_set, "-1");
  if(!arg_get_value(preferences, "plugin_set")) 
   arg_add_value(preferences, "plugin_set", ARG_STRING, strlen(plugin_set), plugin_set);
  else
   arg_set_value(preferences, "plugin_set", strlen(plugin_set), plugin_set);
 }
 
 comm_setup_plugins(globals, plugin_set);
 if(arg_get_value(preferences, "TARGET"))
  {
  char * old = arg_get_value(preferences, "TARGET");
  efree(&old);
  arg_set_value(preferences, "TARGET", strlen(target), target);
  }
 else
  arg_add_value(preferences, "TARGET", ARG_STRING, strlen(target), target);
 return 0;
} 
static int ntp_11_prefs(globals)
 struct arglist * globals;
{
 int problem;
 ntp_caps * caps;
 struct arglist * prefs;
 char * value;

 problem = ntp_11_read_prefs(globals);
 if(!problem)ntp_11_send_prefs_errors(globals);
 caps = arg_get_value(globals, "ntp_caps");
 prefs = arg_get_value(globals, "preferences");
 value = arg_get_value(prefs, "ntp_escape_crlf");
 if(value)caps->escape_crlf = 1;
 return(problem);
}



static int 
ntp_11_read_prefs(globals)
 struct arglist * globals;
{
 struct arglist *  preferences = arg_get_value(globals, "preferences");
 int soc = (int)arg_get_value(globals, "global_socket");
 char * input;
 int input_sz = 1024*1024;
 int n;

 input = emalloc(input_sz);
 for (;;) {
   input[0] = '\0';
#if DEBUG_SSL > 2
   fprintf(stderr, "ntp_11_read_prefs > soc=%d\n", soc);
#endif
   n = recv_line (soc, input, input_sz - 1);

  if (n < 0 || input [0] == '\0') {
    log_write ("Empty data string -- closing comm. channel\n");
    EXIT(0);
  }

  if(strstr(input, "<|> CLIENT") != NULL ) /* finished = 1; */
    break ;
  /* else */
  
  {
   char * pref;
   char * value;
   char * v;
   char * old;
    pref = input;
    v = strchr(input, '<');
    if(v)
    { v-=1;
      v[0] = 0;
    
      value = v + 5;
      /*
       * "system" prefs can't be changed
       */
      if(!strcmp(pref, "logfile")           ||
         !strcmp(pref, "config_file")       ||
         !strcmp(pref, "plugins_folder")    ||
	 !strcmp(pref, "dumpfile")          ||
	 !strcmp(pref, "users")             ||
	 !strcmp(pref, "rules")             ||
	 !strncmp(pref, "peks_", 5)         ||
	 !strcmp(pref, "negot_timeout")     ||
	 !strcmp(pref, "cookie_logpipe")    ||
	 !strcmp(pref, "force_pubkey_auth") ||
	 !strcmp(pref, "log_while_attack")  ||
	 !strcmp(pref, "ca_file") 	    ||
	 !strcmp(pref, "key_file")	    ||
	 !strcmp(pref, "cert_file")	    ||
	 !strcmp(pref, "be_nice")	    ||
	 !strcmp(pref, "log_plugins_name_at_load") ||
         !strcmp(pref, "nasl_no_signature_check"))
      	continue;
      
      old = arg_get_value(preferences, pref);
#ifdef DEBUGMORE     
      printf("%s - %s (old : %s)\n", pref, value, old);
#endif     
      if ( value[0] != '\0' )value[strlen(value)-1]='\0';
    
      if( old != NULL )
      {
       if( strcmp(old, value) != 0 )
        {
	 efree(&old); 
         v = estrdup(value);
	 arg_set_value(preferences, pref, strlen(v), v);
	}
      }
      else
      {
       v = estrdup(value);
       arg_add_value(preferences, pref, ARG_STRING, strlen(v), v);
      }
    }
  }
 }

 efree(&input);
 return(0);
}


static void ntp_11_send_prefs_errors(globals)
 struct arglist * globals;
{
 /* not implemented yet */
 auth_printf(globals, "SERVER <|> PREFERENCES_ERRORS <|>\n");
 auth_printf(globals, "<|> SERVER\n");
}



static int 
ntp_11_rules(globals)
 struct arglist * globals;
{
 struct openvas_rules * user_rules = emalloc(sizeof(*user_rules));
 struct openvas_rules * rules = arg_get_value(globals, "rules");
 char * buffer;
 int finished = 0;
 struct sockaddr_in * soca;
 
 buffer = emalloc(4096); 
 while(!finished)
 {
  auth_gets(globals, buffer, 4095);
  if( buffer[0] == '\0' )
    {
      log_write("Empty buffer - exiting\n");
      EXIT(0);
    }

  if( strstr(buffer, "<|> CLIENT") != NULL )
	finished = 1;
  else 
  {
#ifdef DEBUG_RULES
    printf("User adds %s\n", buffer);
#endif
    users_add_rule(user_rules, buffer);
  }
 }
 efree(&buffer);
 rules_add(&rules, &user_rules, arg_get_value(globals, "user"));
 rules_free(user_rules);
 soca = arg_get_value(globals, "client_address");
 rules_set_client_ip(rules, soca->sin_addr);
 arg_set_value(globals, "rules", -1, rules);
 return(0);
}

void 
ntp_11_show_end(globals, name, internal)
 struct arglist*  globals;
 char * name;
 int internal;
{ 
 int soc = (int)arg_get_value( globals, "global_socket");
 char buf[1024];
 snprintf(buf, sizeof(buf), "SERVER <|> FINISHED <|> %s <|> SERVER\n", name);
 if ( internal )
 	internal_send(soc, buf, INTERNAL_COMM_MSG_TYPE_DATA);
 else
	auth_printf(globals, "%s", buf);
}


static void
files_add_translation(globals, remotename, localname)
 struct arglist * globals;
 char * remotename;
 char * localname;
{
 harglst * trans = arg_get_value(globals, "files_translation");
#if 0
 fprintf(stderr, "files_add_translation: R=%s\tL=%s\n", remotename, localname);
#endif
 if( trans == NULL )
 {
  trans = harg_create(10);
  arg_add_value(globals, "files_translation", ARG_PTR, -1, trans);
 }
 
 if( harg_get_string(trans, remotename) == NULL )
 	harg_add_string(trans, remotename, localname);
 else
 	harg_set_string(trans, remotename, localname);
}



int
ntp_11_recv_file(globals)
 struct arglist * globals;
{
 int soc = (int)arg_get_value(globals, "global_socket");
 char input[4096];
 char * origname, * localname = temp_file_name();
 int n;
 long bytes = 0;
 long tot = 0;
 int fd;
 
#if 0
 fprintf(stderr, "ntp_11_recv_file\n");
#endif
 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)
  return -1;
  
 if( strncmp(input, "name: ", strlen("name: ")) == 0 )
 {
  origname = estrdup(input + sizeof("name: ")-1);
  if(origname[strlen(origname) - 1] == '\n')
   origname[strlen(origname) - 1] = '\0';
 }
 else 
   return -1;
 
 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)
  return -1;
 /* XXX content: message. Ignored for the moment */
 
 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)

  return -1;
  
 if( strncmp(input, "bytes: ", sizeof("bytes: ")-1) == 0 )
 {
  char * t = input + sizeof("bytes: ")-1;
  bytes = atol(t);
 }
 else 
  return -1;
  
 /*
  * Ok. We now know that we have to read <bytes> bytes from the
  * remote socket.
  */
  
  fd = open(localname, O_CREAT|O_WRONLY|O_TRUNC, 0600);
  if(fd < 0)
  {
   perror("ntp_11_recv_file: open() ");
   return -1;
  }
#if 0
  fprintf(stderr, "ntp_11_recv_file: localname=%s\n", localname);
#endif  
  while(tot < bytes)
  {
   bzero(input, sizeof(input));
   n = nrecv(soc, input, MIN(sizeof(input)-1, bytes - tot), 0);
   if(n  < 0)
   {
     char	s[80];
     sprintf(s, "11_recv_file: nrecv(%d)", soc);
    perror(s);
    break;
   }
   else
   {
    write(fd, input, n);
    tot += n;
   }
  }
  /*
   * Add the fact that what the remote client calls
   * <filename> is actually <localname> here
   */
  auth_printf(globals, "SERVER <|> FILE_ACCEPTED <|> SERVER\n"); 
  files_add_translation(globals, origname, localname);
  efree(&localname);
  close(fd);
  return 0;
}
#ifdef ENABLE_SAVE_TESTS
static char*
extract_session_key_from_session_msg(globals, orig)
 struct arglist * globals;
 char * orig;
{
 char * t;
 int i, len;

 t = strrchr(orig, '<');
 if(!t)return NULL;
 t[0] = 0;
 
 t = strrchr(orig, '>');
 if(!t)return NULL;

 t++;
 while(t[0]==' ')t++;
 len = strlen(t);
 while(t[len-1]==' ')
  {
 	t[len-1]= '\0';
	len --;
  } 
 /*
  * Sanity check. All sessions name are under the form
  * <year><month><day>-<hour><minute><second>
  * (ie: 20000718-124427). If we see something else, then
  * our current user is trying to do something evil. or something.
  */
 for(i=0;i<len;i++)
  if(!isdigit(t[i]) && t[i]!='-'){
  	log_write("user %s : supplied an incorrect session name (%s)",
			(char*)arg_get_value(globals, "user"),
			t);
  	return NULL;
	}
 return strdup(t);
 
}

static int
ntp_11_delete_session(globals, orig)
 struct arglist * globals;
 char * orig;
{
 char * session = NULL;
 int ret;
 
 session = extract_session_key_from_session_msg(globals, orig);
 if(!session)return -1;
  
 ret = save_tests_delete(globals, session);
 efree(&session);

 return ret;
}


static int
ntp_11_restore_session(globals, orig)
 struct arglist * globals;
 char * orig;
{
 char * session;
 
 session = extract_session_key_from_session_msg(globals, orig);
 if(!session)return -1;
 
 save_tests_setup_playback(globals, session);
 efree(&session);
 return 0;
}

static int 
ntp_11_list_sessions(globals)
 struct arglist * globals;
{
 auth_printf(globals, "SERVER <|> SESSIONS_LIST\n");
 save_tests_send_list(globals);
 auth_printf(globals, "<|> SERVER\n");
 return 0;
}

#endif /* ENABLE_SAVE_TESTS */


/*----------------------------------------------------------

   Communication protocol: timestamps
 
 ----------------------------------------------------------*/


static int
__ntp_1x_timestamp_scan(globals, msg)
 struct arglist * globals;
 char * msg;
{
  char timestr[1024];
  char * tmp;
  time_t t;
  int len;
  
  t = time(NULL);
  tmp = ctime(&t);
  timestr[sizeof ( timestr ) - 1 ] = '\0';
  strncpy(timestr, tmp, sizeof(timestr) - 1);
  len = strlen(timestr);
  if( timestr[len - 1 ] == '\n' )
	   timestr[len - 1 ] = '\0';

  auth_printf(globals, "SERVER <|> TIME <|> %s <|> %s <|> SERVER\n",msg, timestr);
  return 0;
}


static int
__ntp_1x_timestamp_scan_host(globals, msg, host)
 struct arglist * globals;
 char * msg;
 char * host;
{
  char timestr[1024];
  char * tmp;
  time_t t;
  int len;
  char buf[1024];
  int soc;
  
  t = time(NULL);
  tmp = ctime(&t);
  timestr [ sizeof(timestr) - 1] = '\0';
  strncpy(timestr, tmp, sizeof(timestr) - 1);
  len = strlen(timestr);
  if( timestr[len - 1 ] == '\n' )
	   timestr[len - 1 ] = '\0';

   soc = (int)arg_get_value(globals, "global_socket");
   
   snprintf(buf, sizeof(buf), "SERVER <|> TIME <|> %s <|> %s <|> %s <|> SERVER\n", msg, host, timestr);
   
   internal_send(soc, buf, INTERNAL_COMM_MSG_TYPE_DATA); 

  return 0;
}



int
ntp_1x_timestamp_scan_starts(globals)
 struct arglist * globals;
{
 return __ntp_1x_timestamp_scan(globals, "SCAN_START");
}

int
ntp_1x_timestamp_scan_ends(globals)
 struct arglist * globals;
{
 return __ntp_1x_timestamp_scan(globals, "SCAN_END");
}

int
ntp_1x_timestamp_host_scan_starts(globals, host)
 struct arglist * globals;
 char * host;
{
 return __ntp_1x_timestamp_scan_host(globals, "HOST_START", host);
}
 

int
ntp_1x_timestamp_host_scan_ends(globals, host)
	struct arglist * globals;
	char * host;
{
 return __ntp_1x_timestamp_scan_host(globals, "HOST_END", host);
}

int
ntp_1x_timestamp_host_scan_interrupted(globals, host)
	struct arglist * globals;
	char * host;
{
 return __ntp_1x_timestamp_scan_host(globals, "HOST_INTERRUPTED", host);
}





/*--------------------------------------------------------------------------------------------*/
static int qsort_cmp( const void * a, const void * b )
{
 struct arglist ** plugin_a, ** plugin_b;

 plugin_a = (struct arglist ** ) a;
 plugin_b = (struct arglist ** ) b;

 return strcmp((*plugin_a)->name, (*plugin_b)->name);
}


static char * _find_plugin(struct arglist ** array, char * fname, int start, int end, int rend )
{
 int mid;
 struct arglist * plugin;
 int e;

 if ( start >= rend )
	return NULL;

 if ( start == end )
 {
  plugin = array[start];
 
  if ( strcmp(fname, plugin->name) == 0 )
	return plug_get_name(plugin->value);
   else
	return NULL;
 }

 mid = ( start + end ) / 2;
 plugin = array[mid];
 e = strcmp( plugin->name, fname );
 if ( e > 0 )
	return _find_plugin(array, fname, start, mid, rend);
  else if ( e < 0 )
	return _find_plugin(array, fname, mid + 1, end, rend);
 else
	return plug_get_name(plugin->value);
}



static char * find_plugin(struct arglist ** array, char * fname, int num_plugins )
{
 return _find_plugin ( array, fname, 0, num_plugins, num_plugins);
}


int 
ntp_1x_send_dependencies(globals)
 	struct arglist * globals;
{
 struct arglist * p = arg_get_value(globals, "plugins");
 struct arglist * plugins = p;
 struct arglist ** array;
 int num_plugins = 0;
 char * buf;
 int buf_size = 1024;
 int i = 0;


 if(plugins == NULL)
 {
  fprintf(stderr, "%s:%d: no plugins\n", __FILE__, __LINE__);
  return -1;
 }
 
 while ( p->next != NULL ) 
 {
   num_plugins ++;
   p = p->next;
 }

 /* Store the plugins in an array index by filename */
 array = emalloc ( num_plugins * sizeof(struct arglist * ));
 p = plugins;
 while ( p->next != NULL )
 {
   array[i++] = p;
   p = p->next;
 }

 qsort ( array, num_plugins, sizeof(struct arglist *), qsort_cmp);
 
 auth_printf(globals, "SERVER <|> PLUGINS_DEPENDENCIES\n");
  
 buf = emalloc(buf_size);
 
 while(plugins->next)
 {
  struct arglist * args = plugins->value;
  struct arglist * d, * deps;
  if(!args)
	goto nxt;
  
  d = deps = plug_get_deps(args);
  if(deps == NULL )
    goto nxt;
	
 
  strncat(buf, plug_get_name(args), buf_size);
  strncat(buf, " <|> ", buf_size);
  while(deps->next)
  {
   char * fname = find_plugin(array, deps->name, num_plugins);
   if( fname == NULL )
   {
    deps = deps->next;
    continue;
   }
   if(strlen(fname) + strlen(buf) + 6 > buf_size)
   {
    buf_size *= 2;
    if(strlen(fname) + strlen(buf) + 6 > buf_size)
    	buf_size = strlen(fname) + strlen(buf) + 6;

    buf = erealloc(buf, buf_size);
   }
   strncat(buf, fname, buf_size);
   strncat(buf, " <|> ", buf_size);
   deps = deps->next;
  }
#if 0
  arg_free_all(d);
#endif
  
  auth_printf(globals, "%s\n", buf);
   
  nxt: 
  	bzero(buf, buf_size);
  	plugins = plugins->next;
 }
 auth_printf(globals, "<|> SERVER\n");
 efree(&buf);
 efree(&array);
 return 0;
}
