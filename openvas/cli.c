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
 * cli.c - Command Line Interface manager
 * 
 * modified by Axel Nennker <axel@nennker.de> 20020418 
 *	do not need gtk here
 *	removed gcc -Wall complaints, NULL pointer checks
 *
 */
 
#include <includes.h>
#include "globals.h"

#include "nessus.h"
#include "parser.h"
#include "cli.h"

#undef USE_GTK
#include "read_target_file.h"
#include "nsr_output.h"
#include "nbe_output.h"
#include "text_output.h"
#include "latex_output.h"
#include "xml_output_ng.h"
#include "xml_output.h"
#include "html_output.h"
#include "html_graph_output.h"
#include "attack.h"
#include "auth.h"
#include "comm.h"
#include "backend.h"


static struct cli_args * g_cli = NULL;
/*---------------------------------------------------
   Private functions
-----------------------------------------------------*/

static int 
is_server_present(soc)
	int soc;
{
	fd_set  rd;
	struct timeval tv = {2,0};
	int fd = nessus_get_socket_from_connection(soc);

	FD_ZERO(&rd);
	FD_SET(fd, &rd);
	if(select(fd+1, &rd, NULL, NULL, &tv) > 0)
	{
		int len = -1;
		ioctl(fd, FIONREAD, &len);
		if(!len){
			fprintf(stderr, "Communication closed by server\n");
			return 0;
			}
	}
	return 1;
}



static harglst* build_plugins_order_table(order)
 char * order;
{
 int num = 0;
 char * t;
 int i = 0;
 int * plugins_order_table_int;
 harglst * plugins_order_table = harg_create(4000);


 t = order;

 
 while((t = strchr(t+1, ';')))num++;
 plugins_order_table_int = emalloc((num+1)*sizeof(int));
 t = order;
 if(num)
 while(t)
 {
  char * next = strchr(t, ';');
  if(next)next[0]=0;
  plugins_order_table_int[i++] = atoi(t);
  if(next)next[0]=';';
  t = next+1;
  next = strchr(next+1, ';');
  if(!next)t = NULL;
 }
 
 /*
  * Now, create the names table
  */
  plugins_order_table = harg_create(num*3 + 1);
  
  for(i=0;i<num;i++)
  {
   struct arglist * plugs = Plugins;
   
   while(plugs && plugs->next && 
        ((int)(arg_get_value(plugs->value, "ID"))!=plugins_order_table_int[i]))
         plugs = plugs->next;
   if(!(plugs && plugs->next))
   {
    plugs = Scanners;
    while(plugs && plugs->next && 
        ((int)(arg_get_value(plugs->value, "ID"))!=plugins_order_table_int[i]))
         plugs = plugs->next;
   }
   if(plugs){
   	char * id = emalloc(20);
	sprintf(id, "%d", i+1);
   	harg_add_string(plugins_order_table, id, plugs->name);
	efree(&id);
	}
  }
  efree(&plugins_order_table_int);
  return plugins_order_table;
}



void 
cli_sigterm(s)
 int s;
{
 cli_report(g_cli);
 exit(5);
}
/*
 * Monitor the test - read data from the client, and process it
 */
static void
cli_test_monitor(cli)
 struct cli_args * cli;
{
 int type, finished = 0;
 static char buf [16384], msg [16384];
 int backend = backend_init(NULL);
   
 signal(SIGTERM, cli_sigterm);
 g_cli = cli;  
 cli->backend = backend; 
      
  while(!finished)
   {
       /* I don't think buf[0] == 0 is a case that will happen, but just 
        * to be safe, as it was the previous semantics
        */
    if(network_gets(buf, sizeof(buf) - 1) < 0 || buf[0] == '\0')
    { 
       if(!is_server_present(GlobalSocket))
       {
       fprintf(stderr, "nessus: nessusd abruptly shut the communication down - the test may be incomplete\n");
       finished = 1;
       }
       continue;
   }
   buf[strlen(buf)-1]=0;
   if((type = parse_server_message(buf, backend, msg))==MSG_BYE)
	   finished = 1;
   if(cli->verbose)
   {
	   switch(type)
	   {
		   case MSG_STAT2:
			   {
			   char * hostname;
			   char * action;
			   char * current;
			   int max;
			   char * plug = NULL;
			  
			   parse_nessusd_short_status(&(buf[2]), &hostname, &action, &current, &max);
			   if(cli->plugins_order_table)
			   {
			    plug = harg_get_string(cli->plugins_order_table, current);
			   }
			   
			   if(!strcmp(action, "portscan"))plug="";
			   printf("%s|%s|%s|%d\n", action,hostname,current,max); 
			   efree(&hostname);
			   efree(&action);	   
			   efree(&current);
			   }
			   break;
	           case MSG_STAT:
			   {
			   char * hostname;
			   char * action;
			   char* current;
			   int max;

			   parse_nessusd_status(buf, &hostname, &action, &current, &max);
			   printf("%s|%s|%s|%d|foo\n", action,hostname,current,max); 
			   efree(&hostname);
			   efree(&action);	   
			   efree(&current);
			   }
			   break;
		   case MSG_PLUGINS_ORDER:
		   	   cli->plugins_order_table = build_plugins_order_table(msg);
			   break;
		   case MSG_FINISHED:
			   printf("finished|%s||||\n", msg);
			   break;
	   }		   
		 			   
   }
   fflush(stdout);
   bzero(msg, sizeof(msg));
  }
}


/*---------------------------------------------------
   CLI arguments management
 ----------------------------------------------------*/
struct cli_args * 
cli_args_new()
{
 return emalloc(sizeof(struct cli_args));
}

void
cli_args_server(args, server)
 struct cli_args * args;
 char * server;
{
 if(args->server)free(args->server);
 args->server = strdup(server);
}

void
cli_args_port(args, port)
 struct cli_args * args;
 int port;
{
 args->port = port;
}

void
cli_args_login(args, login)
struct cli_args * args;
 char * login;
{
 if(args->login)free(args->login);
 args->login = strdup(login);
}


void
cli_args_password(args, pwd)
 struct cli_args * args;
 char * pwd;
{
 if(args->password)free(args->password);
 args->password = strdup(pwd);
}


void 
cli_args_target(args, target)
 struct cli_args * args;
 char * target;
{
 if(args->target)free(args->target);
 args->target = strdup(target);
}

void 
cli_args_results(args, results)
 struct cli_args * args;
 char * results;
{
 char* ftype;
 
 if(args->results)free(args->results);
 args->results = strdup(results);
 if(args->extension)free(args->extension);
 /* choose output file type based on fname */
 ftype = strrchr(args->results, '.');
 if(!ftype)
 {
   if(args->results[strlen(args->results)-1]=='/')
    {
      args->results[strlen(args->results)-1]=0;
      ftype = "html_pie";
    }
   else
     ftype = "nsr";
  }
  else 
   ftype++;
    
 args->extension = strdup(ftype);
}

void 
cli_args_cipher(args, cipher)
 struct cli_args * args;
 char * cipher;
{
 if(args->cipher)free(args->cipher);
 args->cipher = strdup(cipher);
}



void 
cli_args_verbose(args, verbose)
 struct cli_args * args;
 int verbose;
{ 
 args->verbose = verbose;
}
void
cli_args_auth_pwd(args, auth_pwd)
 struct cli_args * args;
 cli_auth_pwd_t  auth_pwd;
{
 args->auth_pwd = auth_pwd;
}


void
cli_args_output(args, type)
 struct cli_args * args;
 char * type;
{
 char * ftype = args->extension;

 
 
 
 if(type)ftype = type;

 if(!ftype)
  {
    args->output = (output_func_t)backend_to_nbe;
    args->backend_output_func = 1;
    return;
  }

#ifndef _NO_PIES
 if(!strncmp(ftype, "html_pie", 8)||
     !strncmp(ftype, "html_graph", 10)) {
    args->output = arglist_to_html_graph;
    }
     else 
#endif /* _NO_PIES */
     if (!strncmp(ftype, "html", 4)) {
	args->output = arglist_to_html;
     } else if (!strcmp(ftype, "latex") ||
    	        !strcmp(ftype, "tex")) {
	args->output = arglist_to_latex;
     } else if(!strcmp(ftype, "txt")||
    	      !strcmp(ftype, "text"))  {
    	args->output = arglist_to_text;
     } 
     else if(!strcmp(ftype, "nsr"))
     {	    
    	args->output = (output_func_t)backend_to_nsr;
	args->backend_output_func = 1;
     }
     else if(!strcmp(ftype, "nbe"))
     {	    
    	args->output = (output_func_t)backend_to_nbe;
	args->backend_output_func = 1;
     }
     else if(!strcmp(ftype, "old-xml"))
     {
       args->output = (output_func_t)arglist_to_xml;
     }
     else if(!strcmp(ftype, "xml"))
     {	    
    	args->output = (output_func_t)backend_to_xml_ng;
	args->backend_output_func = 1;
     }
     else {
	     fprintf(stderr, "'%s' is not a valid report type\n", ftype);
	     exit(1);
     }
}
/*---------------------------------------------------------
 * Auditing now
 *--------------------------------------------------------*/
 
int cli_connect_to_nessusd(cli)
 struct cli_args * cli;
{
 /*ENABLE_CRYPTO_LAYER*/
 char * pwd = cli->password;
 char * err;
 err = connect_to_nessusd(cli->server,
 				 cli->port,
				 cli->login,
				 pwd);
 
 if(err)
  {
  fprintf(stderr, "nessus : %s\n", err);
  return -1;
 }
 
 return 0;
}

int cli_test_network(cli)
 struct cli_args * cli;
{
    /* If we fail to turn the target file into a list then
     * We should _NOT_ try to attack anything */
  char * target_list = target_file_to_list(cli->target);
  if (target_list == NULL) {
      /* report the error */
      fprintf(stderr, "nessus : error turning targetfile (%s) to list\n", cli->target);
      return -1;
  }

  attack_host(target_list, Prefs);
  cli_test_monitor(cli);
  return 0 ;
}

void
cli_report(cli)
 struct cli_args * cli;
{
 if(!cli->backend_output_func)
    cli->output(backend_convert(cli->backend), cli->results);
 else
    cli->output((struct arglist*)cli->backend, cli->results);
}


static char* 
sql_addslashes(in)
 char *in;
{
 char * ret;
 char * out = malloc(strlen(in) * 2 + 1);
 bzero(out, strlen(in) * 2 + 1);
 ret = out;
 while(in[0])
 {
  if(in[0] == '\\')
  {
   out[0] = '\\'; out++;
   out[0] = '\\'; out++;
  }

  else if(in[0] == '\n')
  {
   out[0] = '\\'; out++;
   out[0] = 'n'; out++;
  }
  else if(in[0] == '\r')
  {
    out[0] = '\\'; out++;
    out[0] = 'r';  out++;
  }
  else if(in[0] == '\'')
  {
    out[0] = '\\'; out++;
    out[0] = '\'';  out++;
  }
  else {
	  out[0] = in[0];
	  out++;
  }
  in++;
 }
 return realloc(ret, strlen(ret) + 1);
}
static void 
_cli_sql_dump_plugins(p)
 struct arglist * p;
{
 if(p && p->next)
 {
 char * m;
 struct arglist *q = p->value;
 printf("INSERT INTO plugins VALUES ('%d', ", (int)arg_get_value(q, "ID"));


 m = arg_get_value(q, "NAME");
 m = sql_addslashes(m);
 printf("'%s', ", m);
 efree(&m);
 
 m = arg_get_value(q, "FAMILY");
 m = sql_addslashes(m); 
 printf("'%s', ", m);
 efree(&m);
 
 
  m = arg_get_value(q, "CATEGORY");
 m = sql_addslashes(m); 
 printf("'%s', ", m);
 efree(&m);
 
 m = arg_get_value(q, "COPYRIGHT");
 m = sql_addslashes(m);
 printf("'%s', ", m);
 efree(&m);
 
 m = arg_get_value(q, "SUMMARY");
 m = sql_addslashes(m);
 printf("'%s', ", m);
 efree(&m);
 
 m = arg_get_value(q, "DESCRIPTION");
 m = sql_addslashes(m);
 printf("'%s',", m);
 efree(&m);
 
 m=  arg_get_value(q, "VERSION");
 m = sql_addslashes(m);
 printf("'%s',", m);
 efree(&m);
 
 
 m=  arg_get_value(q, "CVE_ID");
 if( m != NULL )
 {
  m = sql_addslashes(m);
  printf("'%s',", m);
  efree(&m);
 }
 else printf("'',");
 
 
 m =  arg_get_value(q, "BUGTRAQ_ID");
 if(m != NULL)
  {
  m = sql_addslashes(m);
  printf("'%s',", m);
  efree(&m);
  }
 else printf("'',");
 
  m =  arg_get_value(q, "XREFS");
 if(m != NULL)
  {
  m = sql_addslashes(m);
  printf("'%s');\n", m);
  efree(&m);
  }
 else printf("'');\n");
 
 
  _cli_sql_dump_plugins(p->next);
 }
}
static void
_cli_dump_plugins(plugins)
 struct arglist * plugins;
{
 if(!plugins)
  return;
 while(plugins->next)
 {
  char * var = arg_get_value(plugins->value, "ASC_ID");
  printf("%s|", var);
  var = addslashes(arg_get_value(plugins->value, "FAMILY"));
  printf("%s|", var);
  efree(&var);
  var = addslashes(arg_get_value(plugins->value, "NAME"));
  printf("%s|", var);
  efree(&var);
  var = addslashes(arg_get_value(plugins->value, "CATEGORY"));
  printf("%s|", var);
  efree(&var);
  var = addslashes(arg_get_value(plugins->value, "COPYRIGHT"));
  printf("%s|", var);
  efree(&var);  
 
  
  var = addslashes(arg_get_value(plugins->value, "SUMMARY"));
  printf("%s|", var);
  efree(&var);
  
  
  var = addslashes(arg_get_value(plugins->value, "VERSION"));
  printf("%s|", var);
  efree(&var);
  
  var = addslashes(arg_get_value(plugins->value, "CVE_ID"));
  printf("%s|", var);
  efree(&var);
  
  var = addslashes(arg_get_value(plugins->value, "BUGTRAQ_ID"));
  printf("%s|", var);
  efree(&var);
  
  var = addslashes(arg_get_value(plugins->value, "XREFS"));
  printf("%s|", var);
  efree(&var);
   
  var = addslashes(arg_get_value(plugins->value, "DESCRIPTION"));
  printf("%s\n", var);
  efree(&var);
  
  plugins = plugins->next;
 }
}


void
cli_sql_dump_plugins(cli)
 struct cli_args * cli;
{
 printf("DROP TABLE plugins;\n");
 printf("CREATE TABLE plugins (\n");
 printf(" id int NOT NULL,\n");
 printf(" name varchar(255),\n");
 printf(" family varchar(255),\n");
 printf(" category varchar(255),\n");
 printf(" copyright varchar(255),\n");
 printf(" summary varchar(255),\n");
 printf(" description blob,\n");
 printf(" version varchar(255),\n");
 printf(" cve_id varchar(255),\n");
 printf(" bugtraq_id varchar(255),\n");
 printf(" xref blob,\n");
 printf(" primary key (id));\n");
 _cli_sql_dump_plugins(Plugins);
 _cli_sql_dump_plugins(Scanners);
}


void
cli_dump_plugins(cli)
 struct cli_args * cli;
{
 _cli_dump_plugins(Plugins);
 _cli_dump_plugins(Scanners);
}


static void
_cli_dump_pprefs()
{
 struct arglist * p = arg_get_value(Prefs, "PLUGINS_PREFS");
 if(!p)
  return;
  
 while(p->next)
 {
  switch(p->type)
  {
	  case ARG_STRING:
 		 printf("%s = %s\n", p->name, (char*)p->value);
		 break;
	  case ARG_INT:
		 printf("%s = %s\n", p->name, p->value ? "yes":"no");
		 break;
	  default:
		 break;
  }
  p = p->next;
 }
}


void
cli_sql_dump_prefs(cli)
 struct cli_args * cli;
{
 cli_dump_prefs(cli);
}

void
cli_dump_prefs(cli)
 struct cli_args * cli;
{
 struct arglist * p = arg_get_value(Prefs, "SERVER_PREFS");
 if(!p)
  return;
  
 while(p->next)
 { 
  switch(p->type)
  {
   case ARG_INT :
    printf("%s = %d\n", p->name, (int)p->value);
    break;
   case ARG_STRING:
   printf("%s = %s\n", p->name, (char*)p->value);
   break;
  }
 p = p->next;	
 }
 

 if(Plugins)_cli_dump_pprefs(Plugins);
 if(Scanners)_cli_dump_pprefs(Scanners);
 
 return;
}
int 
cli_close_connection(cli)
 struct cli_args * cli;
{
 return close_stream_connection(GlobalSocket);
}

#ifdef ENABLE_SAVE_TESTS
void
cli_restore_session(cli, session)
 struct cli_args * cli;
 char * session;
{   
  restore_attack(session, Prefs);
  cli_test_monitor(cli);
}
void
cli_list_sessions(cli)
 struct cli_args * cli;
{
 hargwalk * hw;
 if(!comm_server_restores_sessions(Prefs))
  printf("** The remote nessusd server does not support session-saving\n");
 else
  {
   char * key;
   hw = harg_walk_init(Sessions);
   printf("Remote sessions :\n");
   printf("-----------------\n\n");
   printf("Session ID      | Targets\n");
   printf("==========================\n");
   while((key = (char*)harg_walk_next(hw)))
   {
    printf("%s | %s\n", key, harg_get_string(Sessions, key));
   }
  } 
}
#endif
