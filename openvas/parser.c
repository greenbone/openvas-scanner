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
#include "parser.h"
#include "auth.h"
#include "error_dialog.h"
#include "monitor_dialog.h"
#include "backend.h"
#include "globals.h"

/*
 * nessusd does not convert the subnet by itself, so we create
 * this record on this fly
 */
 
static int 
is_mac_addr(host)
 char * host;
{
 int i;
 if(strlen(host) == 17) /* 12 numbers + 5 */
 {
  for(i=0;i<6;i++, host+=3)
  { 
   int j;
   for(j=0;j<2;j++)
   {
    if(!((host[j] >= '0' && host[j] <= '9') ||
       (host[j] >= 'a' && host[j] <= 'f')))
        return 0;
   }
   host+=3;
  }
 }
 else return 0;
 
 return 1;
}

static char *
__host2subnet(host)
 char * host;
{
 static char subnet[1024];
 struct in_addr ia;
 int mac = 0;
 
 subnet[0] = '\0';
 
 if((inet_aton(host, &ia) == 0) &&
    (!(mac = is_mac_addr(host))))
 {
  char * t;
  /*
   * Not an IP nor a MAC addr
   */
  t = strchr(host, '.');
  if(t)
	++t;
  else
	t = host;
   strncpy(subnet, t, sizeof(subnet) - 1);
 }
 else
 {
   if(mac)
   {
    /*
     * This is a MAC address. In that case, the 'subnet'
     * are the first three bytes (manufacturer id)
     */
    char * t = strchr(host,'.');
    int i;
    for(i=0;i<2;i++)
        {
	if(!t)break;
    	t = strchr(t+1, '.');
       }
    if(t)
    {
     t[0] = '\0';
     strncpy(subnet, host, sizeof(subnet) - 1);
     t[0] = '.';
    }  
    else strncpy(subnet, host, sizeof(subnet) - 1);
   }
   else
   {
     /* this is an IP */
     char * t = strrchr(host, '.');
     if(t)t[0] = '\0';
     strncpy(subnet, host, sizeof(subnet) - 1);
     if(t)t[0] = '.';
  }
 }
 return subnet;
}


/*
 * parse_message_type
 *
 * This functions performs the conversion
 * char * --> type
 */
int 
parse_message_type(type)
	char * type;
{
#ifdef DEBUGMORE
 fprintf(stderr, "%s:%d type : %s\n", __FILE__, __LINE__, type);
#endif
 if(!strcmp(MSG_HOLE_STR, type))return(MSG_HOLE);
 if(!strcmp(MSG_INFO_STR, type))return(MSG_INFO);
 if(!strcmp(MSG_NOTE_STR, type))return(MSG_NOTE);
 if(!strcmp(MSG_TIME_STR, type))return(MSG_TIME);
 if(!strcmp(MSG_STAT_STR, type))return(MSG_STAT);
 if(!strcmp(MSG_PORT_STR, type))return(MSG_PORT);
 if(!strcmp(MSG_ERROR_STR, type))return(MSG_ERROR);
 if(!strcmp(MSG_PING_STR, type))return(MSG_PING);
 if(!strcmp(MSG_PLUGINS_ORDER_STR, type))return(MSG_PLUGINS_ORDER);
 if(!strcmp(MSG_FINISHED_STR, type))return(MSG_FINISHED);
 if(!strcmp(MSG_BYE_STR, type))return(MSG_BYE);
 return(-1);
}

/*
 * parse_server_message
 *
 * This function analyzes a message received
 * from the server, and performs what must
 * must be done depending on the server message
 */
int 
parse_server_message(message, backend, humanmsg)
	char * message;
	int backend;
	char * humanmsg;
{
 char message_type[255];
 char * buf;
 char * t;
 int type;
 
 if(!strncmp(message, "s:", 2))
  return MSG_STAT2;
 else
  {
  t = strstr(message, "SERVER <|> ");
  if(!t)return(-1);
  buf = strstr(message, "<|>");
  buf+=4;
  t = strstr(buf, " <|>");
  if(t)
  {
  t[0]=0;
  }
 strncpy(message_type,buf, sizeof(message_type) - 1);
 if(t)t[0]=' ';
 type = parse_message_type(message_type);
 }
 
 switch(type)
 {
  case MSG_TIME:
   {
	char * msg = parse_separator(t);
	int type = 0;
	int len = 0;
#define TIMER_HOST_START		1
#define TIMER_HOST_END			2
#define TIMER_SCAN_START		3
#define TIMER_SCAN_END			4

	
	
	if(!strcmp(msg, "HOST_START")){
			len = strlen(msg);
			type = TIMER_HOST_START;
			}
	else if(!strcmp(msg, "HOST_END")){
			type = TIMER_HOST_END;
			len = strlen(msg);
			}

	if(type)
	{
	 char * host = parse_separator(t+len+3);
	 char * date = t+strlen(" <|> ")+len+strlen(host)+10;
	 char* e;

         e = strrchr(t, '<');
         if(e != NULL)
         {
               e--;e[0] = '\0';
         }


	 switch(type)
	 {
	  case TIMER_HOST_START:
	  	backend_insert_timestamps(backend, host, "host_start", date); 
		break;
	  case TIMER_HOST_END:
	  	backend_insert_timestamps(backend, host, "host_end", date); 
		break;  	
	 }
	}
	
	else
	{
	 if(!strcmp(msg, "SCAN_START")) {
		type = TIMER_SCAN_START;
		len = strlen(msg);
		}
	 else if(!strcmp(msg, "SCAN_END"))
	 	{
		type = TIMER_SCAN_END;
		len = strlen(msg);
		}
	
	 if(type)
	 {
	  char* date = &t[5+len+strlen(" <|> ")];
	  char* e;
	  
	  e = strrchr(t, '<');
	  if(e != NULL) 
	  	{
		e--;e[0] = '\0';
		}
	  switch(type)
	  {
	    case TIMER_SCAN_START:
	   	backend_insert_timestamps(backend, "", "scan_start", date);
		break;
	   case TIMER_SCAN_END:
	   	backend_insert_timestamps(backend, "", "scan_end", date);
		break;
	   }
	  }
	}
	
	efree(&msg);
	}
	break;
	
  case MSG_STAT2 :
  	return(MSG_STAT2);
	break;
  case MSG_ERROR :
        {
        if(!F_quiet_mode)
          {
           char * msg = parse_separator(t);
#ifdef USE_GTK
	   char * t;
	   while((t = strchr(msg, ';')))t[0]='\n';
           show_error(msg);
#endif
	   efree(&msg);
  	   return(MSG_ERROR);
  	  }
  	break;
  	}
  case MSG_PORT :
  	parse_host_add_port(backend, t, humanmsg);
  	return(MSG_PORT);
  	break;
  case MSG_HOLE :
     	humanmsg[0]=0;
  	parse_host_add_data(backend, t, MSG_HOLE);
  	return(MSG_HOLE);
  	break;
  case MSG_INFO :
  	humanmsg[0]=0;
  	parse_host_add_data(backend, t, MSG_INFO);
  	break;
  case MSG_NOTE :
  	humanmsg[0]=0;
  	parse_host_add_data(backend, t, MSG_NOTE);
  	break;
  case MSG_STAT :
	{
	int tl = strlen(message_type);
	int l = strlen(buf + tl);
  	strncpy(humanmsg, buf+tl, l);
	humanmsg[l] = '\0';
  	return(MSG_STAT);
  	break;
	}
  case MSG_FINISHED :
        {
	 if(!F_quiet_mode)
	 {
	 char * v = strstr(t, " <|> SERVER");
         int t_len;
	 if(v)v[0]=0;
	 else return 0;
	 v = strstr(t, " <|> ");
	 if(v)t = v+strlen(" <|> ");
	 t_len = strlen(t);
	 strncpy(humanmsg, t, t_len);
         humanmsg[t_len] = '\0';
	 return MSG_FINISHED;
	 }
	break;	
	 }
  case MSG_PING :
  	humanmsg[0]=0;
  	network_printf("CLIENT <|> PONG <|> PING <|> CLIENT\n\n");
  	return MSG_PING;
  	break;
  case MSG_PLUGINS_ORDER :
        {
        char * t = strstr(buf, " <|> SERVER");
	int tl = strlen(message_type);
	int l  = strlen(buf + tl);
        if(t)t[0]=0;
        strncpy(humanmsg, buf+tl+5, l);
	humanmsg[l] = '\0';
        return(MSG_PLUGINS_ORDER);
        }
        break;
  case MSG_BYE :
        humanmsg[0]=0;
  	return(MSG_BYE);
  	break;
  }
 return(-1);
}

/*
 * The server has sent a STATUS message.
 *
 */
void 
parse_nessusd_status(servmsg, host, action, current, max)
	char * servmsg;
	char ** host;
        char ** action;
	char ** current;
	int * max;
{
	char * t1,*t2;
	
	t1 = parse_separator(servmsg);if(!t1)return;
	t2 = parse_separator(servmsg+strlen(t1)+3);
	if(!t2){
		efree(&t1);
		return;
		}
		
		
	*host = emalloc(strlen(t1) + 1);
	strncpy(*host, t1, strlen(t1));
	
	*action = emalloc(strlen(t2) + 1);
        strncpy(*action, t2, strlen(t2));
        

	efree(&t2);
        t2 = parse_separator(servmsg+strlen(t1)+3);
	efree(&t1);
	if(!t2)
	 return;
	 
	t1 = strchr(t2, '/');
	if(t1)
	{
	t1[0]=0;
	}
	*current = strdup(t2);
	
	if(t1)
	{
	t1+=sizeof(char);
	*max = atoi(t1);
	}
	efree(&t1);
	efree(&t2);
}

void
parse_nessusd_short_status(msg, host, action, current, max)
	char * msg;
	char ** host;
	char ** action;
	char ** current;
	int * max;
{
 char * t;
 static char portscan[] = "portscan";
 static char attack[]   = "attack";
  /* the short status is : action:hostname:current:max */
  if(msg[0]=='p')
   *action = strdup(portscan);
  else
   *action  = strdup(attack);
  
  msg = msg + 2; 
  t = strchr(msg, ':');
  if(!t)
   return; 
  t[0] = 0;
  *host = strdup(msg);
  
  msg = t + sizeof(char);
  t = strchr(msg, ':');
  
  if(!t)
   return;
  t[0]=0;
  *current = strdup(msg);
  msg = t + sizeof(char);
  *max = atoi(msg);
}

/*
 * The server has sent a PORT message
 *
 */
void 
parse_host_add_port(backend, servmsg, humanmsg)
	int backend;
	char * servmsg;
	char * humanmsg;
{
 char * port;
 char * hostname;
 char * subnet;

 
 hostname = parse_separator(servmsg);if(!hostname)return;
 port = parse_separator(servmsg+strlen(hostname)+3);
 if(!port){efree(&hostname); return;}
 subnet = __host2subnet(hostname);
  backend_insert_report_port(backend, subnet, hostname, port);
#ifdef DEBUGMORE
  fprintf(stderr, "Port %s opened on %s\n", port, hostname);
#endif

  sprintf(humanmsg, "Port %s opened on %s", port, hostname);
  efree(&hostname);
  efree(&port);
}

/* 
 * The server has sent a HOLE or INFOS or NOTE message
 */
void 
parse_host_add_data(backend, servmsg, type)
	int backend;
	char * servmsg;
	int type;
{
 char * port;
 char * data;
 char * hostname;
 char * subnet;
 char * msgt;
 char* script_id;
 char * old;
 
  switch(type)
  {
   case MSG_HOLE :
   msgt = "Security Hole";
   break;
   case MSG_INFO :
   msgt = "Security Warning";
   break;
   case MSG_NOTE :
   msgt = "Security Note";
   break;
   default :
   fprintf(stderr, "received unknown message type (%d)\n", type);
	return;
  }

 hostname = parse_separator(servmsg);
 if(!hostname){
	return;
	}
 old = servmsg + strlen(hostname) + 5;
 port = parse_separator(old);
 if(!port){
	efree(&hostname);
	return;
 	}
 old += strlen(port) + 5; 
 data = parse_separator(old);
 if(!data){
 	efree(&hostname);
	efree(&port);
	return;
	}
 old += strlen(data) + 5; 
 script_id = parse_separator(old); 
 if(!script_id){
 	efree(&hostname);
	efree(&port);
	efree(&data);
	return;
	}
 
 old = data;
 data = rmslashes(old);
 efree(&old);
 
#ifdef NOT_READY
   if( (type==MSG_INFO) && !strncmp(data, "Traceroute", strlen("Traceroute")))
   {
    netmap_add_data(data);
   }
#endif   
   subnet = __host2subnet(hostname);
   backend_insert_report_data(backend, subnet, hostname, port, script_id,
		msgt, data);
 
#ifdef DEBUGMORE
  fprintf(stderr,"data for %s (port %d) [type : %d] : \n%s\n", hostname, port, type,data);
#endif
 
  efree(&script_id);
  efree(&hostname);
  efree(&port);
  efree(&data);
}
 

/* 
 * This function extracts the string after the 
 * ' <|> ' symbol.
 *
 */
char * 
parse_symbol(str)
	char * str;
{
 char * s = str;
 
 while(s)
 {
 s = strchr(s, '|');
 if(!s)return(NULL);
 if((s[1]=='>')&&(s-1)[0]=='<')
 	{
 	return s+3;
 	}
 s++;
 }
 return NULL;
}

char * 
parse_separator(str)
	char * str;
{
 char * s_1, *s_2;
 char * ret;
 
 s_1 = parse_symbol(str);
 if(nulstr(s_1))
   return NULL;
   
 s_2 = parse_symbol(s_1);
 if(!s_2)
  {
  ret = emalloc(strlen(s_1));
  strncpy(ret, s_1, strlen(s_1)-1);
  }
 else
 {
  int c;
  
  s_2 = s_2 - 4;
  c = s_2[0];
  s_2[0] = 0;
  ret = emalloc(strlen(s_1));
  strncpy(ret, s_1, strlen(s_1)-1);
  s_2[0]=c;
  }
  return ret;
}

