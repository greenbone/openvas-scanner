/* OpenVAS
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
 */


 
#include <includes.h>
#include "log.h"
#include "ntp.h"
#include "auth.h"
#include "comm.h"
#include "ntp_11.h"
#include "utils.h"
#include "preferences.h"
#include "detached.h"
#include "save_tests.h"
#include "pluginscheduler.h"



extern int g_max_hosts;
extern int g_max_checks;




/*
 * version check (for libraries)
 *
 * Returns 0  if versions are equal
 * Returns 1 if the fist version is newer than the second 
 * Return -1 if the first version is older than the second
 *
 */
int 
version_check(a,b)
 char * a, *b;
{
 int int_a, int_b;
 
 if(!a || !b) return -2; 
 
 int_a = atoi(a);
 int_b = atoi(b);
 
 if(int_a < int_b) return -1;
 if(int_a > int_b) return 1;
 else {
  char * dot_a = strchr(a, '.'), * dot_b = strchr(b, '.');
  if(dot_a && dot_b)
   return version_check(&(dot_a[1]), &(dot_b[1]));
  else 
   return -2;
 }
}


/*
 * Returns <1> if the two arglists have a name in common
 */
int
common(l1, l2)
 struct arglist * l1, *l2;
{
 if(!l1 || !l2)
  {
#ifdef DEBUG_FUNC_COMMON
   printf("common(): l1 =%d, l2 = %d\n", l1, l2);
#endif   
  return 0;
 }
 while( l1->next != NULL )
 {
  while( l2->next != NULL )
  {
   if(strcmp(l1->name, l2->name) == 0)
   	return 1;
   l2 = l2->next;
  }
  l1 = l1->next;
 }
 return 0;
}
/*
 * Converts a user comma delimited input (1,2,3) into an
 * arglist
 */
struct arglist *
list2arglist(list)
 char * list;
{
 struct arglist * ret = emalloc(sizeof(struct arglist));
 char * t = strchr(list, ',');

 if(!list)
  {
   efree(&ret);
   return ret;
  }
  
  
 while((t = strchr(list, ',')) != NULL)
 {
  t[0] = 0;
  while(list[0]==' ')list++;
  if(list[0] != '\0')
  {
   arg_add_value(ret, list, ARG_INT, 0, (void*)1);
  }
  list = t+1;
 }
 
 while(list[0]==' ')list++;
 if(list[0] != '\0')
  {
   arg_add_value(ret, list, ARG_INT, 0, (void*)1);
  }
  return ret;
}

 


/* 
 * Get the max number of hosts to test at the same time
 */
int 
get_max_hosts_number(globals, preferences)
 struct arglist * globals;
 struct arglist * preferences;
{
  int max_hosts;
  if(arg_get_value(preferences, "max_hosts"))
    {
      max_hosts = atoi(arg_get_value(preferences, "max_hosts"));
      if(max_hosts<=0)
	{
	  log_write("Error ! max_hosts = %d -- check %s\n", 
		    max_hosts, (char *)arg_get_value(preferences, "config_file"));
	  max_hosts = g_max_hosts;
	}
    else if(max_hosts > g_max_hosts && preferences_user_is_admin(globals, preferences) <= 0)
     {
     	log_write("Client tried to raise the maximum hosts number - %d. Using %d. Change 'max_hosts' in openvasd.conf if \
you believe this is incorrect\n",
			max_hosts, g_max_hosts);
	max_hosts = g_max_hosts;
     }
    }
  else max_hosts = g_max_hosts;
  return(max_hosts);
}

/* 
 * Get the max number of plugins to launch against the remote
 * host at the same time
 */
int
get_max_checks_number(globals, preferences)
 struct arglist * globals;
 struct arglist * preferences;
{
 int max_checks;
  if(arg_get_value(preferences, "max_checks"))
    {
      max_checks = atoi(arg_get_value(preferences, "max_checks"));
      if(max_checks<=0)
	{
	  log_write("Error ! max_hosts = %d -- check %s\n", 
		    max_checks, (char *)arg_get_value(preferences, "config_file"));
	  max_checks = g_max_checks;
	}
    else if(max_checks > g_max_checks && preferences_user_is_admin(globals, preferences) <= 0)
     {
     	log_write("Client tried to raise the maximum checks number - %d. Using %d. Change 'max_checks' in openvasd.conf if \
you believe this is incorrect\n",
			max_checks, g_max_checks);
	max_checks = g_max_checks;
     }
    }
  else max_checks = g_max_checks;
  return(max_checks);
}


/*
 * Returns the number of plugins that will be launched
 */
int 
get_active_plugins_number(plugins)
 struct arglist *  plugins;
{
  int num = 0;
  
  if(plugins != NULL)
   while(plugins->next != NULL)
   {
    if(plug_get_launch(plugins->value) != LAUNCH_DISABLED )num++;
    plugins = plugins->next;
   }
   
   
 return num;
}




void 
plugins_set_ntp_caps(plugins, caps)
 struct arglist * plugins;
 ntp_caps* caps;
{
 if(!caps || !plugins)return;
 while(plugins->next)
 {
  struct arglist * v;
  if( plugins->value != NULL )
   v = plugins->value;
  else 
   v = NULL;
  
  if( v != NULL ){
	struct ntp_caps * old = arg_get_value(v, "NTP_CAPS");
	if ( old != NULL )
		arg_set_value(v, "NTP_CAPS", sizeof(*caps), caps);
	else
		arg_add_value(v, "NTP_CAPS", ARG_STRUCT, sizeof(*caps), caps);
	}

  plugins = plugins->next;
 }
}



/*--------------------------------------------------------------------*/


int
is_symlink(name)
 char * name;
{
#ifndef OPENVASNT
 struct stat sb;
 if(stat(name, &sb))return(0);
 return(S_ISLNK(sb.st_mode));
#else
 return(0);
#endif
}

void check_symlink(name)
 char * name;
{
 if(is_symlink(name))
 { 
  fprintf(stderr, "The file %s is a symlink -- can't continue\n", name);
  DO_EXIT(0);
 }
}

/*
 * Converts a hostnames arglist 
 * to a space delimited lists of hosts
 * in one string
 */
char * 
hosts_arglist_to_string(hosts)
 struct arglist * hosts;
{
 int num_hosts = 0;
 struct arglist * start = hosts;
 int hosts_len = 0;
 char * ret;

 while(hosts && hosts->next){
  if(hosts->value)
  {
    num_hosts++;
    hosts_len+=strlen(hosts->value);
  }
  hosts = hosts->next;
 }       
  
 ret = emalloc(hosts_len + 2 * num_hosts + 1);
 
 hosts = start;
 
 while(hosts && hosts->next) {
  if(hosts->value){
   strcat(ret, hosts->value);
   strcat(ret, " ");
  }
  hosts = hosts->next;
 }
return(ret);
} 

/*-----------------------------------------------------------------

		pid file management
		
-------------------------------------------------------------------*/

void
create_pid_file()
{
 FILE * f;
 char * fname = malloc(strlen(OPENVASD_PIDDIR) + strlen("/openvasd.pid") + 1);
 strcpy(fname, OPENVASD_PIDDIR);
 strcat(fname, "/openvasd.pid");
 
 f = fopen(fname, "w");
 if(!f)
 {
fprintf(stderr, "'%s'\n", fname);
  perror("create_pid_file() : open ");
  return;
 }
 fprintf(f, "%d\n", getpid());
 fclose(f);
 free(fname);
}

void
delete_pid_file()
{
 char * fname = malloc(strlen(OPENVASD_PIDDIR) + strlen("/openvasd.pid") + 1);
 strcpy(fname, OPENVASD_PIDDIR);
 strcat(fname, "/openvasd.pid");
 unlink(fname);
 free(fname);
}


/*
 * Returns a name suitable for a temporary file. 
 * This function ensures that this name is not taken
 * already.
 */
char*
temp_file_name()
{
 char* ret = emalloc(strlen(OPENVASD_STATEDIR)+ strlen("tmp/") + strlen("tmp") + 40);
 int fd = - 1;
 do {
 if(fd > 0){
 	if(close(fd) < 0)
	 perror("close ");
	}
 sprintf(ret, "%s/tmp", OPENVASD_STATEDIR);
 mkdir(ret, 0700);
 sprintf(ret, "%s/tmp/tmp.%d-%d", OPENVASD_STATEDIR, getpid(), rand()%1024);
 fd = open(ret, O_RDONLY);
 } 
  while (fd >= 0);
  
 return ret;
}

 
 

/*---------------------------------------------------------------------

	Determines if a process is alive - as reliably as we can

-----------------------------------------------------------------------*/

int 
process_alive(pid)
 pid_t pid;
{
 int i, ret;
 if( pid == 0 ) 
  return 0;
 
 for(i=0,ret=1;(i<10) && (ret > 0);i++)
   ret = waitpid(pid, NULL, WNOHANG);
   
   
 return kill(pid, 0) == 0;
}



/*--------------------------------------------------------------------
 Determines if a BSD socket is still connected. Returns 0 if the socket
 is NOT connected, 1 otherwise
 *--------------------------------------------------------------------*/
int 
is_socket_connected(soc)
	int soc;
{
	fd_set  rd;
	struct timeval tv;
	int m;
	int e;

	FD_ZERO(&rd);
	FD_SET(soc, &rd);
	m = soc + 1;
again:
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	e = select(m+1, &rd, NULL, NULL, &tv);
	if ( e < 0 && errno == EINTR)goto again;
	
	if( e > 0 )
	{
		int len = data_left(soc);
		if( len == 0 )
			return 0;
	}
	return 1;
}



/*---------------------------------------------------------------------

	Determines if the client is still connected

	Returns <1> if the client is here
		<0> if it's not

-----------------------------------------------------------------------*/


int 
is_client_present(soc)
	int soc;
{
	fd_set  rd;
	struct timeval tv;
	int m;
	int e;

	stream_zero(&rd);
	m = stream_set(soc, &rd);
again:
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	e = select(m+1, &rd, NULL, NULL, &tv);
	if ( e < 0 && errno == EINTR)goto again;
	
	if( e > 0 )
	{
		int len = data_left(nessus_get_socket_from_connection(soc));
		if(!len){
			log_write("Communication closed by client\n");
			return 0;
			}
	}
	return 1;
}




int data_left(soc)
 int soc;
{
 int data = 0;
 ioctl(soc, FIONREAD, &data);
 return data;
}


int set_linger(soc, linger)
 int soc, linger;
{
 struct linger l;
 if(linger == 0)
  l.l_onoff = 0;
 else 
  l.l_onoff = 1;
 
 l.l_linger = linger;
 return setsockopt(soc, SOL_SOCKET, SO_LINGER, (void*)&l, sizeof(l));
}


void wait_for_children1()
{
 int e, n = 0;
 do {
 errno = 0;
 e = waitpid(-1, NULL, WNOHANG);
 n++;
 } while ( (e > 0 || errno == EINTR) && n < 20 );
}
