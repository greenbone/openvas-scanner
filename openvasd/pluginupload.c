/* Nessus
 * Copyright (C) 1998 - 2004 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Plugin upload : the client may upload its own plugins to openvasd.
 * This module implements the correct functions to do so.
 *
 *
 */
#include <includes.h>
#include "preferences.h"
#include "users.h"
#include "log.h"
#include "pluginload.h"
/*
 * Where the plugins will be stored on the remote server
 * (<userhome>/plugins)
 */ 
static char *
plugins_homedir(globals)
 struct arglist * globals;
{ 
 char * uhome = user_home(globals);
 char * ret = emalloc(strlen(uhome) + strlen("plugins") + 2);
 sprintf(ret, "%s/plugins", uhome);
 efree(&uhome);
 return ret;
}


int
plugin_recv(globals)
 struct arglist * globals;
{
 int soc = (int)arg_get_value(globals, "global_socket");
 struct arglist * preferences = arg_get_value(globals, "preferences");
 char * name;
 int n;
 long bytes = 0;
 int fd;
 char fullname[1024], tmpname[1024];
 char input[4096];
 char * buffer;
 
  
 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)
  return -1;
  
 if(!strncmp(input, "name: ", strlen("name: ")))
  {
  name = estrdup(input + strlen("name: "));
  if(name[strlen(name) - 1] == '\n')
   name[strlen(name) - 1] = '\0';
  }
  else 
   return -1;
  
 /* 
  * invalid file name
  */
 if(strchr(name, '/'))
  { 
   log_write("%s - invalid file name\n", name);
   return -1; 
  }

 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)
  return -1;
 /* XXX content: message. Ignored for the moment */
 
 n = recv_line(soc, input, sizeof(input) - 1);
 if(n <= 0)
  return -1;
  
 if(!strncmp(input, "bytes: ", strlen("bytes: ")))
 {
  char * t = input + strlen("bytes: ");
  bytes = atol(t);
 }
  else return -1;
  
  
 /*
  * Don't accept plugins bigger than 5Mb 
  */
 if(bytes > 5*1024*1024)
  return -1; 
  
  
 /*
  * Ok. We now know that we have to read <bytes> bytes from the
  * remote socket.
  */
  
  if(preferences_upload_enabled(preferences) &&
     preferences_upload_suffixes(preferences,
     				name))
  {
  char * dir;
  if(!preferences_user_is_admin(globals, preferences))
   dir  = plugins_homedir(globals);
  else
   dir = estrdup(arg_get_value(preferences, "plugins_folder"));
  snprintf(fullname, sizeof(fullname), "%s/%s", dir, name);
  snprintf(tmpname, sizeof(fullname), "%s/.%s.tmp", dir, name);
  efree(&dir);
  }
  else {
  	 strncpy(fullname, "/dev/null", sizeof(fullname) - 1);
  	 strncpy(tmpname, "/dev/null", sizeof(tmpname) - 1);
	}
  
  log_write("saving in %s", fullname);
 
  fd = open(tmpname, O_CREAT|O_WRONLY|O_TRUNC, 0600);
  if(fd < 0)
  {
   perror("plugins_recv(): open() ");
   return -1;
  }
  
  buffer = emalloc(bytes);
  n = 0;
  while (n != bytes)
  { 
   int e;
   e = read_stream_connection_min(soc, buffer+n, bytes-n, bytes-n);
   if (e <= 0)
	    {
		if(errno == EINTR)continue;
     		else break;
	    }		
   n += e;
  }

  write(fd, buffer, n);
  close(fd);
  
  
  if(strcmp(fullname, "/dev/null"))
   auth_printf(globals, "SERVER <|> PLUGIN_ACCEPTED <|> SERVER\n");
  else
   auth_printf(globals, "SERVER <|> PLUGIN_DENIED <|> SERVER\n");
  
  if( strcmp(fullname, tmpname) != 0 )
  {
   unlink(fullname);
   if ( rename(tmpname, fullname) <  0 ) 
   	perror("rename ");
  }
  
  
  efree(&buffer);
#if 0
  arg_set_value(globals, 
  		"plugins", 
		-1, 
  		plugins_reload_user(
			    globals, 
			    preferences, 
			    arg_get_value(globals, "plugins")
			    )
		);
#endif
  return 0;
}
