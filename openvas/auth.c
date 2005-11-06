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
 * This is the Authentication Manager
 *
 */


#include <includes.h>
#include <stdarg.h>
#include "comm.h"
#include "auth.h"
#include "sighand.h"
#include "globals.h"
#include "password_dialog.h"

/* 
 * auth_login
 *
 * sends the login and password to the Nessus 
 * daemon
 *
 * Params :
 *  user : login
 *  password : password
 *
 * Returns :
 *  0 if the login informations were sent successfully
 * -1 if a problem occured
 * 
 * Note : this function does NOT check if the login/password are
 * valid.
 */
 
extern char * stored_pwd;

int auth_login(user,password)
	char * user;
	char * password;
{
  char * buf = emalloc(255);

  /* Note: even if we use SSLv3 authentication, we ask for a password anyway */
  network_gets(buf, 7);
  if(strncmp(buf, "User : ", strlen(buf)))return(-1);
  network_printf("%s\n", user);
  
  bzero(buf, 255);
  network_gets(buf,11);
  if(strncmp(buf, "Password : ", strlen(buf)))return(-1);
  network_printf("%s\n", password);
  efree(&buf);
  return(0);
}


/*
 * network_printf(
 * 
 * This function sends a string to the server.
 * In the future, it will have to encrypt the string
 * but I have not implemented this feature right now
 */
void network_printf(char * data, ...)
{
  va_list param;
  int r, s = 65535;
  char * buffer = emalloc(s);
  int len, n = 0;
  signal(SIGPIPE, sighand_pipe);
  va_start(param, data);

 
  for(;;)
  {
   r = vsnprintf(buffer, s - 1, data, param);
   if(r >= 0 && r < s)break;
   s = r > s ? r + 1 : s * 2;
   buffer = erealloc(buffer, s);
  }
  len = strlen(buffer);
  while(n < len)
  {
   int m = 0;
   int size = 1024;
   /* send by packets of 1024 bytes due to a bug in libpeks */
   while(m < size)
   {
   int e;
   if((len - m - n) < size)size = len - m - n;
   e = nsend(GlobalSocket, &(buffer[n+m]), size, 0);
   if(e < 0) {
     perror("send");
    return;
   }
   m+=e;
  }
  n+=m;
 }
  signal(SIGPIPE, SIG_IGN);
  va_end(param);
  efree(&buffer);
}                    

/*
 * network_gets(
 * 
 * Reads data sent by the server
 * RETURN: >0 is the amount of data placed in s
 *         <0 means there was an error.
 */
int network_gets(s, size)
     char * s;
     size_t size;
{
  int n;
  /* We are assuming that recv_line() will block until it has 
   * recvieved a full line of data, encountered a hard error, or eof 
   * (socket close?)
   * Also, recv_line will return 0 on error.
   */
  n = recv_line(GlobalSocket, s, size); 
  if (n > 0)
    return n;
  else
  {
    s[0] = '\0';    /* zero the buffer */
    return -1;
  }
}

char * network_gets_raw(s, size)
     char * s;
     size_t size;
{
  int n = 0, processed ;

  /* read up until no more data, or a line terminating character 
     '\0' or '\n' is found */
  for (processed = 0; processed < (int)size; processed ++) {
    if ((n = nrecv (GlobalSocket, s + processed, 1, 0)) <= 0) {
      /* on error, the characers read so far might be garbage */
      if (n < 0)
	processed = 0 ;
      break ;
    }
    if (s [processed] == '\0' ||
	s [processed] == '\n' )
      break ;
  }

  /* append a terminating 0 character, return NULL on empty read */
  if (processed + 1 == (int)size)  processed -- ;
  s [processed] = '\0' ;
  if (!processed) s = 0 ;

  return s;
}
