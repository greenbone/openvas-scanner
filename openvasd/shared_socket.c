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
 */

#include <includes.h>
#include "utils.h"
#include "log.h"

struct shared_fd {
	nthread_t current_user;
	nthread_t creator;
	int fd;
	time_t lock_time;
	char * name;
	};


#define MAX_SHARED_SOCKETS 16

static struct shared_fd shared_fd[MAX_SHARED_SOCKETS];

/* Remove a socket from the shared_fd table */
static int openvasd_shared_socket_close(int idx)
{
 if ( idx < 0 || idx >= MAX_SHARED_SOCKETS )
	return -1;
 shutdown(shared_fd[idx].fd, 2);
 close(shared_fd[idx].fd);
 efree(&shared_fd[idx].name);
 bzero(&shared_fd[idx], sizeof(shared_fd[idx]));
 return 0;
}

static int openvasd_shared_socket_register ( int soc, nthread_t pid,  char * buf )
{
 int fd = 0;
 int i;
 int empty_slot = -1;

 
 char * buffer = NULL;
 int bufsz = 0;
 int e;
 int type;

 e = internal_recv( soc, &buffer, &bufsz, &type );
 if ( ( type & INTERNAL_COMM_MSG_SHARED_SOCKET ) == 0 ||
      ( type & INTERNAL_COMM_SHARED_SOCKET_DORECVMSG) == 0)
 {
  log_write("shared_socket_register(): Error - unexpected message %d\n", type);
  return -1;
 }

 fd = recv_fd(soc);
 if ( fd <= 0 )
 {
  log_write("shared_socket_register(): Error - recv_fd() failed\n");
  return -1;
 }

 /* Make sure that the socket does not exist already */
 for ( i = 0 ; i < MAX_SHARED_SOCKETS  ; i ++ )
 {
  if ( shared_fd[i].name != NULL &&
       strcmp(shared_fd[i].name, buf) == 0 )
	{
	 log_write("shared_socket: ERROR : process %d attempted to register '%s' but process %d created it already", pid, buf, shared_fd[i].creator);
	 return -1;
	}
  else if ( shared_fd[i].fd == 0 && empty_slot < 0 )
	empty_slot = i;
 }

 if ( empty_slot < 0 ) {
	log_write("shared_socket: ERROR : too many shared sockets !");
	return -1;
	}

 
 shared_fd[empty_slot].creator = pid;
 shared_fd[empty_slot].current_user = pid;
 shared_fd[empty_slot].lock_time = time(NULL);
 shared_fd[empty_slot].name  = estrdup(buf);
 shared_fd[empty_slot].fd = fd;
 log_write("shared_socket: Process %d registers a shared socket (%s)\n", pid, buf);
 return 0;
}

static int openvasd_shared_socket_acquire( int soc, nthread_t pid, char * buf )
{
 int i;
 for ( i = 0 ; i < MAX_SHARED_SOCKETS ; i ++ )
 {
  if ( shared_fd[i].name != NULL && strcmp(shared_fd[i].name, buf) == 0 )
	{
	 if ( shared_fd[i].current_user != 0 )
		{
	         log_write("shared_socket: %s is busy (locked by %d)\n", buf, shared_fd[i].current_user);
		 /* Send a SOCKET_BUSY message */
		 internal_send(soc, NULL, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_BUSY);
	 	 return 0;
		}
	  else
		{
		 if ( is_socket_connected(shared_fd[i].fd) == 0 )
		  {
	            log_write("shared_socket: socket %s lost connection to its peer - destroying this entry\n", buf);
		    openvasd_shared_socket_close(i);
 		    internal_send(soc, NULL, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_ERROR);
		    return 0; /* Not really an error in itself */
		  }
                 else
                  {
	           log_write("shared_socket: %s now locked by %d\n", buf, pid);
		   shared_fd[i].current_user = pid;
		   shared_fd[i].lock_time    = time(NULL);
		   /* Send the socket itself */
		   internal_send(soc, NULL, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_DORECVMSG);
	 	   send_fd(soc, shared_fd[i].fd);
		   return 0;
		  }
		}
	}
 }

 internal_send(soc, NULL, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_ERROR);
 log_write("shared_socket: %s is unknown\n", buf);
 return -1;
}

static int openvasd_shared_socket_release( int soc, nthread_t pid, char * buf )
{
 int i;
 for ( i = 0; i < MAX_SHARED_SOCKETS ; i ++ )
 {
 if ( shared_fd[i].name != NULL && strcmp(shared_fd[i].name, buf) == 0 )
  {
   if ( shared_fd[i].current_user != pid )  
   {
    log_write("shared_socket: ERROR : Process %d attempted to release socket %s, but it's being locked by process %d", pid, buf, shared_fd[i].current_user);
    return -1;
   }
   
   shared_fd[i].current_user = 0;
   shared_fd[i].lock_time    = 0;
   log_write("shared_socket: %s released by process %d\n", buf, pid);
   return 0;
  }
 }
 log_write("shared_socket: shared_socket_release: %s not found (%d)\n", buf, pid);
 return -1; /* Not found */
}






static int openvasd_shared_socket_destroy( int soc, nthread_t pid, char * buf )
{
 int i;
 for ( i = 0; i < MAX_SHARED_SOCKETS ; i ++ )
 {
  if ( shared_fd[i].name != NULL && strcmp(shared_fd[i].name, buf) == 0 )
  {
   if ( shared_fd[i].current_user == 0 ||
        shared_fd[i].current_user == pid )
      {
       openvasd_shared_socket_close(i);
       log_write("shared_socket: %d destroyed socket %s\n", pid, buf);
       return 0;
      }
  }
 }
 log_write("shared_socket: shared_socket_relase(): %s not found (%d)", buf, pid);
 return -1;
}


int shared_socket_init()
{
 bzero(&shared_fd, sizeof( shared_fd ) );
 return 0;
}


int shared_socket_close()
{
 int i;
 for ( i = 0; i < MAX_SHARED_SOCKETS ; i ++ )
 {
  if ( shared_fd[i].fd != 0 )
	{
	shutdown(shared_fd[i].fd, 2);
	close(shared_fd[i].fd);
	efree(&shared_fd[i].name);
	}
 }
 bzero(&shared_fd, sizeof( shared_fd ) );
 return 0;
}


int shared_socket_cleanup_process( nthread_t process )
{
 int i;
 for ( i = 0; i < MAX_SHARED_SOCKETS ; i ++ )
 {
  if ( shared_fd[i].current_user == process )
  {
   log_write("shared_socket: Process %d has finished - releasing %s\n", process, shared_fd[i].name);
   shared_fd[i].current_user = 0;
   shared_fd[i].lock_time = 0; 
  }
 }
 return 0;
}

int shared_socket_process( int soc, nthread_t pid, char * buf, int message )
{
 if ( message & INTERNAL_COMM_SHARED_SOCKET_REGISTER )
	return openvasd_shared_socket_register(soc, pid, buf);
  
 if ( message & INTERNAL_COMM_SHARED_SOCKET_ACQUIRE )
	return openvasd_shared_socket_acquire(soc, pid, buf);

 if ( message & INTERNAL_COMM_SHARED_SOCKET_RELEASE )
	return openvasd_shared_socket_release(soc, pid,  buf);

 if ( message & INTERNAL_COMM_SHARED_SOCKET_DESTROY )
	return openvasd_shared_socket_destroy(soc, pid, buf);

 return -1; /* Unknown message */
}




