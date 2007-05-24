/* OpenVAS
* $Id$
* Description: Provides signal handling functions.
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

#include "log.h"
#include "auth.h"
#include "sighand.h"
#include "utils.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

extern pid_t bpf_server_pid;
extern pid_t nasl_server_pid;


/* do not leave a zombie, hanging around if possible */
void
let_em_die
  (int pid)
{
  int	status, x;
# ifdef HAVE_WAITPID
  x = waitpid (pid, &status, WNOHANG) ;
# else
# ifdef HAVE_WAIT3
  struct rusage ru ;
# ifdef HAVE_WAIT4
  x = wait4 (pid, &status, WNOHANG, &ru) ;
# else
  x = wait3 (&status, WNOHANG, &ru) ;
# endif
# endif /* HAVE_WAIT3 */
# endif /* HAVE_WAITPID */
}


void
make_em_die
  (int sig)
{
  /* number of times, the sig is sent at most */
  int n = 3 ;


  /* leave if we are session leader */
  if (getpgrp () != getpid()) return ;
  
   
   if(nasl_server_pid != 0 && kill(nasl_server_pid, 0) >= 0 )
       kill(nasl_server_pid, SIGTERM);
 
   if(bpf_server_pid != 0 && kill(bpf_server_pid, 0) >= 0)
   	kill(bpf_server_pid, SIGTERM);

  /* quickly send siglals and check the result */
  if (kill (0, sig) < 0) return ;	     
  let_em_die (0);
  if (kill (0, 0) < 0) return ;

  do {
    /* send the signal to everybody in the group */
    if (kill (0, sig) < 0)
      return ;	     
    sleep (1);
    /* do not leave a zombie, hanging around if possible */
    let_em_die (0);
  } while (-- n > 0) ;

  if (kill (0, 0) < 0)
    return ;

  kill (0, SIGKILL);
  sleep (1);
  let_em_die (0);
}

/*
 *  Replacement for the signal() function, written
 *  by Sagi Zeevi <sagiz@yahoo.com>
 */
void (*nessus_signal(int signum, void (*handler)(int)))(int)
{
  struct sigaction saNew,saOld;

  /* Init new handler */
  sigfillset(&saNew.sa_mask);
  sigdelset(&saNew.sa_mask, SIGALRM); /* make sleep() work */
  
  saNew.sa_flags = 0;
# ifdef HAVE_SIGNAL_SA_RESTORER
  saNew.sa_restorer = 0; /* not avail on Solaris - jordan */
# endif
  saNew.sa_handler = handler;

  sigaction(signum, &saNew, &saOld);
  return saOld.sa_handler;
}


void sighand_chld()
{
 int ret; 
 int e;
 do {
  errno = 0;
  e = wait(&ret);
 } while ( e < 0 && errno == EINTR );
}

void sighand_alarm()
{
  log_write("connection timed out\n");
  shutdown (0,2);
  close (0);
  make_em_die (SIGTERM);
  _EXIT(1);   
}           



void sighandler(sign)
 int sign;
{
 char * sig = NULL;
 int murderer = 0;
 
 switch(sign)
 {
  case SIGTERM:
  	sig = "TERM";
	murderer++;
	delete_pid_file();
  	break;
  case SIGUSR1 :
 	sig = "USR1";
	delete_pid_file();
 	break;
  case SIGINT :
  	sig = "INT";
	delete_pid_file();
	murderer++;
	break;
  case SIGSEGV :
#ifdef HAVE__EXIT
	signal(SIGSEGV, _exit);
#else
  	signal(SIGSEGV, exit);
#endif	
  	sig = "SEGV";
	break;
  default:
  	sig = "< signal nonsense >";
 }
 
 log_write("received the %s signal\n",sig);
 
#ifndef USE_AF_INET
  unlink(AF_UNIX_PATH);
#endif


 if(murderer)
  make_em_die(sign);
  
 
 
  
 _EXIT(0);
}



void sighand_segv()
{
#ifdef HAVE__EXIT
 signal(SIGSEGV, _exit);
#else
 signal(SIGSEGV, exit);
#endif
 log_write("SIGSEGV occured !\n");
#if 0
 for (;;) nice(1);		/* to attach a debugger! */
#endif
 make_em_die (SIGTERM);
 _EXIT(0);
}
