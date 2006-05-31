/* OpenVAS
* $Id$
* Description: Creates new threads.
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
#include <setjmp.h>
#include "processes.h"
#include "sighand.h"
#include "log.h"


static int process_son = 0;

void sighand_process_term(int sig)
{
 int son = process_son;
 if(son){
 	kill(son, SIGTERM);
	process_son = 0;
	}
 _EXIT(0);
}



static void pr_sigterm(int sig)
{
 _exit(0);
}



int terminate_process(pid_t pid)
{
 int ret;
 
 if(pid <= 0 )
   	return 0;


 ret = kill(pid, SIGTERM);
 
 if( ret == 0 )
 { 
  usleep(1000);
  if (waitpid(pid, NULL, WNOHANG) >= 0 )
   	kill(pid, SIGKILL);
 }
  return -1;
}




/*
 * Create a thread
 */
pid_t
create_process(function, argument)
  process_func_t function;
  void * argument;
{
 int pid;

 

 pid = fork();

 if (pid == 0)
 { 
  process_son = 0;
  nessus_signal(SIGHUP, SIG_IGN);
  nessus_signal(SIGTERM, pr_sigterm);
  nessus_signal(SIGINT, pr_sigterm);
  nessus_signal(SIGPIPE, SIG_IGN);
  nessus_signal(SIGUSR1, SIG_IGN);
  nessus_signal(SIGUSR2, SIG_IGN);
  nessus_signal(SIGCHLD, sighand_chld);
  nessus_signal(SIGSEGV, sighand_segv);	/* Comment this line out to dump a core and debug openvasd */
  srand48(getpid() + getppid() + (long)time(NULL));
  (*function)(argument);
  EXIT(0);
 }
 if(pid < 0)
 	log_write("Error : could not fork ! Error : %s\n", strerror(errno));
 process_son = pid;
 return pid;
} 



