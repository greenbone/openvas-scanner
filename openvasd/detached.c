/* OpenVAS
 * Copyright (C) 1998 - 2004 Renaud Deraison
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
 *
 */
 
 
#include <includes.h>
#ifdef ENABLE_SAVE_KB

#include "detached.h"
#include "utils.h"
#include "log.h"
#include "users.h"
#include "processes.h"

/*-----------------------------------------------------------------------*
 *                            Private functions                          *
 *-----------------------------------------------------------------------*/
#define PORT_HDR "SERVER <|> PORT <|> "
#define PORT_HDR_LEN strlen(PORT_HDR)

#define NOTE_HDR "SERVER <|> NOTE <|> "
#define NOTE_HDR_LEN strlen(NOTE_HDR)

#define INFO_HDR "SERVER <|> INFO <|> "
#define INFO_HDR_LEN strlen(INFO_HDR)

#define HOLE_HDR "SERVER <|> HOLE <|> "
#define HOLE_HDR_LEN strlen(HOLE_HDR)

#define NOTE 1
#define INFO 2
#define HOLE 3


/*
 * Invokes sendmail -t
 */
void _detached_send_mail(globals)
 struct arglist * globals;
{
 /*
  * We do not check the full path to sendmail because if root
  * can not trust his path, then I bet he's hosed already
  */
 char * argv[]={"sendmail", "-t", "-B8BITMIME", NULL};
 char * fname = arg_get_value(globals, "detached_scan_email_filename");
 pid_t pid;
 struct stat st;
 off_t * orig_size = arg_get_value(globals, "detached_scan_file_len");
 struct arglist * preferences = arg_get_value(globals, "preferences");
 
 stat(fname, &st);
 
 
 /*
  * Nothing new - we don't send any mail (because a blank mail
  * is useless)
  */
 if(st.st_size == *orig_size)
 {
  log_write("user %s : scan did not produce any result, so no email will be sent",
  		(char*)arg_get_value(globals, "user"));
		
  efree(&orig_size);
  return;
 }
 
 efree(&orig_size);
 
 if(!(pid = fork()))
 {
  int fd;
  int i;
  
  /*
   * Close all open files
   */
  for(i=0;i<getdtablesize();i++)close(i);
  
  /*
   * Our email file becomes stdin
   */
  fd = open(fname, O_RDONLY, 0);
  if(fd < 0)
    {
     log_init(arg_get_value(preferences, "logfile"));
     log_write("user %s : could not open our email %s - %s\n", 
     		(char*)arg_get_value(globals, "user"),
		fname,
		strerror(errno));
     exit(1);
    }
  if(execvp("sendmail", argv) < 0)
   {
    log_init(arg_get_value(preferences, "logfile"));
     log_write("user %s : could not execute sendmail - %s\n", 
     		(char*)arg_get_value(globals, "user"),
		strerror(errno));
   }
   exit(1);
 }
 else if(pid  > 0)waitpid(pid, NULL, 0);
}

static void
detached_copy_data_port(globals, buffer)
 struct arglist * globals;
 char * buffer;
{
 char * t;
 FILE * fl = arg_get_value(globals, "detached_scan_email_fd");
 
  
 t = strchr(buffer, '<');
 if(!t)return;
 t--;
 t[0]='\0';
 t+=5;

 fprintf(fl, "o %s : port %s was found to be open\n\n", 
 		buffer,
		t);
	
}


static void
detached_copy_data_content(globals, buffer, type)
 struct arglist * globals;
 char * buffer;
 int type;
{
 char * t = strrchr(buffer, '<');
 char * host, * port;
 char * asctype = NULL;
 FILE * fl = arg_get_value(globals, "detached_scan_email_fd");
 char * noslashes;
  
  
 
 switch(type)
 {
  case INFO :
  	asctype = "warning";
	break;
  case NOTE :
  	asctype = "note";
	break;
  case HOLE :
  	asctype = "hole";
	break;
 }
 
 
 if(!t)return;
 t--;
 t[0]='\0';
 
 t = strchr(buffer, '<');
 if(!t)
  return;
  
 t--;
 t[0]='\0';
 host = estrdup(buffer);
 buffer = t + 5;
 t = strchr(buffer, '<');
 if(!t)
 {
  efree(&host);
  return;
 }
 
 t--;
 t[0]='\0';
 port = estrdup(buffer);
 
 buffer = t+5;
 
 noslashes = rmslashes(buffer);
 fprintf(fl, "o %s : Security %s found on port %s :\n%s\n\n",
 		host,
		asctype,
		port,
		noslashes);
 efree(&noslashes);		
 efree(&host);
 efree(&port);		
}


/*------------------------------------------------------------------------*
 *                          Public functions                              *
 *------------------------------------------------------------------------*/
void
detached_copy_data(globals, buffer, length)
 struct arglist * globals;
 char * buffer;
 int length;
{
 char *t;
 int info = 0, note = 0, hole = 0;
 
 if(!buffer || !globals)
  return;

 if(!arg_get_value(globals, "detached_scan_email_address"))
  {
  efree(&buffer);
  return;
  }

 while((t = strchr(buffer, ';')))t[0]='\n';
 
 t = strrchr(buffer, '<');
 if(t){
  t--;
  t[0]='\0';
  }
  
 /*
  * Ok, so we want to parse the message. It's in NTP/1.whatever,
  * want we are only interested in open ports and information reports
  */
 if(!strncmp(buffer, PORT_HDR,  PORT_HDR_LEN))
 {
  detached_copy_data_port(globals, buffer+PORT_HDR_LEN);
 }
 else if(!(info = strncmp(buffer, INFO_HDR, INFO_HDR_LEN)) ||
         !(note = strncmp(buffer, NOTE_HDR, NOTE_HDR_LEN)) ||
	 !(hole = strncmp(buffer, HOLE_HDR, HOLE_HDR_LEN)))
	 {
	 detached_copy_data_content(globals, buffer+INFO_HDR_LEN, 
	 		hole==0?HOLE:(info==0?INFO:NOTE));
	 }
 efree(&buffer);
}





int
detached_setup_mail_file(globals, email)
 struct arglist * globals;
 char * email;
{
  FILE* fl;
  char * tmpname;
  char * today;
  time_t t;
  char *hostname = emalloc(256);
  struct stat st;
  off_t * sz;
  
  t = time(NULL);
  today = estrdup(ctime(&t));
  today[strlen(today)-1]='\0';
    
  log_write("user %s : mailing results of a detached scan to %s\n", 
    					(char*)arg_get_value(globals, "user"),
    					email);
					
  if((arg_get_type(globals, "detached_scan_email_address")) < 0)
   arg_add_value(globals, "detached_scan_email_address", ARG_STRING, strlen(email), email);
  else
   arg_set_value(globals, "detached_scan_email_address", strlen(email), email);
   
  tmpname = temp_file_name();  
  fl = fopen(tmpname, "w");
  chmod(tmpname, 0600);
  if(!fl)
    {
     log_write("user %s : could not create file '%s' (%s) - aborting", 
     					(char*)arg_get_value(globals, "user"),
					tmpname,
					strerror(errno));
      
    auth_printf(globals, "SERVER <|> ERROR <|> Could not create the temporary \
file needed for detached scan (%s) - aborting <|> SERVER\n", strerror(errno));
    efree(&today);
    return -1;
   }
   bzero(hostname, 256);
   gethostname(hostname, 255);
   fprintf(fl, "From: OpenVAS Daemon <root@%s>\n", hostname);
   fprintf(fl, "To: OpenVAS User <%s>\n", email);
   fprintf(fl, "Subject: OpenVAS Scan (%s)\n\n", today);
   fflush(fl);
   efree(&today); 
   efree(&hostname);
   stat(tmpname, &st);
   
   sz = emalloc(sizeof(st.st_size));
   memcpy(sz, &(st.st_size), sizeof(st.st_size));
   if(arg_get_type(globals, "detached_scan_file_len") < 0)
    arg_add_value(globals, "detached_scan_file_len", ARG_PTR, sizeof(int),sz);
   else
    arg_set_value(globals, "detached_scan_file_len", sizeof(int), sz);
    
   
   if(arg_get_type(globals, "detached_scan_email_fd") < 0)
     arg_add_value(globals, "detached_scan_email_fd", ARG_PTR, sizeof(fl), fl);
   else
    arg_set_value(globals, "detached_scan_email_fd", sizeof(fl), fl);
   
   
   
   if(arg_get_type(globals, "detached_scan_email_filename") < 0)
     arg_add_value(globals, "detached_scan_email_filename", ARG_STRING, strlen(tmpname), tmpname);
   else
     arg_set_value(globals, "detached_scan_email_filename", strlen(tmpname), tmpname);

 return 0;
}

void
detached_send_email(globals)
 struct arglist * globals;
{
 char * fname = arg_get_value(globals, "detached_scan_email_filename");
 FILE * fl = arg_get_value(globals, "detached_scan_email_fd");
    
 if(fl){
   fclose(fl);
   arg_set_value(globals, "detached_scan_email_fd", 0, NULL);
   }
   
   
 _detached_send_mail(globals);

   
   
 unlink(fname);
 if(fname){
 	efree(&fname);
	arg_set_value(globals, "detached_scan_email_filename", 0, NULL);
	}
}

/*-----------------------------------------------------------------------
 		Management of detached scans
-------------------------------------------------------------------------*/
static char *
detached_dirname(globals)
 struct arglist * globals;
{
 char * dir;
 char * userhome = user_home(globals);
 dir = emalloc(strlen(userhome) + strlen("detached") + 2);
 sprintf(dir, "%s/detached", userhome);
 efree(&userhome);
 return(dir);
}


static int
detached_mkdir(dir)
 char * dir;
{
 char *t = strchr(dir+1, '/');
 while(t)
 {
  t[0] = '\0';
  mkdir(dir, 0700);
  t[0] = '/';
  t = strchr(t+1, '/');
 }
 mkdir(dir, 0700);
 return 0;
}



static char *
detached_fname(globals)
 struct arglist * globals;
{
 char * dir = detached_dirname(globals);
 char * ret;
 
 detached_mkdir(dir);
 ret = emalloc(strlen(dir) + 40);
 sprintf(ret, "%s/%d", dir, getpid());
 efree(&dir);
 return ret;
}

int
detached_new_session(globals, target)
 struct arglist * globals;
 char * target;
{
 char * fname = detached_fname(globals);
 int f = open(fname, O_CREAT|O_WRONLY|O_TRUNC);
 if(f >= 0)
 {
  write(f, target, strlen(target));
  fsync(f);
  close(f);
  chmod(fname, 0600); 
  efree(&fname);
  return getpid();
 }
  else log_write("user %s : could not create %s - %s\n",
  			(char*)arg_get_value(globals, "user"),
			fname,
			strerror(errno));
 efree(&fname);
 return -1;
}


int
detached_send_sessions(globals)
 struct arglist * globals;
{
 char * dir = detached_dirname(globals);
 DIR * d = opendir(dir);
 struct dirent * dp;

 
 if(!d)
  {
  efree(&dir);
  return 0;
  }
 while(( dp = readdir(d) )) 
 {
   char * name = dp->d_name;
   char * full;
   int pid = atoi(name);
   if(pid)
   {
    if(!process_alive(pid))
    {
     log_write("user %s : session %d is dead - removing its lock",
     		(char*)arg_get_value(globals, "user"),
		pid);
     detached_delete_session(globals, pid);
    }
    else  
    {
     int f;
     full = emalloc(strlen(dir) + strlen(name) + 20);
     sprintf(full, "%s/%s", dir, name);
     f = open(full, O_RDONLY);
     if( f >= 0 )
     { 
     char buf[2048];
     read(f, buf, sizeof(buf) - 1);
     auth_printf(globals, "%s %s\n", name, buf);
     close(f);
     }
     efree(&full);
    }
   }
  }
  closedir(d);
  efree(&dir);
  return 0;
}



int
detached_delete_session(globals, index)
 struct arglist * globals;
 int index;
{
 char * dir = detached_dirname(globals);
 char * file  = emalloc(strlen(dir) + 30);
 int f;
 sprintf(file, "%s/%d", dir, index);
 efree(&dir);
 if(( f = open(file, O_RDONLY) ) >= 0)
 {
  close(f);
  if(index != getpid())
   kill(index, SIGTERM);
  unlink(file);
 }
 efree(&file);
 return 0;
}

int
detached_end_session(globals)
 struct arglist * globals;
{
 return detached_delete_session(globals, getpid());
}

#endif /* enable save kb */
