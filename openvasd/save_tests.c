/* OpenVAS
* $Id$
* Description: Saves the current session in realtime.
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
#include "comm.h"
#include "users.h"
#include "locks.h"
#ifdef ENABLE_SAVE_TESTS

#include "save_tests.h"

/*================================================================
	
	              Private functions

 =================================================================*/
 
/*-----------------------------------------------------------------
 
  Name of the directory which contains the sessions of the current
  user (/path/to/var/openvas/<username>/sessions)
  
------------------------------------------------------------------*/ 
static char *
session_dirname(globals)
 struct arglist * globals;
{
 char * home = user_home(globals);
 char * dir;
 dir = emalloc(strlen(home) + strlen("sessions") + 2);
 sprintf(dir, "%s/sessions", home);
 efree(&home);
 return(dir);
}


/*----------------------------------------------------------------

 Create a session directory. 
 XXXXX does not check for the existence of a directory and does
 not check any error
 
------------------------------------------------------------------*/


static int
session_mkdir(dir)
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
 

	
/*----------------------------------------------------------------

 From <session>, return 
 /path/to/var/openvas/<username>/sessions/<session>-<suffix>

------------------------------------------------------------------*/
static char*
session_fname(globals, session, suffix)
 struct arglist * globals;
 char * session;
 char * suffix;
{
 char * dir = session_dirname(globals);
 char * ret;

 
 ret = emalloc(strlen(dir) + strlen(session) + strlen(suffix) + 10);
 sprintf(ret, "%s/%s-%s", dir, session, suffix);
 efree(&dir);
 return ret;
}




/*------------------------------------------------------------------

  Extract the hostname contained in one line of the data sent
  to the client
  
--------------------------------------------------------------------*/
static char*
extract_hostname(line)
 char * line;
{
 char * ret = NULL;
 if(!strncmp(line, "s:", 2))
 {
  char * t = &(line[4]);
  char * e;
  
  e = strchr(t, ':');
  if(e)
  {
   e[0]='\0';
   ret = strdup(t);
   e[0]=':';
  }
 }
 else if(!strncmp(line, "SERVER <|> ", 11))
 {
  char * t = strstr(line, " <|> ");
  char * e;
  t = strstr(t+2, " <|> ");
  if(t)
  {
   t += 5;
   e = strchr(t, ' ');
   if(e)
   {
    e[0] = 0;
    ret = strdup(t);
    e[0] = ' ';
    }
   }
  }
 return ret;
}



/*======================================================================

	                 Public functions
	
 =======================================================================*/	


/*------------------------------------------------------------------
  
   Initialize a new session that will be saved
   
 -------------------------------------------------------------------*/
int
save_tests_init(globals)
 struct arglist * globals;
{ 
 char * index_fname;
 char * data_fname;
 char * user = arg_get_value(globals, "user");
 char * asctime;
 char * dir;
 struct tm * lt;
 time_t t;

 int ret = 0;
 int index;
 int data;

 asctime = emalloc(2048); 
 t = time(NULL);
 lt = localtime(&t);
 
 /*
  * Session id : <year><month><day>-<hour><minute><second>
  */
 strftime(asctime, 2048, "%Y%m%d-%H%M%S", lt);
 
 
 dir = session_dirname(globals);
 session_mkdir(dir);
 efree(&dir);
 
 index_fname = session_fname(globals, asctime, "index");
 data_fname  = session_fname(globals, asctime, "data");
 
 index = open(index_fname, O_CREAT|O_WRONLY|O_EXCL, 0600);
 file_lock(index_fname);
 if(index < 0)
 {
  log_write("Can not save session index - %s", strerror(errno));
  ret = -1;
  goto bye;
 }
 else
 {
  struct arglist * prefs = arg_get_value(globals, "preferences");
  char * target = arg_get_value(prefs, "TARGET");
  
  log_write("user %s : session will be saved as %s", user, index_fname);
  if(arg_get_value(globals, "save_tests_index"))
  {
   arg_set_value(globals, "save_tests_index", sizeof(int), (void*)index);
  }
  else
   arg_add_value(globals, "save_tests_index", ARG_INT, sizeof(int), (void*)index);
 
  if(arg_get_value(globals, "save_tests_index_fname"))
  {
   char * s = arg_get_value(globals, "save_tests_index_fname");
   efree(&s);
   arg_set_value(globals, "save_tests_index_fname", strlen(index_fname), estrdup(index_fname));
  }
  else
   arg_add_value(globals, 
   		 "save_tests_index_fname", 
		 ARG_STRING, 
		 strlen(index_fname),
   		 estrdup(index_fname));
		 
  write(index, target, strlen(target));
  write(index, "\n", 1);
 }
 
 data = open(data_fname, O_CREAT|O_WRONLY|O_EXCL, 0600);
 file_lock(data_fname);
 if(data <  0)
 {
  log_write("Can not save session data - %s", strerror(errno));
  ret = -1;
  close(index);
  goto bye;
 }
 else
 {
  if(arg_get_value(globals, "save_tests_data_fname"))
  {
   char * s = arg_get_value(globals, "save_tests_data_fname");
   efree(&s);
   arg_set_value(globals, "save_tests_data_fname", strlen(data_fname), estrdup(data_fname));
  }
  else
   arg_add_value(globals, 
   		 "save_tests_data_fname", 
		 ARG_STRING, 
		 strlen(data_fname),
   		 estrdup(data_fname));	 
		 
		 
  if(arg_get_value(globals, "save_tests_data"))
   {
    arg_set_value(globals, "save_tests_data", sizeof(int), (void*)data);
    }
  else
   arg_add_value(globals, "save_tests_data", ARG_INT, sizeof(int), (void*)data);
 }
 
bye :
 efree(&data_fname);
 efree(&index_fname);
 efree(&asctime);
 return ret;
}


/*-------------------------------------------------------------------

   Stop the saving of the current session
   
 --------------------------------------------------------------------*/
void
save_tests_close(globals)
 struct arglist* globals;
{
 int f1 = (int)arg_get_value(globals, "save_tests_index");
 int f2 = (int)arg_get_value(globals, "save_tests_data");
 char * index_fname = arg_get_value(globals, "save_tests_index_fname");
 char * data_fname  = arg_get_value(globals, "save_tests_data_fname");

 if(f1 > 0)close(f1);
 if(f2 > 0)close(f2);
 if(index_fname)file_unlock(index_fname);
 if(data_fname)file_unlock(data_fname);
}



/*------------------------------------------------------------------
  
   Write <data> in our current session
 
 -------------------------------------------------------------------*/
void 
save_tests_write_data(globals, data)
 struct arglist * globals;
 char * data;
{
 int f = (int)arg_get_value(globals, "save_tests_data");
 int e, len, n = 0;
 
 if(!f)
  return;
  
 len = strlen(data);
 while(n < len)
 {
  e = write(f, data + n, len - n);
  if(e > 0)n+=e;
  else {
  	log_write("user %s : error in writing data to disk - %s",
  		(char*)arg_get_value(globals, "user"),
		strerror(errno));
	close(f);
	arg_set_value(globals, "save_tests_data", sizeof(int), 0);
	break;
       }	
 }
 efree(&data);
 fsync(f);
}


/*---------------------------------------------------------------

  Mark in our session that <host> has been tested
  
 ----------------------------------------------------------------*/
void
save_tests_host_done(globals, host)
 struct arglist * globals;
 char * host;
{
 int f = (int)arg_get_value(globals, "save_tests_index");
 char * d;
 int len, n = 0, e;
 
 if(!f)
  return;
  
 d = emalloc(strlen(host) + 2);
 strcat(d, host);
 strcat(d, "\n");
 
 len = strlen(d);
 while(n < len)
 {
  e = write(f, d+n, len-n);
  if(e > 0)n+=e;
  else {
   	log_write("user %s : error in writing data to disk - %s",
  		(char*)arg_get_value(globals, "user"),
		strerror(errno));
	close(f);
	arg_set_value(globals, "save_tests_index", sizeof(int), 0);
	break;
  	}
 }
 fsync(f);
 efree(&d);
}




/*----------------------------------------------------------

  Send a session back to our client
  
 -----------------------------------------------------------*/ 
void
save_tests_playback(globals, session, tested_hosts)
 struct arglist * globals;
 char * session;
 harglst * tested_hosts;
{
 char buf[8192];
 FILE * f;
 char * data_fname = session_fname(globals, session, "data");
 
 f = fopen(data_fname, "r");
 if(f)
 {
  while(fgets(buf, sizeof(buf)-1, f))
  {
   char * host = extract_hostname(buf);
   if(!host || harg_get_int(tested_hosts, host))
   {
   auth_printf(globals, "%s", buf);
   save_tests_write_data(globals, estrdup(buf));
   if(strstr(buf, "FINISHED"))
     save_tests_host_done(globals, host);
  /* usleep(5000); */ /* let the client process the data */
   }
   if(host)free(host);
   bzero(buf, sizeof(buf));
  }
  fclose(f);
 }
}


/*-------------------------------------------------------

   Delete the session <session>
   
 --------------------------------------------------------*/
int
save_tests_delete(globals, session)
 struct arglist * globals;
 char * session;
{
 char * data, * index;
 int ret = 0;
 
 data  = session_fname(globals, session, "data");
 index = session_fname(globals, session, "index"); 
 
 ret = unlink(index);
 if(!ret)
  ret = unlink(data);
 else
   unlink(data);
  
 efree(&index);
 efree(&data);
 return ret;
}


/*--------------------------------------------------------

  Set up openvasd so that we are ready to replay a test
  
 ---------------------------------------------------------*/
int
save_tests_setup_playback(globals, session)
 struct arglist* globals;
 char * session;
{
 harglst * tested;
 struct stat st;
 int length = 0;
 char * buf;
 FILE * f;
 char * t;
 char * index = session_fname(globals, session, "index");
 int fd = open(index, O_RDONLY);
 char * target;
 struct arglist * prefs;
 char * plugin_set;
 int len;
 
 session = estrdup(session);
 
 if(arg_get_value(globals, "RESTORE-SESSION"))
  arg_set_value(globals, "RESTORE-SESSION", sizeof(int), (void*)1);
 else
  arg_add_value(globals, "RESTORE-SESSION", ARG_INT, sizeof(int), (void*)1);
 
 if(arg_get_value(globals, "RESTORE-SESSION-KEY"))
  arg_set_value(globals, "RESTORE-SESSION-KEY", strlen(session), session);
 else
  arg_add_value(globals, "RESTORE-SESSION-KEY", ARG_STRING, strlen(session), session);
 
 
 
 
 if(fd < 0)
  {
  log_write("user %s : can not restore session - %s not found", 
  		(char*)arg_get_value(globals, "user"),
		session);
  return -1;
  }
 
 stat(index, &st);
 len = (int)st.st_size;
 
 /*
  * Get the first line of our file, which contains the 
  * list of hosts to test
  */
 buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
 t = buf;
 while(t[length] && t[length]!='\n')length++;
 munmap(buf, len);
 close(fd);
 
 target = emalloc(length+3);
 f = fopen(index, "r");
 fgets(target, length+2, f);
 if(target[strlen(target)-1]=='\n')target[strlen(target)-1]='\0';

 buf = emalloc(4096);
 tested = harg_create(length);
 
 /*
  * Populate our harglst with the names of the
  * hosts that have been completely tested
  */
 while(fgets(buf, 4095, f))
 {
  if(buf[strlen(buf)-1]=='\n')buf[strlen(buf)-1]=0;
  harg_add_int(tested, buf, 1);
  bzero(buf, 4096);
 }
 efree(&buf);
 fclose(f);
 
 /*
  * Set the global variables accordingly
  */
  if(arg_get_value(globals, "TESTED_HOSTS")) 
  arg_set_value(globals, "TESTED_HOSTS", -1, tested);
 else
  arg_add_value(globals, "TESTED_HOSTS", ARG_PTR, -1, tested);
  
  prefs = arg_get_value(globals, "preferences");
 if(arg_get_value(prefs, "TARGET"))
  arg_set_value(prefs, "TARGET", strlen(target), target);
 else
  arg_add_value(prefs, "TARGET", ARG_STRING, strlen(target), target);
  
  plugin_set = arg_get_value(prefs, "plugin_set");
 if( plugin_set == NULL || plugin_set[0] == '\0' )
 {
  plugin_set = emalloc(3);
  sprintf(plugin_set, "-1");
 }
 comm_setup_plugins(globals, plugin_set);
 return 0; 
}


/*------------------------------------------------------------------

   Send the list of sessions to the client
   
 -------------------------------------------------------------------*/

int 
save_tests_send_list(globals)
 struct arglist * globals;
{
 char * dirname;
 DIR * d;
 struct dirent * dp;
 char s[4000];
 
 dirname = session_dirname(globals);
 
 d = opendir(dirname);
 if(d)
 {
  while((dp = readdir(d)))
  {
   char * name = strdup(dp->d_name);
   char * ext = strrchr(name, '-');
   if(ext && (!strcmp(ext, "-index")))
   {
    FILE * f;
    char * fullname;
    
    fullname = emalloc(strlen(dirname) + strlen(name) + 2);
    strcat(fullname, dirname);
    strcat(fullname, "/");
    strcat(fullname, name);
    if(!file_locked(fullname))
    {
     f = fopen(fullname, "r");
     if(f)
     {
      bzero(s, sizeof(s));
      fgets(s, sizeof(s)-1, f);
      fclose(f);
      if(s[strlen(s)-1]=='\n')s[strlen(s)-1]='\0';
      ext[0]='\0';
      auth_printf(globals, "%s %s\n", name, s);
     }
     else perror("fopen ");
     efree(&fullname);
     }
    }
    efree(&name);
  }
 closedir(d);
 }
 
 efree(&dirname);
 return 0;
 
}


/*----------------------------------------------------------------*
 *  Returns <0> if anything worth (note, info or hole) has been   *
 *  sent to the client                                            *
 *----------------------------------------------------------------*/
 
int
save_tests_empty(globals)
 struct arglist* globals;
{
 char * data_fname  = arg_get_value(globals, "save_tests_data_fname");
 FILE * f;
#ifdef HAVE_ALLOCA
 char * buf = alloca(4096);
#else
 char buf[4096];
#endif
 int worth = 0;
 
 f = fopen(data_fname, "r");
 if(!f)
 {
  /* ??? */
   log_write("user %s : Could not re-open %s\n", (char*)arg_get_value(globals, "user"), data_fname); 
   return 0;
 }
 else
 {
  bzero(buf, 4096);
  while(fgets(buf, 4095, f))
  {
#define PORT_HDR "SERVER <|> PORT <|> "
#define PORT_HDR_LEN strlen(PORT_HDR)

#define NOTE_HDR "SERVER <|> NOTE <|> "
#define NOTE_HDR_LEN strlen(NOTE_HDR)

#define INFO_HDR "SERVER <|> INFO <|> "
#define INFO_HDR_LEN strlen(INFO_HDR)

#define HOLE_HDR "SERVER <|> HOLE <|> "
#define HOLE_HDR_LEN strlen(HOLE_HDR)

   if(!strncmp(buf, PORT_HDR, PORT_HDR_LEN) ||
      !strncmp(buf, NOTE_HDR, NOTE_HDR_LEN) ||
      !strncmp(buf, INFO_HDR, INFO_HDR_LEN) ||
      !strncmp(buf, HOLE_HDR, HOLE_HDR_LEN)){
      	worth++;
	break;
    }
  }
  fclose(f);
  return !worth;
 }
}

/*----------------------------------------------------------------*
 * Delete the current session                                     *
 *----------------------------------------------------------------*/
 
int
save_tests_delete_current(globals)
 struct arglist * globals;
{
 char * index_fname = arg_get_value(globals, "save_tests_index_fname");
 char * data_fname  = arg_get_value(globals, "save_tests_data_fname");

 save_tests_close(globals);
 unlink(index_fname);
 unlink(data_fname);
 return 0;
}
 
 
#endif /* ENABLE_SAVE_TESTS */

