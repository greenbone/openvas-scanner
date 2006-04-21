/* Nessus
 * Copyright (C) 1998 - 2004  Renaud Deraison
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
 * save_kb :
 *  save the knowledge base about a remote host
 *
 */
 
#include <includes.h>
#include "log.h"
#include "comm.h"
#include "users.h"
#include "locks.h"
#ifdef ENABLE_SAVE_KB



#ifndef MAP_FAILED
#define MAP_FAILED (void*)(-1)
#endif


#include "save_kb.h"



/*=========================================================================

			Private functions
			
===========================================================================*/

static char *
filter_odd_name(name)
 char * name;
{ 
 char * ret = name;
 while(name[0])
 {
  /*
   * A host name should never contain any slash. But we never
   * know
   */
  if(name[0]=='/')name[0]='_';  
  name++;
 }
 return ret;
}


/*-----------------------------------------------------------------
 
  Name of the directory which contains the sessions of the current
  user (/path/to/var/openvas/<username>/kbs/)
  
------------------------------------------------------------------*/ 
static char *
kb_dirname(globals)
 struct arglist * globals;
{
 char * home = user_home(globals);
 char * dir  = emalloc(strlen(home) + strlen("kbs") + 2);
 sprintf(dir, "%s/kbs", home);
 efree(&home);
 return(dir);
}

/*----------------------------------------------------------------

 Create a kb directory. 
 XXXXX does not check for the existence of a directory and does
 not check any error
 
------------------------------------------------------------------*/


static int
kb_mkdir(dir)
 char * dir;
{
 char *t;
 int ret = 0;
 
 dir = estrdup(dir);
 t = strchr(dir+1, '/');
 while(t)
 {
  t[0] = '\0';
  mkdir(dir, 0700);
  t[0] = '/';
  t = strchr(t+1, '/');
 }
 
 
 if ((ret = mkdir(dir, 0700)) < 0) {
  if(errno != EEXIST)
    log_write("mkdir(%s) failed : %s\n", dir, strerror(errno));
  efree(&dir);
  return ret;
 }
 efree(&dir);
 return ret;
}


/*----------------------------------------------------------------

 From <hostname>, return 
 /path/to/var/openvas/<username>/kb/<hostname>

------------------------------------------------------------------*/
static char*
kb_fname(globals, hostname)
 struct arglist * globals;
 char * hostname;
{
 char * dir = kb_dirname(globals);
 char * ret;
 char * hn = strdup(hostname);
 
 hn = filter_odd_name(hn);
 
 ret = emalloc(strlen(dir) + strlen(hn) + 2);
 sprintf(ret, "%s/%s", dir, hn);
 efree(&dir);
 efree(&hn);
 return ret;
}


/*
 * mmap() tends to sometimes act weirdly
 */

static char*
map_file(file)
 int file;
{
 struct stat st;
 char *ret;
 int i = 0;
 int len;
 
 bzero(&st, sizeof(st));
 fstat(file, &st);
 len = (int)st.st_size;
 if ( len == 0 )
 	return NULL;
	
 lseek(file, 0, SEEK_SET);
 ret = emalloc(len + 1);
 while(i < len )
 {
  int e = read(file, ret + i, len - i);
  if(e > 0)
  	i+=e;
   else
     {
     	log_write("read(%d, buf, %d) failed : %s\n", file, len, strerror(errno));
	efree(&ret);
	lseek(file, len, SEEK_SET);
	return NULL;
     }
 }
 
 lseek(file, len, SEEK_SET);
 return ret;
}
 
static int
save_kb_entry_present_already(globals, hostname, name, value)
 struct arglist * globals;
 char * hostname;
 char * name;
 char * value;
{
  char * buf;
  int fd;
  char* req;
  int ret;
   
  fd = (int)arg_get_value(globals, "save_kb");
  if(fd <= 0)
   return -1;
 
  buf = map_file(fd);
  if(buf)
  {
   req = emalloc(strlen(name) + strlen(value) + 2);
   sprintf(req, "%s=%s",name, value);
   if(strstr(buf, req))
    ret = 1;
   else
    ret = 0;
   efree(&buf);
   efree(&req);
   return ret;
  }
 return -1;
} 
 
static int
save_kb_rm_entry_value(globals, hostname, name, value)
 struct arglist * globals;
 char * hostname;
 char * name;
 char * value;
{
  char * buf;
  char * t;
  int fd;
  char * req;
  
   
  fd = (int)arg_get_value(globals, "save_kb");
  if(fd <= 0)
   return -1;
  
  buf = map_file(fd);
  if(buf)
  {
   if(value)
   { 
    req = emalloc(strlen(name) + strlen(value) + 2);
    sprintf(req, "%s=%s", name, value);
   }
   else 
    req = estrdup(name);
    
   t = strstr(buf, req);
   if(t)
   {
    char * end;
       
     while(t[0] != '\n')
     {
       if(t == buf)break;
       else t--;
     }
       
     if(t[0] == '\n')t++;
     end = strchr(t, '\n');
     t[0] = '\0';
     if(end){
       	end[0] = '\0';
	end++;
	}

     if((lseek(fd, 0, SEEK_SET))<0)
       {
        log_write("lseek() failed - %s\n", strerror(errno));
       }
       
     if((ftruncate(fd, 0))<0)
       {
        log_write("ftruncate() failed - %s\n", strerror(errno));
       }
       
      
     if(write(fd, buf, strlen(buf)) < 0)
       {
        log_write("write() failed - %s\n", strerror(errno));
       }
     
     if(end){
       	if((write(fd, end, strlen(end)))<0)
	  log_write("write() failed - %s\n", strerror(errno));
	}
      }
      efree(&buf);
      efree(&req);
      lseek(fd, 0, SEEK_END);
     }
     return 0;
}

static int
save_kb_rm_entry(globals, hostname, name)
 struct arglist * globals;
 char * hostname;
 char * name;
{
 return save_kb_rm_entry_value(globals, hostname, name, NULL);
}
 
/*
 * Write data
 *
 * We want to avoid duplicates for :
 *
 * 	Successful/...
 *	SentData/...
 *	Launched/...
 *
 * We don't want to save /tmp/...
 */	
static int
save_kb_write(globals, hostname, name, value, type)
 struct arglist * globals;
 char * hostname, * name, * value;
 int type;
{
 int fd;
 char * str;
 int e;
 struct timeval now;

 if(!globals  ||
    !hostname || 
    !name     || 
    !value)
 	return -1;
	
 fd = (int)arg_get_value(globals, "save_kb");
 if(fd <= 0)
  {
  log_write("user %s : Can not find KB fd for %s\n", (char*)arg_get_value(globals, "user"), hostname);
  return -1;
  }
 

 /*
  * Don't save temporary KB entries
  */
 if(!strncmp(name, "/tmp/", 4) ||
    !strncmp(name, "NIDS/", 5) ||
    !strncmp(name, "Settings/", 9))
   	return 0;

 /* Don't save sensitive information */
 if (strncmp(name, "Secret/", 7) == 0)
   return 0;

 /*
  * Avoid duplicates for these families
  */
 if(!strncmp(name, "Success/", strlen("Success/"))   ||
    !strncmp(name, "Launched/", strlen("Launched/")) ||
    !strncmp(name, "SentData/", strlen("SentData/")))
    {
     save_kb_rm_entry(globals, hostname, name);
    }
 
 if(save_kb_entry_present_already(globals, hostname, name, value))
 {
  save_kb_rm_entry_value(globals, hostname, name, value);
 }
   
 str = emalloc(strlen(name) + strlen(value) + 25);
 gettimeofday(&now, NULL);
 sprintf(str, "%ld %d %s=%s\n", (long)now.tv_sec, type, name, value);
 e = write(fd, str, strlen(str));
 if(e < 0)
 {
  log_write("user %s : write kb error - %s\n", (char*)arg_get_value(globals, "user"), strerror(errno));
 }
 efree(&str);
 return 0;
}





/*======================================================================

	                 Public functions
	
 =======================================================================*/

/*------------------------------------------------------------------
  
   Initialize a new KB that will be saved
   
   The indexes of all the opened KB are in a hashlist in 
   globals, saved under the name "save_kb". This makes no sense
   at this time, as the test of each host is done in a separate
   process, but this allows us to regroup easily these in
   the future
   
 -------------------------------------------------------------------*/
int
save_kb_new(globals, hostname)
 struct arglist * globals;
 char * hostname;
{ 
 char * fname;
 char * dir;
 char * user = arg_get_value(globals, "user");
 int ret = 0;
 int f;

 if( hostname == NULL )
    return -1;
 dir = kb_dirname(globals);
 kb_mkdir(dir);
 efree(&dir);
 
 fname = kb_fname(globals, hostname);
 
 if(file_locked(fname))
 {
  efree(&fname);
  return 0;
 }
 unlink(fname); /* delete the previous kb */
 f = open(fname, O_CREAT|O_RDWR|O_EXCL, 0640);
 if(f < 0)
 {
  log_write("user %s : Can not save KB for %s - %s", user, hostname, strerror(errno));
  ret = -1;
  efree(&fname);
  return ret;
 }
 else
 {
  file_lock(fname);
  log_write("user %s : new KB will be saved as %s", user, fname);
  if(arg_get_value(globals, "save_kb"))
    arg_set_value(globals, "save_kb", sizeof(int), (void*)f); 
  else
    arg_add_value(globals, "save_kb", ARG_INT, sizeof(int),(void*)f);
 }
 return 0;
}


void
save_kb_close(globals, hostname)
 struct arglist * globals;
 char * hostname;
{
 int fd = (int)arg_get_value(globals, "save_kb");
 char* fname = kb_fname(globals, hostname);
 if(fd > 0)close(fd);
 file_unlock(fname);
 efree(&fname);
}

/*
 * Returns <1> if we already saved a KB for this host,
 * less than <max_age> seconds ago. If <max_age> is
 * equal to zero, then the age is not taken in account
 * (returns true if a knowledge base exists)
 */
int
save_kb_exists(globals, hostname)
 struct arglist * globals;
 char * hostname;
{
 char * fname = kb_fname(globals, hostname);
 FILE *f;
 
 if(file_locked(fname))
 {
  efree(&fname);
  return 0;
 }
 f = fopen(fname, "r");
 efree(&fname);
 if(!f) return 0;
 else {
 	fclose(f);
 	return 1;
      }
}


int
save_kb_write_str(globals, hostname, name, value)
 struct arglist * globals;
 char * hostname, * name, * value;
{
 char * newvalue  = addslashes(value);
 int e;
 
 e = save_kb_write(globals, hostname, name, newvalue, ARG_STRING);
 efree(&newvalue);
 return e;
}


int
save_kb_write_int(globals, hostname, name, value)
 struct arglist * globals;
 char * hostname, * name;
 int value;
{
 static char asc_value[25];
 int e;
 sprintf(asc_value, "%d", value);
 e = save_kb_write(globals, hostname, name, asc_value, ARG_INT);
 bzero(asc_value, sizeof(asc_value));
 return e;
}





/*
 * Restores a copy of the knowledge base
 */
int
save_kb_restore_backup(globals, hostname)
 struct arglist * globals;
 char*hostname;
{
 char * fname = kb_fname(globals, hostname);
 char * bakname;
 int fd;
 
 bakname = emalloc(strlen(fname) + 5);
 strcat(bakname, fname);
 strcat(bakname, ".bak");
 
 unlink(fname);
 if((fd = open(bakname, O_RDONLY)) >= 0)
 {
  close(fd);
  rename(bakname, fname);
 }
 return 0;
}
/*
 * Makes a copy of the knowledge base
 */

int
save_kb_backup(globals, hostname)
 struct arglist * globals;
 char* hostname;
{
 char * fname = kb_fname(globals, hostname);
 char * newname = NULL;
 int fd_src = -1, fd_dst = -1;
 
 
 if(file_locked(fname))
  {
   log_write("%s is locked\n", fname);
   goto failed1;
  }
 
 file_lock(fname);
 
 newname = emalloc(strlen(fname) + 5);
 strcat(newname, fname);
 strcat(newname, ".bak");
 
 if((fd_src = open(fname, O_RDONLY)) >= 0)
 {
  char buf[4096];
  int n;
  fd_dst = open(newname, O_WRONLY|O_CREAT|O_TRUNC, 0640);
  if(fd_dst < 0)
  { 
   log_write("save_kb_backup failed : %s", strerror(errno));
   close(fd_src);
   goto failed;
  }
  bzero(buf, sizeof(buf));
  while((n = read(fd_src, buf, sizeof(buf))) > 0)
  {
   int m = 0;
   while(m != n)
   {
    int e = write(fd_dst, &(buf[m]), n-m);
    if(e < 0)
     {
     log_write("save_kb_backup failed : %s", strerror(errno));
     close(fd_src);
     close(fd_dst);
     goto failed;
     }
     m+=e;
    } 
    bzero(buf, sizeof(buf));
   }
  }
  else 
    log_write("save_kb_backup failed : %s\n", strerror(errno));
    
  close(fd_src);
  close(fd_dst);
  efree(&newname);
  file_unlock(fname);
  efree(&fname);
  return 0;
failed:
  file_unlock(fname);
failed1:  
  efree(&fname);
  efree(&newname);
  return -1;
}


/*
 * Restores a previously saved knowledge base
 *
 * The KB entry 'Host/dead' is ignored, as well as all the 
 * entries starting by '/tmp/'
 */
struct kb_item ** 
save_kb_load_kb(globals, hostname)
 struct arglist * globals;
 char * hostname;
{
 char * fname = kb_fname(globals, hostname);
 FILE * f;
 int fd;
 struct kb_item ** kb;
 char buf[4096];
 long max_age = save_kb_max_age(globals);
 
 if(file_locked(fname))
 {
  efree(&fname);
  return NULL;
 }
 f = fopen(fname, "r");
 if(!f)
  {
   log_write("user %s : Could not open %s - kb won't be restored for %s\n", (char*)arg_get_value(globals, "user"), fname, hostname);
   efree(&fname);
   return NULL;
  }
 bzero(buf, sizeof(buf));
 fgets(buf, sizeof(buf) - 1, f);
 
 kb  = kb_new();
 /*
  * Ignore the date
  */
 bzero(buf, sizeof(buf)); 
 
 while(fgets(buf, sizeof(buf) - 1, f))
 {
  int type;
  char * name, * value, *t;
  struct timeval then, now;
  
  buf[strlen(buf)-1]='\0'; /* chomp(buf) */
  t = strchr(buf, ' ');
  if(!t)continue;
  
  t[0] = '\0';
  
  then.tv_sec = atol(buf);
  t[0] = ' ';t++;
  type = atoi(t);
  t = strchr(t, ' ');
  if(!t)
	  continue;
  t[0] = ' ';t++;
  name = t;
  t = strchr(name, '=');
  if(!t)continue;
  t[0] = '\0';
  name = strdup(name);
  t[0] = ' ';
  t++;
  value = strdup(t);
  
  if(strcmp(name, "Host/dead") && strncmp(name, "/tmp/", 4) &&
     strcmp(name, "Host/ping_failed"))
  {
   gettimeofday(&now, NULL);
   if(now.tv_sec - then.tv_sec > max_age)
   {
    /* 
    log_write("discarding %s because it's too old\n",
    		name,
    		(now.tv_sec - then.tv_sec));
     */		
   }
   else
   {
    if(type == ARG_STRING)
    {
     char * tmp = rmslashes(value);
     kb_item_add_str(kb, name, tmp);
     efree(&tmp);
    }
    else if(type == ARG_INT)
      kb_item_add_int(kb, name, atoi(value));
   }
  }
  efree(&value);
  efree(&name);
  bzero(buf, sizeof(buf));
 }
 fclose(f);
 
 /*
  * Re-open the file
  */
 fd = open(fname, O_RDWR);
 efree(&fname);
 if(fd > 0)
 {
  lseek(fd, 0, SEEK_END);
  if(arg_get_value(globals, "save_kb"))
     arg_set_value(globals, "save_kb", ARG_INT, (void*)fd);
  else
    arg_add_value(globals, "save_kb", ARG_INT, sizeof(int), (void*)fd);
 }
 else log_write("user %s : ERROR - %s\n", (char*)arg_get_value(globals, "user"), strerror(errno));
 return kb;
}


/*-------------------------------------------------------------------
 * Preferences set by the user
 *-------------------------------------------------------------------*/


/* 
 * Returns <1> if the user wants us the save the knowledge base
 */
int save_kb(globals)
 struct arglist * globals;
{
 struct arglist * preferences;
 char * value;
 
 if(!globals)
  return 0;
  
 preferences = arg_get_value(globals, "preferences");
 if(!preferences)
  return 0;
  
 value = arg_get_value(preferences, "save_knowledge_base");
 
 if(value && !strcmp(value, "yes"))
  return 1;
 
 return 0;
}

/*
 * Returns <1> if we should only test hosts whose knowledge base we
 * already have
 */
int save_kb_pref_tested_hosts_only(globals)
 struct arglist * globals;
{ 
 struct arglist * preferences = arg_get_value(globals, "preferences");
 char * value;
 
 value = arg_get_value(preferences, "only_test_hosts_whose_kb_we_have");
 if(value && !strcmp(value, "yes"))
  return 1;
 
 return 0;
}

/*
 * Returns <1> if we should only test hosts whose kb we DO NOT have
 */
int save_kb_pref_untested_hosts_only(globals)
 struct arglist * globals;
{ 
 struct arglist * preferences = arg_get_value(globals, "preferences");
 char * value;
 
 value = arg_get_value(preferences, "only_test_hosts_whose_kb_we_dont_have");
 if(value && !strcmp(value, "yes"))
  return 1;
 
 return 0;
}

/*
 * Returns <1> if we should restore the KB for the tests
 */
int save_kb_pref_restore(globals)
 struct arglist * globals;
{ 
 struct arglist * preferences = arg_get_value(globals, "preferences");
 char * value;
 
 value = arg_get_value(preferences, "kb_restore");
 if(value && !strcmp(value, "yes"))
  return 1;
 
 return 0;
}

/*
 * Return <1> if this type of plugin can be executed
 */
int save_kb_replay_check(globals, type)
 struct arglist * globals;
 int type;
{
 struct arglist * preferences = arg_get_value(globals, "preferences");
 char * name = NULL;
 char * value;
 switch(type)
 {
  case ACT_SCANNER:
  	name = "kb_dont_replay_scanners";
	break;
  case ACT_GATHER_INFO:
  	name = "kb_dont_replay_info_gathering";
	break;
  case ACT_MIXED_ATTACK:
  case ACT_DESTRUCTIVE_ATTACK:
  case ACT_ATTACK:
  	name = "kb_dont_replay_attacks";
	break;
  case ACT_DENIAL:
  case ACT_KILL_HOST:
  case ACT_FLOOD:
  	name = "kb_dont_replay_denials";
	break;
  /* ACT_SETTINGS and ACT_INIT should always be executed */
 }
 
 if(name)
 {
  value = arg_get_value(preferences, name);
  if(value && !strcmp(value, "yes"))return 0;
 }
 return 1;
}

/*
 * Returns the max. age of the KB, in seconds, as set
 * by the user
 */
long 
save_kb_max_age(globals)
 struct arglist * globals;
{
 struct arglist * prefs = arg_get_value(globals, "preferences");
 long ret = atol(arg_get_value(prefs, "kb_max_age"));
 if(!ret)
  return 3600;
 else
  return ret;
}


/*
 * Differential scans
 *
 *
 * The idea of a differential scan is to only show the user what
 * has changed in the report. To do this, libnessus relies on the content
 * of the Success/... and Failures/... KB entries that record if a test 
 * was sucessful or failed in the past.
 *
 * Note that the KB now contain the full text of the messages sent 
 * back to the client, so libnessus will be able to determine if a message
 * has changed or not (such as a newer FTP version for instance).
 *
 *
 * TODO :
 *    Add 'DataSent/PluginID/Num' entries
 */

int
diff_scan(globals)
 struct arglist * globals;
{
 struct arglist * prefs = arg_get_value(globals, "preferences");
 char * v = arg_get_value(prefs, "diff_scan");

 if(v && !strcmp(v, "yes"))
  return 1;
 else
  return 0;
}


void
diff_scan_enable(pluginargs)
 struct arglist * pluginargs;
{
 arg_add_value(pluginargs, "DIFF_SCAN", ARG_INT, sizeof(int), (void*)1);
}

#endif
