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
 *
 *
 * If we want to scan big networks, nothing should be kept in memory
 * but be stored on disk instead. This also makes the link with
 * a database much easier.
 *
 * "As-is", this modules generates a flat file which is queried as a DB.
 * Users who deal with a huge number of hosts should consider installing
 * a MySQL module.
 */

#include <includes.h>
#include "backend.h"
#include "nsr_output.h"
#include "nbe_output.h"
#include "error_dialog.h"

	
#define MAX_TMPFILES 256
struct backend backends[MAX_TMPFILES];




void be_info(int be, const char * str)
{
#ifdef BACKEND_DEBUG
 printf("%s(%d) disposable:%d, fd:%d, %s\n",
 		str,
 		be,
		backends[be].disposable,
		backends[be].fd,
		backends[be].fname);
#endif
}		

/*--------------------------------------------------------------------*
  	Monitoring functions
----------------------------------------------------------------------*/


int 
backend_init(fname)
 char * fname;
{
 char * tmpfile;
 int i = 0;
 char * tmpdir;
 
 while((backends[i].fname) && (i<MAX_TMPFILES))i++;
 if(backends[i].fname)
  {
   show_error("No free tempfile !\n");
   return -1;
  }
 if(!fname)
 {
 tmpdir = getenv("TMPDIR");
 if(!tmpdir)tmpdir = getenv("TEMPDIR");
 if(!tmpdir)tmpdir = "/tmp";
 
 tmpfile = emalloc(strlen(tmpdir) + strlen("/nessus-XXXXXX") + 1);
 strcat(tmpfile, tmpdir);
 strcat(tmpfile, "/nessus-XXXXXX");
#ifdef HAVE_MKSTEMP
 backends[i].fd = mkstemp(tmpfile);
 if( backends[i].fd >= 0 )
 	fchmod(backends[i].fd, 0600); /* glibc bug */
#else
 mktemp(tmpfile);
 backends[i].fd = open(tmpfile, O_CREAT|O_EXCL|O_RDWR, 0600); 
#endif
 if(backends[i].fd < 0)
 {
   show_error(strerror(errno));
   efree(&tmpfile);
   return -1;
 }
 backends[i].disposable = 1;
 }
 else
 {
  if((backends[i].fd = open(fname,O_RDONLY)) < 0)
   {
   show_error(strerror(errno));
   return -1;
   }
  tmpfile = estrdup(fname);
  backends[i].disposable = 0;
 }
 
 
 backends[i].fname = tmpfile; 
 backends[i].backend_type = BACKEND_NSR;
 
 be_info(i, "BACKEND_INIT");
 
		
 return i;
}





int
backend_fd(be)
{
 return backends[be].fd;
}
 
 
int 
backend_type(be) 
 int be;
{
 return backends[be].backend_type;
}




/*
 * backend_inset_scaninfo_timestamp
 */
int
backend_insert_timestamps(be, host, type, time)
 int be;
 char * host;
 char * type;
 char * time;
{
 lseek(backends[be].fd, 0, SEEK_END);
 if((write(backends[be].fd, "timestamps||", strlen("timestamps||")) < 0)   ||
    (write(backends[be].fd, host, strlen(host)) < 0 )	         	 ||
    (write(backends[be].fd, "|", 1) < 0)			 	 ||
    (write(backends[be].fd, type, strlen(type)) < 0)		 	 ||
    (write(backends[be].fd, "|", 1) < 0)			 	 ||
    (write(backends[be].fd, time, strlen(time)) < 0)		 	 ||
    (write(backends[be].fd, "|", 1) < 0)				 ||
    (write(backends[be].fd, "\n", 1) < 0))
    	{
	perror("write ");
    	return -1;
	}
 else
   return 0;
}

/*
 * backend_write_port is a variation of backend_write(),
 * I should clean that up soon.
 */
int
backend_insert_report_port(be, subnet, host, port)
 int be;
 char * subnet;
 char * host;
 char * port;
{
 lseek(backends[be].fd, 0, SEEK_END);
 if((write(backends[be].fd, "results|", strlen("results|")) < 0)   ||
    (write(backends[be].fd, subnet, strlen(subnet)) < 0) 	 ||
    (write(backends[be].fd, "|", 1) < 0)			 ||
    (write(backends[be].fd, host, strlen(host)) < 0 )	         ||
    (write(backends[be].fd, "|", 1) < 0)			 ||
    (write(backends[be].fd, port, strlen(port)) < 0)		 ||
    (write(backends[be].fd, "\n", 1) < 0))
    	{
	perror("write ");
    	return -1;
	}
 else
   return 0;
}


int
backend_insert_report_data(be, subnet, host, port, script_id, severity, data)
 int be; /* backend */
 char * subnet;
 char * host;
 char * port;
 char * script_id;
 char * severity;
 char * data;
{
  if(!subnet 	||
     !host   	||
     !port   	||
     !script_id	||
     !severity  ||
     !data)
  {
    fprintf(stderr, "backend_insert: some arguments are NULL\n");
     return -1;
  } 
 lseek(backends[be].fd, 0, SEEK_END);
 data = addslashes(data);
 if((write(backends[be].fd, "results|", strlen("results|")) < 0)    ||
    (write(backends[be].fd, subnet, strlen(subnet)) < 0)	    ||
    (write(backends[be].fd, "|", 1) < 0) 			    ||
    (write(backends[be].fd, host, strlen(host)) < 0) 	  	  ||
    (write(backends[be].fd, "|", 1) < 0) 			  ||
    (write(backends[be].fd, port, strlen(port)) < 0)	  	  ||
    (write(backends[be].fd, "|", 1) < 0) 			  ||
    (write(backends[be].fd, script_id, strlen(script_id)) < 0)    ||
    (write(backends[be].fd, "|", 1) < 0)			  ||
    (write(backends[be].fd, severity, strlen(severity)) < 0)      ||
    (write(backends[be].fd, "|", 1) < 0) 			  ||
    (write(backends[be].fd, data, strlen(data)) < 0)		  ||
    (write(backends[be].fd, "\n", 1) < 0))
 {
  perror("write ");
  efree(&data);
  return -1;
 }
 efree(&data);
 return 0;
}

int _backend_cmpcb(void *unused, harglst *not_used, hargkey_t *lKey,
	hargtype_t lType, hargkey_t *rKey, hargtype_t rType) 
{
	unsigned long rin,lin;
	unsigned long rip,lip;
	rin = (unsigned long)inet_addr(rKey);
	lin = (unsigned long)inet_addr(lKey);
	if(rin == 0xffffffff) {
		if(lin == 0xffffffff) {
			return strcmp(rKey,lKey);
		} else {
			return 1;
		}
	} else {
		if(lin == 0xffffffff) {
			return -1;
		} else {
			rip = ntohl(rin);
			lip = ntohl(lin);
			if(lip < rip ) { return 1; }
			if(lip == rip) { return 0; } 
			if(lip > rip)  { return -1; }
		}
	}
	return 0;
}



struct arglist *
backend_convert(be)
 int be;
{
 harglst * hhosts;
 FILE * fd = fopen(backends[be].fname, "r");
 char buf[65535];
 char * current_hostname = NULL;
 struct arglist* current_host = NULL;
 struct arglist * nhosts = NULL;
 char * key;
 int line = 0;
 unsigned x;

 if(!fd)
  {
   perror("fopen ");
   return NULL;
  }
  
 hhosts = harg_create(65000);
 bzero(buf, sizeof(buf));
 
 while(fgets(buf, sizeof(buf) - 1, fd) && !feof(fd))
 {
  char * buffer = NULL;
  struct arglist * host = NULL;
  struct arglist * ports = NULL;
  struct arglist * port = NULL;
  struct arglist * content = NULL;
  char * hostname;
  char * t;
  char * t2;
  char * id = NULL;
  
  
  line++;
  
  /* remove trailing \n */
  buf[strlen(buf) - 1] = '\0'; 
  
  /* skip lines that are not <results> */
  if(strncmp(buf, "results", strlen("results")))
  	continue;
	
  t = strchr(buf, '|');
  if(!t)goto parse_error;
  
 t = strchr(t+1, '|');
 if(!t)goto parse_error;
 
  hostname = &(t[1]);
  t = strchr(t+1, '|');
  if(!t)goto parse_error;
 	
 t[0] = '\0';
 
 if(!current_hostname || strcmp(current_hostname, hostname))
 {
  host = harg_get_ptr(hhosts, hostname);
  if(!host)
  {
   current_host = host = emalloc(sizeof(struct arglist));
   if(current_hostname)efree(&current_hostname);
   current_hostname = estrdup(hostname);
   harg_add_ptr(hhosts, hostname, host);
  }
  else 
   {
    current_host = host;
    if(current_hostname)efree(&current_hostname);
    current_hostname = estrdup(hostname);
   }
  }else
   {
    host = current_host;
   }
  
  t+=sizeof(char);
  /*
   * <port (num/proto)>|<script id>|<REPORT|INFO|NOTE>|<data>
   * ^
   * t is here
   */
   
   t2 = strchr(t, '|');
   if(t2){
    t2[0]='\0';
   }
   
   
  buffer = strdup(t);
  ports = arg_get_value(host, "PORTS");
  if(!ports)
  {
   ports = emalloc(sizeof(struct arglist));
   arg_add_value(host, "PORTS", ARG_ARGLIST, -1, ports);
  }
  
  port = arg_get_value(ports, buffer);
  if(!port)
  {
   port = emalloc(sizeof(struct arglist));
   arg_add_value(ports, buffer, ARG_ARGLIST, -1, port);
  }
  arg_add_value(port, "STATE", ARG_INT, sizeof(int), (void*)1);
  efree(&buffer);
  
  if(!t2 || !t2[1]){
  	bzero(buf, sizeof (buf));
	continue; /* port is open, that's all. */
 	}
  
   t = t2+sizeof(char);
  /*
   *
   */
  t2 = t;
  t = strchr(t2, '|');
  if(!t)continue;
  t[0]='\0';
  if(atoi(t2) > 1000){
	id = strdup(t2);
	}
  else id = strdup("0");
  
  t+=sizeof(char);
  t2 = strchr(t, '|');
  if(!t2)continue;
  t2[0]=0;
   
 
  if(!strcmp(t, "Security Note"))
  	buffer = estrdup("NOTE");
  else if(!strcmp(t, "Security Warning"))	
  	buffer = estrdup("INFO");
  else if(!strcmp(t, "Security Hole"))
  	buffer = estrdup("REPORT");
  else buffer = NULL;
 
  if ( buffer == NULL )
	{
	 fprintf(stderr, "Error - line %d is malformed\n", line);
	 continue;
	}
  content = arg_get_value(port, buffer);
  
  if(!content)
  {
   content = emalloc(sizeof(struct arglist));
   arg_add_value(port, buffer, ARG_ARGLIST, -1, content);
  }
  
  efree(&buffer);
  t2+=sizeof(char);
  buffer  = rmslashes(t2);
  arg_add_value(content, id, ARG_STRING, strlen(buffer),buffer);
  efree(&id);
  bzero(buf, sizeof(buf));
  continue;
parse_error:
 bzero(buf, sizeof(buf));
 fprintf(stderr, "Parse error line <%d>\n", line);
 }
 fclose(fd);
 /*
  *  harglist -> arglist conversion
  */
 harg_csort(hhosts,_backend_cmpcb,"heh");
 harg_sort(hhosts);
 x = 0;
 nhosts = emalloc(sizeof(struct arglist));
 while((key = (char *)harg_get_nth(hhosts,x))) {
  struct arglist * new = emalloc(sizeof(struct arglist));
  struct arglist * h = harg_get_ptr(hhosts, key);
  new->name = strdup(key);
  new->type = ARG_ARGLIST;
  new->length = -1;
  new->value = h;
  new->next = nhosts;
  nhosts = new;
  x++;
 }

 return nhosts;
}

int
backend_close(be)
 int be;
{
 be_info(be, "CLOSE");
 
#ifdef HAVE_MMAP
 if(backends[be].mmap)
 {
  struct stat  buf;
  int len;
  fstat(backends[be].fd, &buf);
  len = (int)buf.st_size;
  munmap(backends[be].mmap, len);
  backends[be].mmap = NULL;
  efree(&backends[be].lines);
  efree(&backends[be].eols);
  backends[be].num_lines = 0;
  
 }
#endif 
 if(backends[be].fd >= 0)
  close(backends[be].fd);
 backends[be].fd = -1;
 return 0;
}

int
backend_dispose(be)
 int be;
{
 int disposable = backends[be].disposable;
 int i;
 
 be_info(be, "DISPOSE");
 
		
 if(backends[be].fd >= 0)
  backend_close(be);
 
 if(disposable)
 {
  unlink(backends[be].fname);
 }
 if(backends[be].fname)
	 bzero(backends[be].fname, strlen(backends[be].fname));
 efree(&(backends[be].fname));

#ifdef HAVE_MMAP 
 efree(&(backends[be].lines));
 efree(&(backends[be].eols));
 if(backends[be].fields)
 {
 for(i=0;i<BE_NUM_FIELDS;i++)
 {
  efree(&(backends[be].fields[i]));
 }
 efree(&(backends[be].fields));
 }
#endif 
 bzero(&(backends[be]), sizeof(backends[be]));
 backends[be].fd = -1;
 return 0; 
}


int
backend_empty(be)
 int be;
{
 FILE * f;
 char buf[32768];
 
 if(backends[be].fname == NULL )
 {
        fprintf(stderr, "NULL backend fname\n");
 	return -1;
 }

 if(backends[be].fd < 0)
 {
  backends[be].fd = open(backends[be].fname, O_RDWR);
 }
 
 if(backends[be].fd < 0)
 {
   fprintf(stderr, "Could not open backend\n");
   return -1;
 }
 
 lseek(backends[be].fd, 0, SEEK_SET);
 f = fdopen(backends[be].fd, "r");
 if ( f == NULL ) 
 {
  fprintf(stderr, "Could not re-open the backend\n");
  return -1;
 }
 
 while(fgets(buf, sizeof(buf) - 1, f) != NULL )
 {
  buf[sizeof(buf) - 1] = '\0';
  if(strncmp(buf, "results", strlen("results")) == 0)
   {
   return 1;
   }
 }
 
 return 0;
}


int
backend_clear_all()
{
 int i;
 for(i=0;i<MAX_TMPFILES;i++)
 {
  if(backends[i].fname)
   backend_dispose(i);
 }
 return 0;
}



int 
backend_import_report(fname)
 char * fname;
{
 char *ext = strrchr(fname, '.');
 if(!ext)
 {
  if(strcmp(fname, "-") == 0)
  {
   return nbe_to_backend(fname); /* for now, we only pipe nbe files via stdin */
  }
  show_error("Unknown report type - please set an extension to the filename");
  return -1;
 }
 
 if(!strcmp(ext, ".nsr"))
 {
  return nsr_to_backend(fname);
 }
 
 if(!strcmp(ext, ".nbe"))
 {
  return nbe_to_backend(fname);
 }
 
 show_error("This file format can not be read back by the Nessus client");
 return -1;
}
