/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 */
 
#include <includes.h>
#include "report.h"
#include "error_dialog.h"
#include "backend.h"
#include "data_mining.h"
#include "report_utils.h"

/*
 * nessusd does not convert the subnet by itself, so we create
 * this record on this fly
 */
static char *
__host2subnet(host)
 char * host;
{
 static char subnet[1024];
 struct in_addr ia;
 bzero(subnet, sizeof(subnet));
 if(inet_aton(host, &ia) == 0)
 {
  char * t;
  /*
   * Not an IP
   */
  t = strchr(host, '.');
  if(t)
	++t;
  else
	t = host;
   strncpy(subnet, t, sizeof(subnet) - 1);
   return subnet;
 }
 else
 {
  /*
   * Is an IP
   */
  char * t = strrchr(host, '.');
  if(t)t[0] = '\0';
  strncpy(subnet, host, sizeof(subnet) - 1);
  if(t)t[0] = '.';
  return subnet;
 }
}



int backend_to_nsr(int, char *);
int nsr_to_backend(char*);


int arglist_to_file(struct arglist * , char * );
int file_to_arglist(struct arglist ** , char * );
int arglist_to_html(struct arglist *, char *);



int nsr_to_backend(filename)
 char * filename;
{
 FILE * f = fopen(filename, "r");
 char buf[32768];
 int be;
 if(!f)
 {
  perror("fopen ");
  show_error("Could not open report");
  return -1;
 }

 be = backend_init(NULL);
 bzero(buf, sizeof(buf));
 while(fgets(buf, sizeof(buf) - 1, f))
 {
  char * t = strchr(buf, '|');
  if(t)
  {
   char* subnet;
   char* hostname = buf;
   char* port;
   char* script_id = "";
   char* severity = "";
   char* data = "";
   
   t[0] = '\0';
   subnet = __host2subnet(hostname);
   port = &(t[1]);
   t = strchr(port, '|');
   if(!t)
   {
    /*
     * It was a port
     */
     backend_insert_report_port(be, subnet, hostname, port);
   }
   else
   {
    t[0] = '\0';
    script_id = &(t[1]);
    t = strchr(script_id, '|');
    if(t)
    {
     t[0] = '\0';
     severity = &(t[1]);
     t = strchr(severity, '|');
     if(t)
     {
      t[0] = '\0';
      data = &(t[1]);
     }
    }
    
    while((t = strchr(data, ';')))t[0] = '\n';
    if(!strcmp(severity, "INFO"))severity = "Security Warning";
    else if(!strcmp(severity, "NOTE"))severity = "Security Note";
    else if(!strcmp(severity, "REPORT"))severity ="Security Hole";
    backend_insert_report_data(be, subnet, hostname, port, script_id, severity, data);
  
   }
  }
 }
 fclose(f);
 return be;
}

extern int	F_quiet_mode;

int backend_to_nsr(be, filename)
 int be;
 char * filename;
{
  int fd;
  struct subset  * sq, *q;
  static cmp_func_t cmp[] = {safe_strcmp};

  if (F_quiet_mode)
    fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
  else
    fd = open(filename, O_RDWR|O_CREAT|O_EXCL, 0600);

 if(fd < 0)
 {
   char	err[1024];
   int	e = errno;
   perror(filename);
   snprintf(err, sizeof(err), "%s: %s", filename, strerror(e));
   show_error(err);
   return -1;
 }

 
 /*
  * Signature
  */

 
 sq = q = subset_uniq(subset_sort(query_backend(be, "SELECT subnet FROM results"), 0, 0, cmp), 0);
 while(q)
 {
  struct subset * sr, *r;
  sr = r = query_backend(be, "SELECT host,port,plugin_id,severity,report FROM results WHERE subnet = '%s'", subset_value(q));
  while(r)
  {
   int i;
   for(i=0;i<5;i++)
   {
    char * data = subset_nth_value(r, i);
    char * t;
  
    while((t = strchr(data, '\n')))t[0] = ';';
    if(i == 3) 
    { 
     if(strstr(data, "Hole"))data = "REPORT";
     else if(strstr(data, "Warning"))data = "INFO";
     else if(strstr(data, "Note"))data = "NOTE";
    }
    write(fd, data, strlen(data));
 
    if(subset_nth_value(r, i+1))write(fd, "|", 1);
    else break;
   }
  write(fd, "\n", 1);
  r = subset_next(r);
  }
  subset_free(sr);
  q = subset_next(q);
 }
 subset_free(sq);
 close(fd);
 return 0; 
}


int 
arglist_to_file(hosts, filename)
 struct arglist * hosts;
 char * filename;
{
 FILE * file;
 
 file = fopen(filename, "w");
 if(!file){
 	show_error("Could not create this file !");
	perror("open "); 
	return(-1);
	}
 while(hosts && hosts->next)
 {
  char * hostname;
  char * port;
  char * desc;
  struct arglist * ports;
  hostname = hosts->name;
  ports = arg_get_value(hosts->value, "PORTS");
  if(ports)
  {
   while(ports && ports->next)
   {
    struct arglist * report;
    struct arglist * info;
    struct arglist * note;
    
    port = ports->name;
    report = arg_get_value(ports->value, "REPORT");
    if(report)while(report->next)
     {
     if(report->name != NULL)
     {
     char * t;
     desc = emalloc(strlen(report->value)+1);
     strncpy(desc, report->value, strlen(report->value));
     while((t = strchr(desc, '\n')))t[0]=';';
     fprintf(file,"%s|%s|%s|REPORT|%s\n", hostname,
     					  port,
     					  strcmp(report->name, "REPORT")?
					  report->name:"", 
					  desc);
     efree(&desc);
     }
     report = report->next;
     } 
   info = arg_get_value(ports->value, "INFO");
   if(info)while(info->next)
    {
     if(info->name != NULL)
     {
     char * t;
     desc = emalloc(strlen(info->value)+1);
     strncpy(desc, info->value, strlen(info->value));
     while((t = strchr(desc, '\n')))t[0]=';';
     fprintf(file,"%s|%s|%s|INFO|%s\n", hostname,
     					port, 
					strcmp(info->name,"INFO")?
					info->name:"", 
					desc);
     efree(&desc);
     }
     info = info->next;
    }

   note = arg_get_value(ports->value, "NOTE");
   if(note)while(note->next)
    {
     if(note->name != NULL)
     {
     char * t;
     desc = emalloc(strlen(note->value)+1);
     strncpy(desc, note->value, strlen(note->value));
     while((t = strchr(desc, '\n')))t[0]=';';
     fprintf(file,"%s|%s|%s|NOTE|%s\n", hostname,
     					port, 
					strcmp(note->name,"NOTE")?
					note->name:"", 
					desc);
     efree(&desc);
     }
     note = note->next;
    }

    if(!report && !info)fprintf(file, "%s|%s|\n", hostname, port);
    ports = ports->next;
   }
  }
  hosts = hosts->next;
 }
 fclose(file);
 return(0);
}


/*
 * File import.
 *
 * In order to speed up the file import, which
 * can take a lot of time when reading an awfully huge
 * file, we first store the data in a hash table, then
 * in an arglist (linked list)
 */
int 
file_to_arglist(hosts, filename)
 struct arglist ** hosts;
 char * filename;
{
 FILE * fd;
 char buf[65535];
 harglst * hhosts = harg_create(65000);
 hargwalk * hw;
 struct arglist * current_host = NULL;
 char * current_hostname = NULL;
 int line = 0;
 char * key;
 struct arglist *nhosts;
 
 if(!filename)
  return -1;
  
 if(!strcmp(filename, "-"))fd = stdin;
 else fd = fopen(filename, "r");
 if(!fd)return(-1);
 
 bzero(buf, sizeof (buf));
 while(fgets(buf, sizeof (buf)-1, fd) && !feof(fd))
 {
  char * buffer = NULL;
  struct arglist * host = NULL;
  struct arglist * ports = NULL;
  struct arglist * port = NULL;
  struct arglist * content = NULL;
  char * t;
  char * t2;
  char* id = NULL;
 
  line++;
  buf[strlen(buf)-1]=0;
  t = strchr(buf, '|');
  if(!t){
  	fprintf(stderr, "** Parse error line %d - ignoring\n", line);
	fprintf(stderr, "buf = <%s>\n", buf);
  	continue;
	}

#ifdef DEBUG_IMPORT	
  if(!(line % 1000))printf("LINE %d\n", line);
#endif  
  t[0]=0;
  if(!current_hostname || strcmp(current_hostname, buf))
  {
  host = harg_get_ptr(hhosts, buf);
  if(!host)
   {
   current_host = host = emalloc(sizeof(struct arglist));
   if(current_hostname)efree(&current_hostname);
   current_hostname = estrdup(buf);
   harg_add_ptr(hhosts, buf, host);
   }
  else {
   	current_host = host;
	if(current_hostname)efree(&current_hostname);
	current_hostname = estrdup(host->name);
       }
  }
  else
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
   if(!t2)continue;
   t2[0]='\0';
   
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
  
  if(!t2[1]){
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
  t[0]=0;
  if(atoi(t2) > 1000){
	id = strdup(t2);
	}
  
  t+=sizeof(char);
  t2 = strchr(t, '|');
  if(!t2)continue;
  t2[0]=0;
   
 
  
  buffer = strdup(t);
  content = arg_get_value(port, buffer);
  
  if(!content)
  {
   content = emalloc(sizeof(struct arglist));
   arg_add_value(port, buffer, ARG_ARGLIST, -1, content);
  }
  
  efree(&buffer);
  t2+=sizeof(char);
  t = t2;
  
  while((t=strchr(t, ';')))t[0]='\n';
  
  buffer = emalloc(strlen(t2)+1);
  strncpy(buffer, t2, strlen(t2));


  arg_add_value(content, id, ARG_STRING, strlen(t2),buffer);
  efree(&id);
  bzero(buf, sizeof (buf));
 }
 fclose(fd);
 
 /*
  *  harglist -> arglist conversion
  */
 hw = harg_walk_init(hhosts);
 nhosts = emalloc(sizeof(struct arglist));
 while((key = (char*)harg_walk_next(hw)))
 {
  struct arglist * new = emalloc(sizeof(struct arglist));
  struct arglist * h = harg_get_ptr(hhosts, key);
  arg_add_value(new, key, ARG_ARGLIST, -1, h);
  efree(&new->next);
  new->next = nhosts;
  nhosts = new;
 }
 /*harg_walk_stop(hw);*/
 harg_close(hhosts);
 *hosts = nhosts;
 return(0);
}
