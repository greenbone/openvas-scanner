/* Nessus
 * Copyright (C) 2000 - 2003 Renaud Deraison
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
 * Professional looking, flashy-flashy report.
 *
 */
 

/*------------------------------------------------------------

	Directory structure :
		
	directory/
		index.html
		pies_*.gif
	
		192_168_x_y/
			index.html
			pie_*.gif
		 .
		 .
		 .
 
 
 The index contains :
 
 	- the global report (html_graph_global_report())
		- percentage of risks severity
		- weaker services
		- services presence
		- Operating System
		- Top 5 of the most dangerous hosts
		- TOC
		
 Each hosts contains :
 	
	- percentage of risks
	- percentage of services that have the biggest number of
	  problem <-
	- HTML report

 -------------------------------------------------------------------*/	
#include <includes.h>
#ifndef HAVE_LIBFREETYPE
/* prevent undefined references in gdc (http://bugs.debian.org/242936) */
# define HAVE_LIBFREETYPE 0
#endif
#include <gdc.h>
#include <gdchart.h>
#include <gdcpie.h>
#include "report.h"
#include "report_utils.h"
#include "error_dialog.h"
#include "globals.h"
#include "nsr_output.h"


static void insert_img(FILE *, char*);



/*
 * Handy functions
 */

static void
insert_img(f, name)
 FILE * f;
 char * name;
{
 fprintf(f, "<br><center><img src=\"%s\" border=\"0\"></center><br>\n", name);
}
 
 
/*---------------------------------------------------------------------------------
 	
	                   Percentage of risk severity
			   
 ---------------------------------------------------------------------------------*/
 
static int risk_severity_by_port(port, risks)
 struct arglist * port;
 float * risks;
{
 struct arglist * holes;
 struct arglist * warnings;
 struct arglist * notes;
 while(port && port->next)
 {

  holes = arg_get_value(port->value, "REPORT");
  warnings = arg_get_value(port->value, "INFO");
  notes = arg_get_value(port->value, "NOTE");

  risks[2] +=  arglist_length(holes);
  risks[1] +=  arglist_length(warnings);
  risks[0] +=  arglist_length(notes);

  port = port->next;
 }
 return 0;     
}

static int risk_severity_by_host(host, risks)
 struct arglist * host;
 float *risks;
{
 if ( host == NULL ) return 0;
 while( host->next != NULL )
 {
  risk_severity_by_port(host->value, risks);
  host = host->next;
 }
 return 0;
}

static int risk_severity(hosts, risks)
 struct arglist * hosts;
 float *risks;
{ 
 int i;
 for ( i = 0; i < 3 ; i ++ ) risks[i] = 0;
 if ( hosts == NULL );

 while( hosts->next != NULL )
 {
  risk_severity_by_host(hosts->value, risks);
  hosts = hosts->next;
 }
 return 0;
} 

/*----------------------------------------------------------------------------
		
		      Most vulnerables services

 -----------------------------------------------------------------------------*/
 


static int 
fill_list_of_services_by_ports(ports, list)
 struct arglist * ports, * list;
{
 char * name = ports->name;
 struct arglist * report;
 struct arglist * elems;
 
  if(!(elems = arg_get_value(list, name)))
  {
   struct arglist * s = emalloc(sizeof(struct arglist));
   arg_add_value(list, name, ARG_ARGLIST, -1, s);
   elems = s;
  }
 
 report = arg_get_value(ports->value, "REPORT");
 if(report)
 {
  while(report && report->next)
  {
   arg_add_value(elems, report->name, ARG_STRING, strlen(report->value), estrdup(report->value));
   report = report->next;
  }
 }
 return 0;
} 

static int 
fill_list_of_services(hosts, list)
 struct arglist * hosts, * list;
{
 while(hosts && hosts->next)
 {
 struct arglist * ports = arg_get_value(hosts->value, "PORTS");
  while(ports && ports->next)
  {
   fill_list_of_services_by_ports(ports, list);
   ports = ports->next;
  }
  hosts = hosts->next;
 }
 return 0;
} 

static int
top_n_most_vulnerable_services(list_services, value, services, n)
 struct arglist * list_services;
 float * value;
 char ** services;
 int n;
{
 while(list_services && list_services->next)
 {
  int len = arglist_length(list_services->value);
  int i;
  

  if(len){
   for(i=0;i<n;i++)
   {
    if(len >= value[i])
     break;
   }
  }
  else i = n;
  
 
  /* 
   * Update our stats 
   */
  if(i < n)
  {
   int j;
   
   for(j=n-1;j>i;j--)
   {
    value[j] = value[j-1];
    efree(&services[j]);
    services[j] = estrdup(services[j-1]);
   }
   value[i] = (float)len;
   efree(&services[i]);
   services[i] = estrdup(list_services->name);
  }
  
  list_services = list_services->next;
  }
  return 0;
}
static int 
most_vulnerable_services(hosts, top_n, services, value)
	struct arglist * hosts;
	int top_n;
	char** services;
	float* value;
{
 struct arglist * list_of_services = emalloc(sizeof(struct arglist));
 
  fill_list_of_services(hosts, list_of_services);
  top_n_most_vulnerable_services(list_of_services, value, services, top_n);
  arg_free_all(list_of_services);
  return 0;

}


/*----------------------------------------------------------------------------
		
		      Most present services 

 -----------------------------------------------------------------------------*/
 


static int 
fill_list_of_services_presence_by_ports(ports, list)
 struct arglist * ports, * list;
{
 char * name = ports->name;
 struct arglist * elems;
 
  if(!(elems = arg_get_value(list, name)))
  {
   struct arglist * s = emalloc(sizeof(struct arglist));
   arg_add_value(list, name, ARG_ARGLIST, -1, s);
   elems = s;
  }
 arg_add_value(elems, "present", ARG_INT, sizeof(int), (void*)1);
 return 0;
} 

static int 
fill_list_of_services_presence(hosts, list)
 struct arglist * hosts, * list;
{
 while(hosts && hosts->next)
 {
 struct arglist * ports = arg_get_value(hosts->value, "PORTS");
  while(ports && ports->next)
  {
   fill_list_of_services_presence_by_ports(ports, list);
   ports = ports->next;
  }
  hosts = hosts->next;
 }
 return 0;
} 

static int
top_n_most_present_services(list_services, value, services, n)
 struct arglist * list_services;
 float * value;
 char ** services;
 int n;
{
 while(list_services && list_services->next)
 {
  int len = arglist_length(list_services->value);
  int i;
  

  if(len){
   for(i=0;i<n;i++)
   {
    if(len >= value[i])
     break;
   }
  }
  else i = n;
  
 
  /* 
   * Update our stats 
   */
  if(i < n)
  {
   int j;
   
   for(j=n-1;j>i;j--)
   {
    value[j] = value[j-1];
    efree(&services[j]);
    services[j] = estrdup(services[j-1]);
   }
   value[i] = (float)len;
   efree(&services[i]);
   services[i] = estrdup(list_services->name);
  }
  list_services = list_services->next;
  }
  return 0;
}
static int 
most_present_services(hosts, top_n, services, value)
	struct arglist * hosts;
	int top_n;
	char** services;
	float* value;
{
 struct arglist * list_of_services = emalloc(sizeof(struct arglist));
 
 
  fill_list_of_services_presence(hosts, list_of_services);
  top_n_most_present_services(list_of_services, value, services, top_n);
  arg_free_all(list_of_services);
  return 0;
}




/*----------------------------------------------------------------------------

			Operating systems
			
-----------------------------------------------------------------------------*/




static void
fill_operating_systems_list(hosts, list)
 struct arglist * hosts, * list;
{
 while(hosts && hosts->next)
 {
  struct arglist * p = arg_get_value(hosts->value, "PORTS");
  if(p)
  {
   p = arg_get_value(p, "general/tcp");
   if(p)
   {
    p = arg_get_value(p, "INFO");
    if(p)
    {
     while(p && p->next)
     {
      if(strstr(p->value, "Nmap found"))
      {
       /* got it */
       char * name = p->value;
       struct arglist * al;
       name += strlen("Nmap found that this host is running ");
       
        al = arg_get_value(list, name);
	if(!al)
	{
	 al = emalloc(sizeof(struct arglist));
	 arg_add_value(list, name, ARG_ARGLIST, -1, al);
	}
        arg_add_value(al,"count", ARG_INT, sizeof(int), (void*)1); 
       }
      p = p->next;
     }
    }
   }
  }
  hosts = hosts->next;
 }
}


static int
top_n_operating_systems(list_services, value, services, n)
 struct arglist * list_services;
 float * value;
 char ** services;
 int n;
{
 while(list_services && list_services->next)
 {
  int len = arglist_length(list_services->value);
  int i;
  

  if(len){
   for(i=0;i<n;i++)
   {
    if(len >= value[i])
     break;
   }
  }
  else i = n;
  
 
  /* 
   * Update our stats 
   */
  if(i < n)
  {
   int j;
   
   for(j=n-1;j>i;j--)
   {
    value[j] = value[j-1];
    efree(&services[j]);
    services[j] = estrdup(services[j-1]);
   }
   value[i] = (float)len;
   efree(&services[i]);
   services[i] = estrdup(list_services->name);
  }
  list_services = list_services->next;
  }
  return 0;
}


static void 
most_used_operating_systems(hosts, names, values, n)
 struct arglist * hosts;
 char ** names;
 float * values;
 int n;
{
 struct arglist * list = emalloc(sizeof(struct arglist));
 fill_operating_systems_list(hosts, list);
 top_n_operating_systems(list, values, names, n);
 arg_free_all(list);
}
	
/*----------------------------------------------------------------------------

			Single host report
			
-----------------------------------------------------------------------------*/
/* All the cross references (CVE, BID) have the same format - XREF: <num>,...<br> */
static char * 
extract_xref(file, str, url)
 FILE * file;
 char * str, * url;
{
 while(str != NULL && strncmp(str, "<br>", 4) != 0)
   {
    char * e1 = strchr(str, ',');
    char * e2 = strchr(str, '<');
    char tmp = '\0';
    if((e1 > e2) || (e1 == NULL))e1 = e2;
   
   
    if(e1 != NULL)
    {
     tmp = e1[0];
     e1[0] = '\0';
    }
    fprintf(file, "<a href=\"%s%s\">%s</a>", url, str, str);
    str = e1;
    if(e1 != NULL)
    {
     e1[0] = tmp;
   
     if(tmp == ','){
     	fputc(',', file);
	fputc(' ', file);
	str ++;
	str ++;
	}
     else
        fputc('<', file);
    }
   }
  return str;
}
 
static void 
print_data_with_links(file, str, plugin_id)
 FILE * file;
 char * str, * plugin_id;
{
 while(str != NULL && str[0] != '\0')
 {
  if(strncmp(str, "http:", 5) == 0 || strncmp(str, "https:", 6) == 0 )
  {
   char * e1, * e2;
   char tmp = 0;
   
   e1 = strchr(str, ' ');
   e2 = strstr(str, "<br>");
   if((e1 > e2) || (e1 == NULL))e1 = e2;
   
   if(e1 != NULL)
   {
    tmp = e1[0];
    e1[0] = '\0';
   }
   fprintf(file, "<a href=\"%s\">%s</a>", str, str);
   str += strlen(str) - 1;
   if(e1 != NULL)
   {
    e1[0] = tmp;
   }
  }
  else if(strncmp(str, "CVE : ", 6) == 0)
  {
   fprintf(file, "CVE : ");
   str += 6;
   str = extract_xref(file, str, "http://cgi.nessus.org/cve.php3?cve=");
  }
  else if(strncmp(str, "BID : ", 6) == 0)
  {
  fprintf(file, "BID : ");
  str += 6;
  str = extract_xref(file, str, "http://cgi.nessus.org/bid.php3?bid=");
  }
  else fputc(str[0], file);
  if ( str != NULL ) str++;
 }
 
 fprintf(file, "Nessus ID : <a href=\"http://cgi.nessus.org/nessus_id.php3?id=%s\">%s</a>", plugin_id, plugin_id);
}

static char * convert_cr_to_html(str)
 char * str;
{
 int num = 0;
 char * t;
 char * ret;
 int i, j = 0;
 /*
  * Compute the size we'll need
  */
  
  t = str;
  while(t[0])
  {
   if((t[0]=='\n')||(t[0]=='>')||(t[0]=='<'))num++;
   t++;
  }
 
  ret = emalloc(strlen(str)+5*num+1);
  for(i=0, j=0;str[i];i++,j++)
  {
   if(str[i]=='\n'){
   	ret[j++]='<';
	ret[j++]='b';
	ret[j++]='r';
	ret[j++]='>';
	ret[j]='\n';
	}
   else if(str[i]=='>') {
    	ret[j++]='&';
	ret[j++]='g';
	ret[j++]='t';
	ret[j]=';';
	}
  else if(str[i]=='<')
  	{
	ret[j++]='&';
	ret[j++]='l';
	ret[j++]='t';
	ret[j]=';';
	}
  else ret[j] = str[i];
  }
  return ret;
}


   
static char * portname_to_ahref(name, hostname)
 char * name;
 char * hostname;
{
  char *t, *k;

  /*
   * Convert '192.168.1.1' to '192_168_1_1' or
   * 'prof.nessus.org' to 'prof_nessus_org'
   */
  hostname = 
    t = estrdup (hostname) ;
  while ((t = strchr (t, '.')) != 0)
    t [0] = '_' ;
  if (name == 0)
    return hostname ;

  /*
   * Convert 'telnet (21/tcp)' to '21_tcp'
   */
  name =
    k = estrdup (name);
  if ((t = strrchr (k, '(')) != 0) 
    k = t + 1;
  if ((t = strchr (k, ')')) != 0)
    t [0] = '\0' ;
  while ((t = strchr (k, '/')) != 0)
    t [0] = '_' ;
 
  /*
   * append: "name" + "_" + "hostname"
   */
  t = emalloc (strlen (hostname) + strlen (k) + 15);
  strcat (strcat (strcpy (t, hostname), "_"), k);
  efree (&hostname);
  efree (&name);
  return t ;
}


  

static int 
host_details(file, hosts)
 FILE * file;
 struct arglist * hosts;
{
 char * hostname;
 char * port;
 char * desc;
 struct arglist * ports;
 char * name;
 struct arglist * next_al;
 char * next = NULL;
 char * next_name = NULL;
 next_al = hosts->next;
 if(next_al && next_al->next)
 {
  char * t;
  next = strdup(next_al->name);
  next_name = strdup(next);
  while((t = strchr(next, '.')))t[0]='_';
 }
 
 if(next)
 {
  fprintf(file, "[<a href=\"../%s/index.html\">Next host : %s</a>]<p>\n",
  		next, next_name);
 }
 else
   fprintf(file, "[<a href=\"../index.html\">Back to the index</a>]<p>\n");
 hostname = hosts->name;
 ports = arg_get_value(hosts->value, "PORTS");
 name = portname_to_ahref("toc", hostname);
 fprintf(file, "<a name=\"%s\"></a>\n", name);
 efree(&name);

 if(ports)
 {
  struct arglist * open = ports;
  if(open->next)
  {
  
    fprintf(file, "List of open ports :<p>\n");
 
    fprintf(file, "<ul><ul><i>\n");
    while(open && open->next){
    	name = portname_to_ahref(open->name, hostname);
	if(name)
	{
	if(arg_get_value(open->value, "REPORT") ||
	   arg_get_value(open->value, "INFO") ||
	   arg_get_value(open->value, "NOTE"))
	   {
	     fprintf(file, "<li><a href=\"#%s\">%s</a>\n",
	   		name, open->name);
	     if(arg_get_value(open->value, "REPORT")){
	      fprintf(file, "<FONT COLOR=\"#FF0000\"> (Security hole found)</FONT>\n");
	     }		
	     else if (arg_get_value(open->value, "INFO")) fprintf(file, "<FONT COLOR=\"#660000\"> (Security warnings found)</FONT>\n");
	     else fprintf(file, " (Security notes found)\n");
	   }	 
	 else		  
		fprintf(file, "<li>%s\n", open->name);
	efree(&name);
	}
	 else fprintf(file, "<li>%s\n", open->name);
	open = open->next;
      }
    fprintf(file, "</i></ul></ul><p><p>\n");
   }
  /*
   * Write the summary of the open ports here
   */
   while(ports && ports->next)
   {
    struct arglist * report;
    struct arglist * info;
    struct arglist * note;
    port = ports->name;
    report = arg_get_value(ports->value, "REPORT");
    if(report)while(report && report->next)
     {
     char * name = portname_to_ahref(ports->name, hostname);
     fprintf(file, "<a name=\"%s\"></a>",name);
     efree(&name);
     if(strlen(report->value))
     {
      
     /*
      * Convert the \n to <p> 
      */
     desc = convert_cr_to_html(report->value);
     name = portname_to_ahref("toc", hostname);
          
     fprintf(file, "<font size=\"-1\"><div align=\"right\"><a href=\"#%s\">\
[ back to the list of ports ]</a></div></font><p>\n",
      		name);
      efree(&name);		
      fprintf(file, "<FONT COLOR=\"#FF0000\">");
      fprintf(file, "<b>Vulnerability found on port %s</b></FONT><p><ul>\n",port);
      print_data_with_links(file, desc, report->name);
      fprintf(file, "<p></ul>\n");
      efree(&desc);
     }
      report = report->next;

     }
   info = arg_get_value(ports->value, "INFO");
   if(info)while(info && info->next)
    {
     if(!report){
      	char * name = portname_to_ahref(ports->name, hostname);
     	fprintf(file, "<a name=\"%s\"></a>",name);
	efree(&name);
	}
     if(strlen(info->value))
     {
     char * name;
     desc = emalloc(strlen(info->value)+1);
     strncpy(desc, info->value, strlen(info->value));
     /*
      * Convert the \n to <p> 
      */
     desc = convert_cr_to_html(info->value); 
     name = portname_to_ahref("toc", hostname);
     fprintf(file, "<FONT SIZE=\"-1\"><div align=\"right\"><a href=\"#%s\">\
[ back to the list of ports ]</a></div></FONT><p>\n",
      		name);
      fprintf(file, "<FONT COLOR=\"#660000\">");		
     fprintf(file, "<b>Warning found on port %s</b></FONT><p><ul><p>\n", port);
     efree(&name);	
     print_data_with_links(file, desc, info->name);
     fprintf(file, "<p></ul>\n");
     efree(&desc);
     }  
     info = info->next;
    }
   note = arg_get_value(ports->value, "NOTE");
   if(note)while(note && note->next)
    {
     if(!report){
      	char * name = portname_to_ahref(ports->name, hostname);
     	fprintf(file, "<a name=\"%s\"></a>",name);
	efree(&name);
	}
     if(strlen(note->value))
     {
     char * name;
     desc = emalloc(strlen(note->value)+1);
     strncpy(desc, note->value, strlen(note->value));
     /*
      * Convert the \n to <p> 
      */
     desc = convert_cr_to_html(note->value); 
     name = portname_to_ahref("toc", hostname);
     fprintf(file, "<FONT SIZE=\"-1\"><div align=\"right\"><a href=\"#%s\">\
[ back to the list of ports ]</a></div></FONT><p>\n",
      		name);
     fprintf(file, "<b>Information found on port %s</b><p><ul><p>\n", port);
     efree(&name);	
     print_data_with_links(file, desc, note->name);
     fprintf(file, "<p></ul>\n");
     efree(&desc);
     }  
     note = note->next;
    }

    ports = ports->next;
   }
  }
  fprintf(file, "</ul>\n");
 if(next)
 {
  fprintf(file, "[<a href=\"../%s/index.html\">Next host : %s</a>]<p>\n",
  		next, next_name);
  free(next);
  if(next_name)free(next_name);
 }
 fprintf(file, "<hr>\n");
 fprintf(file, "<i>This file was generated by <a href=\"http://www.nessus.org\">");
 fprintf(file, "Nessus</a>, the open-sourced security scanner.</i>\n");
 fprintf(file, "</BODY></HTML>");
 return(0);
}


static char * 
create_host_report(struct arglist * host)
{
 char * name;
 char * t;
 float * risks = emalloc(sizeof(float)*6);
 float total;
 FILE * f;
 
 if(!host)
  	return NULL;
 name = estrdup(host->name);
 /*
  * 192.168.1.6 -> 192_168_1_6
  */
 while((t=strchr(name, '.')))t[0]='_';
 
 mkdir(name, 0750);
 chdir(name);
 
 /*
  * Risks severity
  */
    
 risk_severity_by_port(arg_get_value(host->value, "PORTS"), risks);
 total = risks[0] + risks[1] + risks[2] + risks[3];

 f = fopen("index.html", "w");
 if(f)
 {
   char * lbl[] = {"Low/Info", "Medium", "High"};
   int	expl[] = { 0, 0, 0, 20};

   unsigned long   clr[] = { 0x80FF80L, 0xFFFF80L, 0xFF80FFL, 0xFF4040L};
   int risk_count = 4;
   int non_zero_risks = 0;
  
   FILE * pie;
   fprintf(f, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n");
   fprintf(f, "<HTML><HEAD><TITLE>%s</TITLE></HEAD>\n", host->name);
   fprintf(f, "<BODY TEXT=\"#000000\" BGCOLOR=\"#FFFFFF\" LINK=\"#3333FF\" VLINK=\"#551A8B\" ALINK=\"#FF0000\">");
   fprintf(f, "<CENTER><b><H1>%s</H1></b></CENTER><P>\n", host->name);
   fprintf(f, "<ul>\n");
   fprintf(f, "Repartition of the level of the security problems : <br>\n");
   fprintf(f, "<ul>\n");
   /*
    * Make a pie
    */
    if(total > 1)
    {
    pie = fopen("pie_risks.gif", "wb");
    GDCPIE_other_threshold = -1;
    
    GDCPIE_title = "Security Risks";
    GDCPIE_label_line = TRUE;
    GDCPIE_label_dist = 15;
    GDCPIE_LineColor = 0x000000L;
    GDCPIE_PlotColor =  0xC0C0C0L;
    GDCPIE_EdgeColor = GDC_NOCOLOR; /* http://bugs.debian.org/326502 */
    GDCPIE_label_size = GDC_SMALL;
    GDCPIE_title_size = GDC_MEDBOLD;
    GDCPIE_3d_angle  = 45;
    if ( total > 1 ) GDCPIE_explode   = expl;
    GDCPIE_Color = clr;
    GDCPIE_BGColor = 0xFFFFFFL;
    GDC_generate_gif = TRUE;
    GDC_hold_img = GDC_DESTROY_IMAGE;
    GDC_image = NULL;
    GDC_image_type = GDC_GIF;
    GDCPIE_missing = NULL;
    GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;
    GDCPIE_percent_fmt = " (%.0f%%)";

    /* remove zero elements */
    {
     int j;
     for (j=0; j<risk_count; j++)
     {
      if ( risks[j]  == 0) { 
        int i;
	for(i=j;i<risk_count - 1;i++)
	{
         risks[  i ] = risks[ i + 1 ];
         clr[ i ]   = clr[ i + 1 ];
         lbl[ i ]   = lbl[ i + 1 ];
	}
      } else {
       non_zero_risks++;
      }
     }
    }
    if (non_zero_risks>1) { /* is 1 or more as total > 0 */
     expl[non_zero_risks-1] = 20;
    }
    
    
    risk_count = non_zero_risks;

    pie_gif(480, 360, pie, GDC_3DPIE, risk_count, lbl, risks);
    fclose(pie);
   insert_img(f, "pie_risks.gif");
   }
  fprintf(f, "</ul>\n");
  fprintf(f, "</ul>\n");
  fprintf(f, "<hr>\n");
  host_details(f, host);
 
    
  fclose(f);
 }
 free(risks);
 chdir("..");
 return name;
}
 
/*----------------------------------------------------------------------------

		              Make the global index

------------------------------------------------------------------------------*/
static int html_make_index(hosts)
 struct arglist * hosts;
{
 FILE * f = fopen("index.html", "w");
 int n;
 
 if(!f)
  return -1;
 
 
 
 /*
  * Title
  */
  
 fprintf(f, "<HTML><HEAD><TITLE>Nessus Report</TITLE></HEAD>\n");
 fprintf(f, "<BODY TEXT=\"#000000\" BGCOLOR=\"#FFFFFF\" LINK=\"#3333FF\" VLINK=\"#551A8B\" ALINK=\"#FF0000\">");
 fprintf(f, "<CENTER><b><H1>Nessus Report</H1></b></CENTER><P><hr><p>\n");

 

 
 /*
  * Summary
  */ 

 fprintf(f, "&#160;&#160;&#160;&#160;&#160;&#160;&#160;\n");
 n = arglist_length(hosts);
 fprintf(f, "The Nessus Security Scanner was used to assess the security of %d host%s<br>\n",
 		n,n>1?"s":"");
 fprintf(f, "<ul>\n");
 n = number_of_holes(hosts);
 if(n)fprintf(f, "<li><FONT COLOR=\"#FF0000\"><b> %d security hole%s %s been found</b></FONT>\n",
 					n, n>1?"s":"", n>1?"have":"has");

 n = number_of_warnings(hosts);
 fprintf(f, "<li><b><FONT COLOR=\"#660000\"> %d security warning%s %s been found</b></FONT>\n",
 					n, n>1?"s":"", n>1?"have":"has");
					
 n = number_of_notes(hosts);
 fprintf(f, "<li><b> %d security note%s %s been found</b>\n",
 					n, n>1?"s":"", n>1?"have":"has");
					

 fprintf(f, "</ul><br>\n<hr>\n");
 

 fprintf(f, "<H2>Part I : Graphical Summary :</H2><p>\n");
 /*
  * Risk severity
  */
  {
 
   float risks_f[3];
   char * lbl[] = {"Low/Info", "Medium", "High"};
   int expl [] = {0,0,0};
   unsigned long   clr[] = { 0x80FF80L, 0xFFFF80L, 0xFF4040L};
   FILE * pie;
   int num_risks = 0;
   int i;
   
   risk_severity(hosts, risks_f);
   for(i=0;i<3;i++)
   {
    if(risks_f[i] == 0)
    {
     int j;
     for(j=i;j<3;j++)
     {
     risks_f[j] = risks_f[j + 1];
     lbl[j] = lbl[j + 1];
     clr[j] = clr[j + 1];
     }
    }
    else num_risks ++;
   }
   
   expl[num_risks-1] = 20;
   
   if(num_risks > 1)
   {			
    pie = fopen("pie_risks.gif", "wb");
    GDCPIE_title = "Security Risks";
    GDCPIE_other_threshold = -1;
    GDCPIE_label_line = TRUE;
    GDCPIE_label_dist = 15;
    GDCPIE_LineColor = 0x000000L;
    GDCPIE_label_size = GDC_SMALL;
    GDCPIE_explode   = expl;
    GDCPIE_Color = clr;
    GDCPIE_BGColor = 0xFFFFFFL;
    GDCPIE_EdgeColor = GDC_NOCOLOR; /* http://bugs.debian.org/326502 */
    GDCPIE_missing = NULL;
    GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;
    GDCPIE_percent_fmt = " (%.0f%%)";
    GDC_image_type = GDC_GIF;
    pie_gif(480, 360, pie, GDC_3DPIE, num_risks, lbl, risks_f);
    fclose(pie);
    insert_img(f, "pie_risks.gif");
    }
  }
 

  /*
   * Most vulnerables services
   */
   {
    int n = 10; /* top ten */
    char ** services = emalloc((n+1) * sizeof(char*));
    float * value = emalloc(n*sizeof(float));
    int num = 0;
    int i;
    unsigned long color = 0xFF4040L;
    FILE * chart = fopen("chart_dangerous_services.gif", "wb");
    most_vulnerable_services(hosts, n, services, value);
    while(services[num] && (num < n))num++;
    
    /*
     * Ok, we now have data of the <num> most vulnerables
     * services
     */
     if(num)
     {
     GDC_title = "Most dangerous services on the network :";
     GDC_ytitle = "Number of holes";
     GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
     GDC_LineColor = 0x000000L;                  /* line color      (black) */
     GDC_SetColor = &(color);
     GDC_image_type = GDC_GIF;
     out_graph(480, 360, chart, GDC_3DBAR, num, services, 1, value);
     fclose(chart);
     insert_img(f, "chart_dangerous_services.gif");
     for(i=0;i<num;i++)free(services[i]);
     }
    }

   /*
    * Most present services
    */
    {
    int n = 10; /* top ten */
    char ** services = emalloc((n+1) * sizeof(char*));
    float * value = emalloc(n*sizeof(float));
    int num = 0;
    int i;
    unsigned long color[1] = {0x8080FFL};
    FILE * chart = fopen("chart_services_occurences.gif", "wb");
    most_present_services(hosts, n, services, value);
    while(services[num] && (num < n))num++;
   
    if(num)
    {
    /*
     * Ok, we now have data of the <num> most vulnerables
     * services
     */
    
     GDC_title = "Services that are the most present on the network :";
     GDC_ytitle = "Number of occurences";
     GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
     GDC_LineColor = 0x000000L;                  /* line color      (black) */
     GDC_SetColor = color;
     GDC_image_type = GDC_GIF;
     out_graph(480, 360, chart, GDC_3DBAR, num, services, 1, value);
     fclose(chart);
     insert_img(f, "chart_services_occurences.gif");
     for(i=0;i<num;i++)free(services[i]);
     }
    }
    
   /*
    * Top 10 in operating systems
    */
    {
    int n = 10; /* top ten */
    char ** oses = emalloc((n+1) * sizeof(char*));
    float * value = emalloc(n*sizeof(float));
    int num = 0;
    unsigned long color = 0xFFFF80L;
    FILE * chart = fopen("chart_operating_systems.gif", "wb");
    most_used_operating_systems(hosts, oses, value, n);
    while(oses[num] && (num < n))num++;
    
    /*
     * Ok, we now have data of the <num> most vulnerables
     * services
     */
    if(num)
     {
     GDC_title = "Operating systems present on the network :";
     GDC_ytitle = "Number of occurences";
     GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
     GDC_LineColor = 0x000000L;                  /* line color      (black) */
     GDC_SetColor = &(color);
     GDC_image_type = GDC_GIF;
     out_graph(480, 360, chart, GDC_3DBAR, num, oses, 1, value);
     fclose(chart);
     insert_img(f, "chart_operating_systems.gif");
     }
    }
    
   /*
    * Most dangerous host
    */
   { 
    struct arglist * most = most_dangerous_host(hosts);
    float total;
    float host_weight;
    float values[2];
    char * names[2];
    int expl [] = {0,20};
     unsigned long   clr[] = {  0xFF4040L, 0xFFFF80L};
  
    if(most)
    {
     FILE * pie;
    
    total = (float)number_of_holes(hosts) + (float)number_of_warnings(hosts);
    host_weight = (float)number_of_holes_by_host(most->value) +
    		  (float)number_of_warnings_by_host(most->value);

    if(total)
    {		  
    values[0] = (host_weight * 100) / total;	  
    values[1] = 100 - values[0];
    }
    else
    { 
      values[0] = 0;
      values[1] = 100;
    }
    names[0] = most->name;
    names[1] = "Others";


    if (values[1] != 0 && total > 1 )
    {
    pie = fopen("pie_most.gif", "wb");
    GDCPIE_other_threshold = -1;
    GDCPIE_title = "Most dangerous host weight in the global insecurity";
    GDCPIE_label_line = TRUE;
    GDCPIE_label_dist = 15;
    GDCPIE_LineColor = 0x000000L;
    GDCPIE_label_size = GDC_SMALL;
    GDCPIE_explode   = expl;
    GDCPIE_Color = clr;
    GDCPIE_BGColor = 0xFFFFFFL;
    GDCPIE_EdgeColor = GDC_NOCOLOR; /* http://bugs.debian.org/326502 */
    GDCPIE_missing = NULL;
    GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;
    GDCPIE_percent_fmt = " (%.0f%%)";
    GDC_image_type = GDC_GIF;
    pie_gif(480, 360, pie, GDC_3DPIE, 2,names, values);
    fclose(pie);
    insert_img(f, "pie_most.gif");
     }
    }
    }
   /*
    * Toc
    */
 
    fprintf(f, "<hr>\n");
    fprintf(f, "<H2>Part II. Results, by host : </H2><br>\n");
    fprintf(f, "<ul>\n");
    fprintf(f, "<center><table border=\"0\">\n");
    fprintf(f, "<tr>\n");
    fprintf(f, "<td background=\"#000000\">");
    fprintf(f, "<font color=\"#ffffff\">");
    fprintf(f, "Host name</font></td>\n");
    fprintf(f, "<td background=\"#000000\">");
    fprintf(f, "<font color=\"#ffffff\">");
    fprintf(f, "Notes</font></td>\n");
    fprintf(f, "</tr>\n");
    while(hosts && hosts->next)
    {
     char * name = create_host_report(hosts);
     int holes;
     int warnings;
     int notes;
     holes = number_of_holes_by_host(hosts->value);
     warnings = number_of_warnings_by_host(hosts->value);
     notes = number_of_notes_by_host(hosts->value);
     fprintf(f, "<tr>\n");
     fprintf(f, "<td>\n");
     fprintf(f, "<a href=\"%s/index.html\">%s</a></td>\n", name, hosts->name);
     if(holes)fprintf(f, "<td><FONT COLOR=\"#FF0000\">(<b>found %d security hole%s)</b></FONT></td>\n",
 					holes, holes>1?"s":"");
     else if(warnings)fprintf(f, "<td><FONT COLOR=\"#660000\">(<b>found %d security warning%s</b>)</FONT></td>\n",
 					warnings, warnings>1?"s":"");
     else if(notes)fprintf(f, "<td>(<b>found %d security note%s</b>)</td>\n",
 					notes, notes>1?"s":"");
          else fprintf(f, "\n");
     efree(&name);
     hosts = hosts->next;
     fprintf(f, "</tr>\n");
    }
    fprintf(f, "</table></center>\n");
    fprintf(f, "</ul>\n");
    /*
     * Appendix
     */
     
     fprintf(f, "<hr>\n");
     fprintf(f, "<i>This file was generated by </i><a href=\"http://www.nessus.org\">");
     fprintf(f, "Nessus</a>,<i> the open-sourced security scanner.</i>\n");
     fprintf(f, "</BODY></HTML>");
     fclose(f);
     return 0;
}											  
int arglist_to_html_graph(hosts, directory)
 struct arglist * hosts;
 char *  directory;
{

 /* 
  * Remove the trailing slashes if any
  */
 while(directory[strlen(directory)-1]=='/')directory[strlen(directory)-1]='\0';
 
 
 if(mkdir(directory, 0750)<0)
 {
  show_error(strerror(errno));
  return -1;
 }
 
 if(chdir(directory)<0)
 {
  show_error(strerror(errno));
  return -1;
 }
 
 /*
  * First of all, save the .nsr file. This stuff is still in beta
  */
 arglist_to_file(hosts, "report.nsr"); 
 if(html_make_index(hosts)<0)
 {
  show_error(strerror(errno));
  return -1;
 }

 return 0;
}


 
