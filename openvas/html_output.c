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
 * Output modified by Isaac Dawson of Security Management Partners. 
 *
 * changes to generate valid html: Axel Nennker axel@nennker.de
 * 20020919 see: http://validator.w3.org/file-upload.html
 *  - an attribute vaule must be quoted if it contains any character
 *    other than letters(A-Za-z), digits, hyphens and periods
 *  - added charset iso-8859-1
 * 20020924 Axel Nennker axel@nennker.de
 *  some more fixes for valid html4.0
 *
 */
 
#include <includes.h>
#include "report.h"
#include "report_utils.h"
#include "error_dialog.h"
#include "globals.h"


static char * convert_cr_to_html(char *);
static char * portname_to_ahref(char *, char *);
void summary_to_file(FILE *, struct arglist *);


/*
 * Handy functions
 */
 
 
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
  t = emalloc (strlen (hostname) + strlen (k) + 2);
  strcat (strcat (strcpy (t, hostname), "_"), k);
  efree (&hostname);
  efree (&name);
  return t ;
}


  

int 
arglist_to_html(hosts, filename)
 struct arglist * hosts;
 char * filename;
{
 FILE * file;
 struct arglist * h;
 
 if(!strcmp(filename, "-"))file = stdout;
 else file = fopen(filename, "w");
 if(!file){
 	show_error("Could not create this file !");
	perror("fopen ");
	return(-1);
	}

 /* Print the Style Sheet Opts and Report Summary */
 summary_to_file(file, hosts);

 h = hosts;


 /* Loop through hosts and print out their problems "Host List"*/
 while(h && h->next)
 {
  int result;
  char * href = portname_to_ahref(NULL, h->name);
  fprintf(file, "   <tr>\n\t <td class=default width=\"60%%\"><a href=\"#%s\">%s</a></td>\n", href, h->name);
  result = is_there_any_hole(h->value);
 
  if(result == HOLE_PRESENT) 
 	fprintf(file, "\t<td class=default width=\"40%%\"><font color=red>Security hole(s) found</font></td></tr>\n");
  else if(result == WARNING_PRESENT)
	fprintf(file, "\t<td class=default width=\"40%%\">Security warning(s) found</td></tr>\n");
  else if(result == NOTE_PRESENT)
	fprintf(file, "\t<td class=default width=\"40%%\">Security note(s) found</td></tr>\n");
  else fprintf(file, "\t<td class=default width=\"40%%\">No noticeable information found</td></tr>\n");
  efree(&href);
  h = h->next;
 }
 fprintf(file, "</tbody></table></td></tr></tbody></table>\n\n");
 /* Finish printing Host list */



 /* Enter crazy loop for hosts and specific issues */
 while(hosts && hosts->next)
 {
  char * hostname;
  char * port;
  char * desc;
  struct arglist * ports;
  char * href;
  char * name;
  hostname = hosts->name;

  href = portname_to_ahref(NULL, hostname);
  fprintf(file, "<a name=\"%s\"></a>\n", href);
  efree(&href);
  name = portname_to_ahref("toc", hostname);
  fprintf(file, "<a name=\"%s\"></a>\n", name);
  efree(&name);

  fprintf(file, "<div align=\"left\"><font size=-2><a href=\"#toc\">[ return to top ]</a></font></div><br><br>\n");
  fprintf(file, "<table bgcolor=\"#a1a1a1\" border=0 cellpadding=0 cellspacing=0 width=\"60%%\">\n");
  fprintf(file, "<tbody><tr><td>\n   <table cellpadding=2 cellspacing=1 border=0 width=\"100%%\">\n");
  fprintf(file, "   <tbody>\n   <tr>\n\t<td class=title colspan=3>Analysis of Host</td></tr>\n");
  fprintf(file, "   <tr>\n\t<td class=sub width=\"20%%\">Address of Host</td>\n");
  fprintf(file, "\t<td class=sub width=\"30%%\">Port/Service</td>\n");
  fprintf(file, "\t<td class=sub width=\"30%%\">Issue regarding Port</td></tr>\n");

  
  ports = arg_get_value(hosts->value, "PORTS");
  if(ports)
  {
     struct arglist * open = ports;
     if(open->next)
     {
  
        while(open && open->next){
        	name = portname_to_ahref(open->name, hostname);
	  if(name)
	  {
	      if(arg_get_value(open->value, "REPORT") ||
	         arg_get_value(open->value, "INFO") ||
	         arg_get_value(open->value, "NOTE")) 
	      {
	             fprintf(file, "   <tr>\n\t<td class=default width=\"20%%\">%s</td>\n", hostname);
	             fprintf(file, "\t<td class=default width=\"30%%\"><a href=\"#%s\">%s</a></td>\n",
	   		name, open->name);
	             if(arg_get_value(open->value, "REPORT")) fprintf(file, "\t<td class=default width=\"30%%\"><font color=red>Security hole found</font></td></tr>\n");
	             else if(arg_get_value(open->value, "INFO")) fprintf(file, "\t<td class=default width=\"30%%\">Security warning(s) found</td></tr>\n");
	             else fprintf(file, "\t<td class=default width=\"30%%\">Security notes found</td></tr>\n");
		
	      }	 
	        else {	
		     fprintf(file, "   <tr>\n\t<td class=default width=\"20%%\">%s</td>\n", hostname);
		     fprintf(file, "\t<td class=default width=\"30%%\">%s</td>\n\t<td class=default width=\"30%%\">No Information</td></tr>\n", open->name);
	      }
	      efree(&name);
	  }
	    else {
	        	fprintf(file, "   <tr>\n\t<td class=default width=\"20%%\">%s</td>\n", hostname);
                        fprintf(file, "\t<td class=default width=\"30%%\">%s</td>\n\t<td class=default width=\"30%%\">No Information</td></tr>\n", open->name);
	    }
	  open = open->next;
       }
    fprintf(file, "</tbody></table></td></tr></tbody></table><br><br>\n");
   }

   fprintf(file, "<table bgcolor=\"#a1a1a1\" cellpadding=0 cellspacing=0 border=0 width=\"75%%\">\n");
   fprintf(file, "<tbody><tr><td>\n");
   fprintf(file, "\t<table cellpadding=2 cellspacing=1 border=0 width=\"100%%\">\n");
   fprintf(file, "\t\t<td class=title colspan=3>Security Issues and Fixes: %s</td></tr>\n", hostname);
   fprintf(file, "\t\t<tr>\n\t<td class=sub width=\"10%%\">Type</td>\n");
   fprintf(file, "\t\t<td class=sub width=\"10%%\">Port</td>\n");
   fprintf(file, "\t\t<td class=sub width=\"80%%\">Issue and Fix</td></tr>\n");

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
     if(strlen(report->value))
     {
     /*
      * Convert the \n to <p> 
      */
      desc = convert_cr_to_html(report->value);
      name = portname_to_ahref("toc", hostname);
      efree(&name);		
      fprintf(file, "\t\t<tr>\n\t<td valign=top class=default width=\"10%%\"><font color=red>Vulnerability</font></td>\n");

      name = portname_to_ahref(ports->name, hostname);
      fprintf(file, "\t\t<td valign=top class=default width=\"10%%\"><a name=\"%s\"></a>%s</td>\n", name, port);
      efree(&name);

      fprintf(file, "\t\t<td class=default width=\"80%%\">"); 	
      print_data_with_links(file, desc, report->name);
      fprintf(file, "\t</td></tr>\n");
      efree(&desc);
     }
      report = report->next;
     }
   info = arg_get_value(ports->value, "INFO");
   if(info)while(info && info->next)
    {
     if(strlen(info->value))
     {
     /*
      * Convert the \n to <p> 
      */
     desc = convert_cr_to_html(info->value); 
     name = portname_to_ahref("toc", hostname);
      efree(&name); 
      fprintf(file, "   <tr>\t\n<td valign=top class=default width=\"10%%\">Warning</td>\n");

      name = portname_to_ahref(ports->name, hostname);
      fprintf(file, "\t<td valign=top class=default width=\"10%%\"><a name=\"%s\"></a>%s</td>\n", name, port);
      efree(&name);
      
     fprintf(file, "\t<td class=default width=\"80%%\">");
     print_data_with_links(file, desc, info->name);
     fprintf(file, "</td></tr>\n");
     efree(&desc);
     }  
     info = info->next;
    }

   note = arg_get_value(ports->value, "NOTE");
   if(note)while(note->next)
    {
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
      efree(&name); 
      fprintf(file, "   <tr>\n\t<td valign=top class=default width=\"10%%\">Informational</td>\n");

      name = portname_to_ahref(ports->name, hostname);
      fprintf(file, "\t<td valign=top class=default width=\"10%%\"><a name=\"%s\"></a>%s</td>\n", name, port);
      efree(&name);

      fprintf(file, "\t<td class=default width=\"80%%\">");
     print_data_with_links(file, desc, note->name);
     fprintf(file, "</td></tr>\n");
     efree(&desc);
     }  
     note = note->next;
    }
    ports = ports->next;
   }
  }
  fprintf(file, "</td></tr></tbody></table></td></tr></tbody></table>\n");
  hosts = hosts->next;
 }
 fprintf(file, "<hr>\n");
 fprintf(file, "<i>This file was generated by <a href=\"http://www.nessus.org\">");
 fprintf(file, "Nessus</a>, the open-sourced security scanner.</i>\n");
 fprintf(file, "</BODY>\n");
 fprintf(file, "</HTML>\n");
 fclose(file);
 return(0);
}


void summary_to_file(FILE *file, struct arglist *hosts)
{

 fprintf(file, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n");
 fprintf(file, "<HTML>\n");
 fprintf(file, " <HEAD>\n");
 fprintf(file, " <TITLE>Nessus Scan Report</TITLE>\n");
 fprintf(file, " <meta http-equiv=\"Content-Type\" content=\"text/html; charset=\"iso-8859-1\">\n");
 fprintf(file, " <style type=\"text/css\">\n");
 fprintf(file, " <!--\n");
 fprintf(file, "  BODY {\n\tBACKGROUND-COLOR: #ffffff\n }\n");
 fprintf(file, "  A {\tTEXT-DECORATION: none }\n");
 fprintf(file, "  A:visited {\tCOLOR: #0000cf; TEXT-DECORATION: none }\n");
 fprintf(file, "  A:link {\tCOLOR: #0000cf; TEXT-DECORATION: none }\n");
 fprintf(file, "  A:active {\tCOLOR: #0000cf; TEXT-DECORATION: underline }\n");
 fprintf(file, "  A:hover {\tCOLOR: #0000cf; TEXT-DECORATION: underline }\n");
 fprintf(file, "  OL {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  UL {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  P {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  BODY {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  TD {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  TR {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  TH {\tCOLOR: #333333; FONT-FAMILY: tahoma,helvetica,sans-serif }\n");
 fprintf(file, "  FONT.title {\tBACKGROUND-COLOR: white; COLOR: #363636; FONT-FAMILY: \
                  tahoma,helvetica,verdana,lucida console,utopia; FONT-SIZE: 10pt; FONT-WEIGHT: bold }\n");
 fprintf(file, "  FONT.sub {\tBACKGROUND-COLOR: white; COLOR: #000000; FONT-FAMILY: \
                  tahoma,helvetica,verdana,lucida console,utopia; FONT-SIZE: 10pt }\n");
 fprintf(file, "  FONT.layer {\tCOLOR: #ff0000; FONT-FAMILY: courrier,sans-serif,arial,helvetica; FONT-SIZE: 8pt; TEXT-ALIGN: left }\n");
 fprintf(file, "  TD.title {\tBACKGROUND-COLOR: #A2B5CD; COLOR: #555555; FONT-FAMILY: \
                  tahoma,helvetica,verdana,lucida console,utopia; FONT-SIZE: 10pt; FONT-WEIGHT: bold; HEIGHT: 20px; TEXT-ALIGN: right }\n");
 fprintf(file, "  TD.sub {\tBACKGROUND-COLOR: #DCDCDC; COLOR: #555555; FONT-FAMILY: \
                  tahoma,helvetica,verdana,lucida console,utopia; FONT-SIZE: 10pt; FONT-WEIGHT: bold; HEIGHT: 18px; TEXT-ALIGN: left }\n");
 fprintf(file, "  TD.content {\tBACKGROUND-COLOR: white; COLOR: #000000; FONT-FAMILY: \
                  tahoma,arial,helvetica,verdana,lucida console,utopia; FONT-SIZE: 8pt; TEXT-ALIGN: left; VERTICAL-ALIGN: middle }\n");
 fprintf(file, "  TD.default {\tBACKGROUND-COLOR: WHITE; COLOR: #000000; FONT-FAMILY: \
                  tahoma,arial,helvetica,verdana,lucida console,utopia; FONT-SIZE: 8pt; }\n");
 fprintf(file, "  TD.border {\tBACKGROUND-COLOR: #cccccc; COLOR: black; FONT-FAMILY: \
                  tahoma,helvetica,verdana,lucida console,utopia; FONT-SIZE: 10pt; HEIGHT: 25px }\n");
 fprintf(file, "  TD.border-HILIGHT {\tBACKGROUND-COLOR: #ffffcc; COLOR: black; FONT-FAMILY: \
                  verdana,arial,helvetica,lucida console,utopia; FONT-SIZE: 10pt; HEIGHT: 25px }\n");
 fprintf(file, "-->\n</style>\n");
 fprintf(file, "</HEAD>\n");
 fprintf(file, "<BODY>\n");
 fprintf(file, "<table bgcolor=\"#a1a1a1\" border=0 cellpadding=0 cellspacing=0 width=\"95%%\">\n");
 fprintf(file, "<tbody>\n\t<tr><td>\n<table border=0 cellpadding=2 cellspacing=1 width=\"100%%\">\n");
 fprintf(file, "\t<tbody>\n   <tr>\n");
 fprintf(file, "\t<td class=title>Nessus Scan Report</td></tr>\n");
 fprintf(file, "   <tr>\n\t<td class=content>This report gives details on hosts that were tested\n");
 fprintf(file, "\t\tand issues that were found. Please follow the recommended\n");
 fprintf(file, "\t\tsteps and procedures to eradicate these threats.\n");
 fprintf(file, "</td></tr></tbody></table></td></tr></tbody></table><br>\n");
 fprintf(file, "\n");


 /*
  * Write a (small) summary Hosts that are up, holes/warnings ect.
  */
 fprintf(file, "<table bgcolor=\"#a1a1a1\" border=0 cellpadding=0 cellspacing=0  width=\"60%%\">\n");
 fprintf(file, "<tbody><tr><td>\n");
 fprintf(file, "    <table border=0 cellpadding=2 cellspacing=1 width=\"100%%\">\n   <tbody>\n");
 fprintf(file, "    <tr>\n\t<td class=title colspan=2>Scan Details</td></tr>\n");
 fprintf(file, "    <tr>\n\t<td class=default width=\"60%%\">Hosts which were alive and responding during test</td>\n");
 fprintf(file, "\t<td class=default width=\"30%%\">%d</td></tr>\n",
                                arglist_length(hosts));

 fprintf(file, "   <tr>\n\t<td class=default width=\"60%%\">Number of security holes found</td>\n");
 fprintf(file, "\t<td class=default width=\"30%%\">%d</td></tr>\n",
                                number_of_holes(hosts));
 fprintf(file, "   <tr>\n\t<td class=default width=\"60%%\">Number of security warnings found</td>\n");
 fprintf(file, "\t<td class=default width=\"30%%\">%d</td></tr>\n",
                                number_of_warnings(hosts));
 fprintf(file, "</tbody></table></td></tr></tbody></table><br><br>\n");

 fprintf(file, "<a name=\"toc\"></a>");

 fprintf(file, "<table bgcolor=\"#a1a1a1\" border=0 cellpadding=0 cellspacing=0  width=\"60%%\">\n");
 fprintf(file, "<tbody><tr><td>\n   <table border=0 cellpadding=2 cellspacing=1 width=\"100%%\">\n");
 fprintf(file, "   <tbody>\n   <tr>\n\t<td class=title colspan=2>Host List</td></tr>\n");
 fprintf(file, "   <tr>\n\t<td class=sub width=\"60%%\">Host(s)</td>\n");
 fprintf(file, "\t<td class=sub width=\"40%%\">Possible Issue</td></tr>\n");

}
