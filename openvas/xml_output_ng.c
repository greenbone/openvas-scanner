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
 * TODO :
 * - add name and ip in <host .../>
 * - <status />
 *
 * Author: Guillaume Valadon <guillaume@valadon.net>
 *
 * Layout: Lionel Cons <lionel.cons@cern.ch>
 *
 * Layout changes and XML compliance fixes: 
 *  Dmitriy Kropivnitskiy <nigde@mitechki.net>
 *  Axel Nennker <axel@nennker.de> 20020310
 */


#include <includes.h>
#include <stdarg.h>

#include "report.h"
#include "error_dialog.h"
#include "backend.h"
#include "data_mining.h"
#include "globals.h"
#include "report_utils.h"

int backend_to_xml_ng (int, char *);

static void xml_info (int, FILE*, int);
static void xml_config (FILE*, int);
static void xml_plugins (FILE*, int);
static void fprintf_report (FILE*, char*, char*);
static char * ne_strcasestr (char*, char *);
static char * escape_string (char*);

/* Play with 'name(port/proto)' (ex: 'www(80/tcp)') */
static char* getname (char *str);
static char* getport (char *str);
static char* getproto (char *str);
static char* getrisk (char*);

#ifndef XML_INDENT
#define XML_INDENT "\t"
#endif

static int 
xml_fprintf( FILE* fd, int indent, char* fmt, ... )
{
 va_list ap;
 int i = (indent>=0)?indent:0;
 int ret = 0;

 for (; i; i--) {
  fprintf( fd, "%s", XML_INDENT ); 
 }
 va_start(ap,fmt);
 ret = vfprintf( fd, fmt, ap );
 va_end(ap);
 if (ret>0) ret += indent; 
 return ret;
} /* xml_fprintf */

static char * 
ne_strcasestr(char * haystack, char * needle)
{
 int len_h = strlen(haystack);
 int len_needle = strlen(needle);
 
 while(len_h >= len_needle)
 {
  if(!strncasecmp(haystack, needle, len_needle))
   return haystack;
  else
  {
   len_h --;
   haystack++;
  }
 }
 return NULL;
} /* ne_strcasestr */



static char * escape_string (char * str)
{
 char *ret, *temp;
 int i, y, len;

 temp = str;
 ret = emalloc (5*strlen(temp)+1);
 len = strlen (str);

 bzero( ret, 5*strlen(temp)+1 );

 for (i=0,y=0;i<len;i++,y++)
 {
  switch (temp[i])
  {
   case '>':
    ret = strcat (ret, "&gt;"); 	y+=3;
    break;

   case '<':
    ret = strcat (ret, "&lt;"); 	y+=3;
    break;

   case '&':
    ret = strcat (ret, "&amp;"); 	y+=4;
    break;
    
   case '\"':
     ret = strcat(ret, "&quot;"); 	y += 5;
     break;
   
   case '\'' : 
      ret = strcat(ret, "&apos;"); 	y += 5;
      break;

   default: 
    ret[y] = temp[i];
  }
 }

 ret = (char*) erealloc (ret, strlen (ret)+1);
 if (!ret) {
  fprintf( stderr, "realloc failed" );
 }
 return ret;
} /* escape_string */

static void
xml_fprintf_element (FILE *fd, int indent, char *tag, char *value)
{
 int i = (indent>=0)?indent:0;
 char *escstr = NULL;

 for (; i; i--) {
  fprintf( fd, "%s", XML_INDENT ); 
 }
 if (!value) {
    fprintf (fd, "<%s></%s>\n", tag, tag);
    return;
 }
 if (strlen(value)==0) {
    fprintf (fd, "<%s></%s>\n", tag, tag);
    return;
 }
 escstr =  escape_string(value);
 if (escstr == NULL) {
    fprintf (fd, "<%s></%s>\n", tag, tag);
    return;
 }
 
 fprintf (fd, "<%s>%s</%s>\n", tag, escstr, tag);
 efree(&escstr);
} /* xml_fprintf_element */

static void
xml_info_host (int be, FILE* fd, int indent, struct arglist * t)
{
 xml_fprintf (fd, indent, "<host>\n");
 if (First_time)
 {
  t = Prefs;
  if (t)
  {
   xml_fprintf_element (
    fd, indent+1, "name", (char *) arg_get_value (t, "openvasd_host")); 
  }
 }
 else
  xml_fprintf (fd, indent+1, 
   "<error txt=\"No server name information (not connected ?).\"/>\n");

 t = arg_get_value(Prefs, "SERVER_INFO");
 if (t)
 {
  xml_fprintf_element (fd, indent+1, "osname", (char *) arg_get_value (t, "server_info_os"));
  xml_fprintf_element (fd, indent+1, "osvers", (char *) arg_get_value (t, "server_info_os_version"));
 }
 xml_fprintf (fd, indent, "</host>\n");
} /* xml_info_host */

static void
xml_info_date (
int be, 
FILE* fd, 
int indent, 
struct arglist * t)
{
 struct subset * s;

 xml_fprintf (fd, indent, "<date>\n");
 s = query_backend(be, "SELECT date FROM timestamps WHERE type = 'scan_start'");
 if (s && subset_size (s) != 0)
 { 
  xml_fprintf_element (fd, indent+1, "start", subset_value (s));
 }
 else
  xml_fprintf (fd, indent+1, "<error txt=\"No scan start date.\"/>\n");
 
 s = query_backend(be, "SELECT date FROM timestamps WHERE type = 'scan_end'");
 if (s && subset_size (s) != 0)
 { 
 xml_fprintf_element (fd, indent+1, "end", subset_value (s));
 }
 else
 xml_fprintf (fd, indent+1, "<error txt=\"No scan end date.\"/>\n");
 
 xml_fprintf (fd, indent, "</date>\n");
} /* xml_info_date */

static void
xml_info_openvasd (int be, FILE* fd, int indent, struct arglist * t)
{
 if (t)
 {
  xml_fprintf (fd, indent, "<openvasd>\n");
  xml_fprintf_element (fd, indent+1, "version", (char *) arg_get_value (t, "server_info_openvasd_version"));
  xml_fprintf_element (fd, indent+1, "libnasl", (char *) arg_get_value (t, "server_info_libnasl_version"));
  xml_fprintf_element (fd, indent+1, "libnessus", (char *) arg_get_value (t, "server_info_libnessus_version"));
  xml_fprintf_element (fd, indent+1, "thread", (char *) arg_get_value (t, "server_info_thread_manager"));
  xml_fprintf (fd, indent, "</openvasd>\n");
 } else {
  show_error("xml_output: No openvasd informations.\n");
  xml_fprintf (fd, indent, "<openvasd>\n");
  xml_fprintf (fd, indent+1, "<!-- no version information found -->\n");
  xml_fprintf (fd, indent, "</openvasd>\n");
 }
} /* xml_info_openvasd */

static void
xml_info (int be, FILE* fd, int indent)
{
 struct arglist * t;
 t = arg_get_value(Prefs, "SERVER_INFO");

 if (t)
 {
  xml_fprintf (fd, 2, "<info>\n");
   xml_info_openvasd(be, fd, indent+1, t);
   xml_info_host(be, fd, indent+1, t);
   xml_info_date(be, fd, indent+1, t);
  xml_fprintf (fd, 2, "</info>\n\n");
 } else {
  fprintf (stderr, "xml_output: No SERVER_INFO found.\n");
  xml_fprintf (fd, 2, "<info>\n");
   xml_fprintf (fd, indent+1, "<!-- no version information found -->");
  xml_fprintf (fd, 2, "</info>\n\n");
 }
} /* xml_info */

static void
xml_config_scanners (FILE* fd, int indent, struct arglist* t)
{
  xml_fprintf (fd, indent, "<scanners>\n");
  while( t->next != NULL )
  {
        char* esc_name = escape_string(t->name);
	xml_fprintf (fd, indent+1, "<plugin id=\"%s\" value=\"%s\"/>\n", esc_name, (t->value?"yes":"no"));
        efree(&esc_name);
	t = t->next;
  }
  xml_fprintf (fd, indent, "</scanners>\n\n");
} /* xml_config_scanners */

static void
xml_config_global_pref (FILE* fd, int indent, char *name, char *value)
{
  char* esc_name = escape_string(name);
  char* esc_value = escape_string(value);
  xml_fprintf (fd, indent+1, 
   "<pref name=\"%s\" value=\"%s\" />\n", esc_name, esc_value);
  efree(&esc_name);
  efree(&esc_value);
} /* xml_config_global_pref */

static void
xml_config_global (FILE* fd, int indent, struct arglist* t)
{
  xml_fprintf (fd, indent, "<global> ");
  while( t->next != NULL )
  {
    if (t->type == ARG_STRING) {
      xml_config_global_pref(fd, indent+1, t->name, t->value);
    } else if (t->type == ARG_INT) {
      xml_config_global_pref(fd, indent+1, t->name, (t->value)?"yes":"no");
    }
    t = t->next;
  } /* while */
  fprintf (fd, "</global>\n");
} /* xml_config_global */

static void
xml_setting(FILE* fd, int indent, char* name, char* value)
{
 char* esc_name = escape_string(name);
 char* esc_value = escape_string(value);;
 xml_fprintf (fd, indent, 
  "<setting name=\"%s\" value=\"%s\"/>\n", esc_name, esc_value);
 efree(&esc_name);
 efree(&esc_value);
} /* xml_setting */

static void
xml_config_plugins (FILE* fd, int indent, struct arglist* t)
{
  xml_fprintf (fd, indent, "<plugins>\n");
  while( t->next )
  {
   if (t->type == ARG_STRING)
     xml_setting (fd, indent+1, t->name, (char *) t->value);
   else if (t->type == ARG_INT)
     xml_setting (fd, indent+1, t->name, (t->value?"yes":"no"));
   t = t->next;
  }
  xml_fprintf (fd, indent, "</plugins>\n\n");
} /* xml_config_server */

static void
xml_config_server (FILE* fd, int indent, struct arglist* t)
{
  xml_fprintf (fd, indent, "<server>\n");
  while( t->next )
  {
   if(strcmp(t->name, "plugin_set") != 0)
   {
   if (t->type == ARG_STRING)
    xml_setting (fd, indent+1, t->name, (char *) t->value);
   else if (t->type == ARG_INT)
    xml_setting (fd, indent+1, t->name, (t->value?"yes":"no"));
  }
   t = t->next;
  }
  xml_fprintf (fd, indent, "</server>\n\n");
} /* xml_config_server */

static void
xml_config (FILE* fd, int indent)
{
  struct arglist * t;
  
  xml_fprintf (fd, indent, "<config>\n");

  t = Prefs;
  if (t)
  {
   xml_config_global (fd, indent+1, t);
  }

  t = arg_get_value(Prefs, "SCANNER_SET");
  if (t)
  {
   xml_config_scanners(fd, indent+1, t);
  }

  t = arg_get_value(Prefs, "SERVER_PREFS");
  if (t)
  {
   xml_config_server(fd, indent+1, t);
  }

  t = arg_get_value(Prefs, "PLUGINS_PREFS");
  if (t)
  {
   xml_config_plugins(fd, indent+1, t);
  }

  xml_fprintf (fd, indent, "</config>\n\n");
}

static void 
xml_plugins_plugin (FILE* fd, int indent, struct arglist * u)
{ 

     xml_fprintf (fd, indent, "<plugin id=\"%d\">\n", (int) arg_get_value (u, "ID"));
     xml_fprintf_element (fd, indent+1, "name", (char *) arg_get_value (u, "NAME"));
     xml_fprintf_element (fd, indent+1, "version", (char *) arg_get_value (u, "VERSION"));
     xml_fprintf_element (fd, indent+1, "family", (char *) arg_get_value (u, "FAMILY"));
     xml_fprintf_element (fd, indent+1, "cve_id", (char *) arg_get_value (u, "CVE_ID"));
     xml_fprintf_element (fd, indent+1, "bugtraq_id", (char *) arg_get_value (u, "BUGTRAQ_ID"));
     xml_fprintf_element (fd, indent+1, "category", (char *) arg_get_value (u, "CATEGORY"));
     xml_fprintf_element (fd, indent+1, "risk",  getrisk((char*)arg_get_value (u, "DESCRIPTION")));
     xml_fprintf_element (fd, indent+1, "summary", arg_get_value (u, "SUMMARY"));
     xml_fprintf_element (fd, indent+1, "copyright", (char *) arg_get_value (u, "COPYRIGHT"));
     xml_fprintf (fd, indent, "</plugin>\n\n");
} /* xml_plugins_plugin */

static void 
xml_plugins (FILE* fd, int indent)
{ 
 struct arglist * t;

 xml_fprintf (fd, indent, "<plugins>\n");

  t = Scanners;
  if (t && t->type == ARG_ARGLIST)
  {
  while (t->next)
  {
     struct arglist * u = t->value;
     if (arg_get_value (u, "ENABLED"))
     {
      xml_plugins_plugin(fd, indent+1, u);
     }

    t = t->next;
    }
  }
  else
   xml_fprintf (fd, indent+1, "<error txt=\"No scanners list.\"/>\n");

  t = Plugins;
  if (t && t->type == ARG_ARGLIST)
  {
  while (t->next)
  {
     struct arglist * u = t->value;
     if (arg_get_value (u, "ENABLED"))
     {
      xml_plugins_plugin(fd, indent+1, u);
     }

    t = t->next;
    }
  }
  else
   xml_fprintf (fd, indent+1, "<error txt=\"No plugins list.\"/>\n");

  xml_fprintf (fd, indent, "</plugins>\n\n");
}


static char *
getrisk (char * str)
{
 char *bck=emalloc (255*sizeof (char)),*ret;
 int i=0;
 if ((ret=ne_strcasestr (str, "Risk Factor : ")) != NULL)
 {
  strncpy (bck, &ret[14], 255);
  while (i < 255 && bck[i] != '/' && isalpha (bck[i])) i++;
  bck[i]='\0';
  return bck;
 }
 else
 {
  return strcpy (bck, "Unknown");
 }
}


static char* 
getname (char *str)
{
 int i=0, offset=0, len=strlen (str);
 char *ret = emalloc (len);
 for (i=0;i<len; i++)
  if (str[i] !=  '(' && str[i] != ' ') ret[offset++] = str[i]; 
  else break;

 ret[offset] = '\0';
 return ret;
}

static char*
getport (char *str)
{
 int i=0, offset=0, len=strlen (str);
 char *ret = emalloc (len);
 for (i=0;i<len; i++)
  if (str[i] == '(') break;
 i++;
 for (i=i;i<len; i++)
  if (str[i] != '/') ret[offset++] = str[i];
  else break;
 ret[offset] = '\0';
 return ret;
}

static char*
getproto (char *str)
{
 int i=0, offset=0, len=strlen (str);
 char *ret = emalloc (len);
 for (i=0;i<len; i++)
  if (str[i] == '(') break;
 i++;
 for (i=0;i<len; i++)
  if (str[i] == '/') break;
 i++;
 for (i=i;i<len; i++)
  if (str[i] != ')') ret[offset++] = str[i];
  else break;

 ret[offset] = '\0';
 return ret;
}

static void
fprintf_report (FILE* fd, char* marge, char* report)
{
 int i=0;
 int len =  strlen(report);
 fputc('\n', fd);
 fputs(marge, fd);

 for (i=0;i<len;i++)
 {
  if (report[i]=='\n') {
  	fputc('\n', fd);
	fputs(marge, fd);
	}
  else fputc (report[i], fd);
 }
  fputc ('\n', fd);
}

static void
xml_results_result_ports( 
 FILE* fd, 
 int indent, 
 int be, 
 struct subset * h, 
 struct subset  *q)
{
  struct subset * sp, *p; /* set of ports */
  cmp_func_t cmp[] = {safe_strcmp};

   sp = p = subset_uniq(subset_sort(query_backend(be, "SELECT port FROM results WHERE host = '%s' AND subnet = '%s'", subset_value (h), subset_value (q)), 0, 0, cmp), 0);
   xml_fprintf (fd, indent, "<ports>\n");
   
   while(p)
   {
    struct subset * si, * i;

    si = i = query_backend(be, "SELECT severity,plugin_id,report FROM results WHERE port = '%s' AND host = '%s' AND subnet = '%s'", subset_value (p), subset_value (h), subset_value (q));

    /* port a la nmap 
    <port protocol="tcp" portid="445"><state state="closed" />
     <service name="microsoft-ds" method="table" conf="3" />
    </port>
    */

    if (subset_size (i) != 0)
    { 
     char* portprotostr; 
     char* portnamestr;
     char* portnumberstr;
 
     portnumberstr = getport (subset_value (p));
     portprotostr = getproto (subset_value (p));
     if (portnumberstr && (atoi(portnumberstr) > 0)) {
      xml_fprintf (fd, indent+1, 
       "<port protocol=\"%s\" portid=\"%s\">\n", portprotostr, portnumberstr);
     } else {
      xml_fprintf (fd, indent+1, 
       "<port protocol=\"%s\">\n", portprotostr);
     }
     efree (&portprotostr);
     efree (&portnumberstr);

     portnamestr = getname (subset_value (p));
     xml_fprintf (fd, indent+2, "<service name=\"%s\" method=\"nessus\" conf=\"3\" />\n", portnamestr);
     efree (&portnamestr);

     while (i)
     {
	   
      if (subset_nth_value(i, 1) && strncmp (subset_nth_value (i, 1), "", 1) != 0)
      {
       char * free;

       xml_fprintf (fd, indent+2, "<information>\n");
       xml_fprintf_element (fd, indent+3, "severity", subset_nth_value (i, 0));
       xml_fprintf_element (fd, indent+3, "id", subset_nth_value (i, 1));
       xml_fprintf (fd, indent+3, "<data>\n");
       free = escape_string (subset_nth_value (i,2));
       fprintf_report (fd, "\t\t\t\t\t\t\t",  free);
       efree (&free);
       xml_fprintf (fd, indent+3, "</data>\n");
       xml_fprintf (fd, indent+2, "</information>\n");
      }

      i = subset_next (i); 
     } /* while */
     xml_fprintf (fd, indent+1, "</port>\n");
    }
     else {
     	char * port;
	char * protocol;
	char * portnamestr;
	
	port = getport(subset_value(p));
	protocol = getproto(subset_value(p));
	portnamestr = getname(subset_value(p));
        xml_fprintf(fd, indent + 1, "<port protocol=\"%s\" portid=\"%s\">\n", protocol, port);
        xml_fprintf(fd, indent + 2, "<service name=\"%s\" method=\"nessus\" conf=\"3\" />\n", portnamestr);
        efree(&portnamestr);
        efree(&port);
        efree(&protocol);
	xml_fprintf (fd, indent+1, "</port>\n");
      }

    subset_free(si);
    p = subset_next(p);
   } /* while */

   xml_fprintf (fd, indent, "</ports>\n");
  subset_free(sp);
} /* xml_results_result_ports */

static void
xml_results_result( 
 FILE* fd, int indent, int be, struct subset * h, struct subset  *q )
{
  struct subset * st, * t;
  char *start = NULL, *end = NULL;
  int i=0;

  xml_fprintf (fd, indent, "<result>\n");
  xml_fprintf (fd, indent, 
   "<host name=\"%s\" ip=\"%s\"/>\n", subset_value (h), subset_value (h));
  st = t =query_backend (be, 
   "SELECT date,type FROM timestamps WHERE host = '%s'", subset_value (h));

  if (subset_size (t) == 2)
  { 
   for (i=0; i<2; i++)
   {
    if (t)
    {
    if (!strcmp (subset_nth_value (t, 1), "host_start"))
     start = subset_nth_value (t, 0);	   
    else
     if (!strcmp (subset_nth_value (t, 1), "host_end"))
      end = subset_nth_value (t, 0);	   
    t = subset_next(t);
    }
    else break;
   }
  xml_fprintf (fd, indent+1, "<date>\n");
  xml_fprintf_element (fd, indent+2, "start", start);
  xml_fprintf_element (fd, indent+2, "end", end);
  xml_fprintf (fd, indent+1, "</date>\n");
  }
  else
  {
   xml_fprintf (fd, indent+1, "<date>\n");
   xml_fprintf (fd, indent+2, "<error txt=\"No scan dates.\"/>\n");
   xml_fprintf (fd, indent+1, "</date>\n");
   if(subset_size(t))fprintf (stderr, "WARNING: bad timestamps for this host (%s) !!\n", subset_value (h));
  }

  subset_free (st);

  xml_results_result_ports(fd,indent,be,h,q);
  xml_fprintf (fd, indent, "</result>\n");
} /* xml_results_result */

static void
xml_results ( FILE* fd, int indent, int be)
{
 struct subset  * sq, * q;
 cmp_func_t cmp[] = {safe_strcmp};

 xml_fprintf (fd, indent, "<results>\n");

 sq = q = subset_uniq(subset_sort(query_backend(be, "SELECT subnet FROM results"), 0, 0, cmp), 0);
 while(q)
 {
  struct subset * sh, * h;
  sh = h = subset_uniq(subset_sort(query_backend(be, "SELECT host FROM results WHERE subnet = '%s'", subset_value (q)), 0, 0, cmp), 0);

  while (h)
  {
   xml_results_result(fd, indent, be, h, q);
   h = subset_next(h);
  }

  subset_free(sh);
  q = subset_next(q);
 }

 xml_fprintf (fd, indent, "</results>\n\n");
 subset_free(sq);
} /* xml_results */

int backend_to_xml_ng(be, filename)
 int be;
 char * filename;
{
 FILE* fd = fopen(filename, "w");

 if(!fd)
 {
  show_error(strerror(errno));
  return -1;
 }

 xml_fprintf (fd, 0, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
 xml_fprintf (fd, 0, "<!-- nessus.xsl can be found in the nessus-tools directory -->\n");

 xml_fprintf (fd, 0, "<?xml-stylesheet type=\"text/xsl\" href=\"nessus.xsl\"?>\n");
 xml_fprintf (fd, 0, "<report version=\"1.4\">\n");
 /* don't need this: fprintf (fd, "\t<scan>\n"); */
  xml_info (be, fd, 1); 
  xml_config (fd, 1); 
  xml_plugins (fd, 1);
  xml_results(fd, 1, be);
 /* dont't need this: fprintf (fd, "\t</scan>\n"); */
 xml_fprintf (fd, 0, "</report>\n");

 fclose(fd);
 return 0; 
}

