/* Nessus
 * Copyright (C) 1998, 1999, 2000 Renaud Deraison
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
#include "report_utils.h"
#include "error_dialog.h"
#include "globals.h"
#include "xml_output.h"

static char *parse_portname ( char *name, int howto );

typedef struct {
	char sym;
	char * xml_sym;
} e_char;

static char * xml_escape(const char * str) {
	const e_char sym[] = {{'&', "&amp;"}, {'<', "&lt;"}, {'>', "&gt;"}};
	const int symnum = 3;
	static char buf[8192];
	char *p, *s, *start;
	int i, j;
	
	strncpy(buf, str, sizeof(buf)-1);
	for(i = 0; i < symnum; i++) {
		start = s = strdup(buf);
		j = 0;
		buf[0] = '\0';
		while((p = strchr(s, sym[i].sym)) != NULL) {
			strncpy(&buf[j], s, p - s);
			j += p - s;
			buf[j] = '\0';
			strcat(buf, sym[i].xml_sym);
			j += strlen(sym[i].xml_sym);
			s = p;
			s++;
			if(!(*s))
				break;
		}
		if(*s)
			strcat(buf, s);
		free(start);
	}
	return buf;
}

static char *parse_portname ( char *name, int howto )
{
	char *a, *b, *c;
	char *buf;

	switch ( howto )
	{
		case GET_SERVICE_NAME:
			/*
			 * convert 'telnet (21/tcp)' to 'telnet'
			 */

			a = estrdup ( name );
			buf = strtok ( a, " " );
			b = emalloc ( strlen ( buf ) + 1 );
			strcpy ( b, buf );
			efree ( &name );
			return b;			
			break;
	
		case GET_PORT_NUMBER:  
		  /*
		   * convert 'telnet (21/tcp)' to '21'
		   */

			a = estrdup ( name );
			if ( ( b = strchr ( a, '(' ) ) != 0 )
				a = b + 1;

			c = strtok ( a, "/" );
			buf = emalloc ( strlen ( c ) + 1 );
			strcpy ( buf, c );
			efree ( &name );

			return buf;			   
			break;
	
		case GET_PROTOCOL:
			
			/*
			 * convert 'telnet (21/tcp)' to 'tcp'
			 */
			
			a = estrdup ( name );
			if ( ( b = strchr ( a, '/' ) ) != 0 )
				a = b + 1;
				
			c = strtok ( a, ")" );
			buf = emalloc ( strlen ( c ) + 1 );
			strcpy ( buf, c );
			efree ( &name );
				
			return buf;						 
			break;
	}
	return 0;
}


int 
arglist_to_xml(hosts, filename)
 struct arglist * hosts;
 char * filename;
{
	FILE *file;
	struct arglist *h;
	char *port;
	struct arglist *ports;
	char *hostname;
	char *name;
	char	*svc,*pnum, *proto;

	if ( !strcmp ( filename, "-" ) )
		file = stdout;
	else
		file = fopen ( filename, "w" );
	
	if ( !file )
	{
		show_error ( "Could not create this file! " );
		perror ( "fopen " );
		return ( -1 );
	}	

	fprintf ( file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" );
	fprintf ( file, "<!DOCTYPE scanreport SYSTEM \"nsr.dtd\">\n" );
	fprintf ( file, "<scanreport>\n" );
	
	/*
	 * Write a (small) summary
	 */
	 
	fprintf ( file, "<summary>\n" );
	fprintf ( file, "\t<alivehosts>%d</alivehosts>\n", arglist_length ( hosts ) ); 
	fprintf ( file, "\t<securityholes>%d</securityholes>\n", number_of_holes ( hosts ) );
	fprintf ( file, "\t<securitywarnings>%d</securitywarnings>\n", number_of_warnings ( hosts ) );
	fprintf ( file, "\t<securitynotes>%d</securitynotes>\n", number_of_notes ( hosts ) );
	fprintf ( file, "</summary>\n" );

	h = hosts;

	fprintf ( file, "\n" );
	fprintf ( file, "<testedhostsummary>\n" );
	while ( h && h->next )
	{
		int result;
		
		fprintf ( file, "\t<testedhost hostname=\"%s\">\n", h->name );
		
		result = is_there_any_hole ( h->value );
		switch ( result )
		{
			case HOLE_PRESENT:
				fprintf ( file, "\t\t<result>Security holes found</result>\n" );
				break;
				
			case WARNING_PRESENT:
				fprintf ( file, "\t\t<result>Security warnings found</result>\n" );
				break;
				
			case NOTE_PRESENT:
				fprintf ( file, "\t\t<result>Security notes found</result>\n" );
				break;
				
			default:
				fprintf ( file, "\t\t<result>no noticeable problem found</result>\n" );
		}
		fprintf ( file, "\t</testedhost>\n" );
		h = h->next;
	}
	fprintf ( file, "</testedhostsummary>\n" );

	fprintf ( file, "<details>\n" );
	while ( hosts && hosts->next )
	{
	  hostname = hosts->name;
	  fprintf ( file, "\t<host hostname=\"%s\">\n", hostname );
		
		ports = arg_get_value ( hosts->value, "PORTS" );
		if ( ports )
		{
			struct arglist *open = ports;
			if ( open->next )
			{
				fprintf ( file, "\t\t<openports>\n" );
				while ( open && open->next )
				{
					name = estrdup ( open->name );
					svc = parse_portname ( name, GET_SERVICE_NAME );

					name = estrdup ( open->name );
					pnum = parse_portname ( name, GET_PORT_NUMBER );

					name = estrdup ( open->name ); 
					proto = parse_portname ( name, GET_PROTOCOL );

					fprintf ( file, "\t\t\t<port service=\"%s\" protocol=\"%s\" portnum=\"%s\">\n", svc, proto, pnum );
					efree ( &svc );
					efree ( &pnum );
					efree ( &proto );

					if ( arg_get_value ( open->value, "REPORT" ) )
						fprintf ( file, "\t\t\t\t<info>Security hole found</info>\n" );					
					else if ( arg_get_value ( open->value, "INFO" ) )
						fprintf ( file, "\t\t\t\t<info>Security warning found</info>\n" );
					else
						fprintf ( file, "\t\t\t\t<info>Security notes found</info>\n" );
						
					fprintf ( file, "\t\t\t</port>\n" );

					open = open->next;
				}						
			
				fprintf ( file, "\t\t</openports>\n" );
			}			
		}
	
	  /*
	   * Write the summary of the open ports here
	   */

		fprintf ( file, "\t\t<portsummary>\n" );
		while ( ports && ports->next )
		{
			struct arglist *report;
	    struct arglist *info;
	    struct arglist *note;
		
	  	port = ports->name;
    
			report = arg_get_value(ports->value, "REPORT");
			if ( report )
			{
				while ( report && report->next )
				{
					if ( strlen ( report->value ) )
			    		{  	
						name = estrdup ( ports->name );	
						svc = parse_portname ( name, GET_SERVICE_NAME );
			
						name = estrdup ( ports->name );	
						pnum = parse_portname ( name, GET_PORT_NUMBER );

						fprintf ( file, "\t\t\t<portinfo service=\"%s\" portnum=\"%s\" found=\"Vunerability\">\n", svc, pnum );
						
						efree ( &svc );
						efree ( &pnum );

						fprintf ( file, "\t\t\t\t<description>%s</description>\n", xml_escape(report->value) ); 	 
						fprintf ( file, "\t\t\t</portinfo>\n" );
					}
					report = report->next;
				}
			}

			info = arg_get_value( ports->value, "INFO" );
			if ( info )
			{
					while ( info && info->next )
					{
						if ( strlen ( info->value ) )
						{
							name = estrdup ( ports->name );
							svc = parse_portname ( name, GET_SERVICE_NAME );
				
							name = estrdup ( ports->name );	
							pnum = parse_portname ( name, GET_PORT_NUMBER );
	
							fprintf ( file, "\t\t\t<portinfo service=\"%s\" portnum=\"%s\" found=\"Warning\">\n", svc, pnum );

							efree ( &svc);
							efree ( &pnum );
							
							fprintf ( file, "\t\t\t\t<description>%s</description>\n", xml_escape(info->value) ); 	 
							fprintf ( file, "\t\t\t</portinfo>\n" );			
						}
						info = info->next;
					}
			}
		
			note = arg_get_value(ports->value, "NOTE");
			if ( note )
			{
				while ( note && note->next )
				{			
					if ( strlen ( note->value ) )
					{
						name = estrdup ( ports->name );	
						svc = parse_portname ( name, GET_SERVICE_NAME );
			
						name = estrdup ( ports->name );
						pnum = parse_portname ( name, GET_PORT_NUMBER );

						fprintf ( file, "\t\t\t<portinfo service=\"%s\" portnum=\"%s\" found=\"Information\">\n", svc, pnum );

						efree ( &svc );
						efree ( &pnum );
			
						fprintf ( file, "\t\t\t\t<description>%s</description>\n", xml_escape(note->value) ); 	 
						fprintf ( file, "\t\t\t</portinfo>\n" );					
					}
					note = note->next;
				}
			}			
			ports = ports->next;
		}
	
		fprintf ( file, "\t\t</portsummary>\n" );
	  fprintf ( file, "\t</host>\n" );		

		hosts = hosts->next; 
	}

	fprintf ( file, "</details>\n" );
	fprintf ( file, "</scanreport>\n" );
	fclose ( file );
	
	return ( 0 );
}

