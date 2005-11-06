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
 */
 
#include <includes.h>
#include "report.h"
#include "report_utils.h"
#include "globals.h"
#include "text_output.h"
#define CATEGORY_A 0
#define CATEGORY_B 1
#define CATEGORY_C 2
#define CATEGORY_D 3
#define CATEGORY_E 4


static void latex_print_header(FILE *);
static void latex_print_footer(FILE *);

/* Pluto 25.6.00:
 * easy rules for a complicated issue ...
 * What if we have a large network with lots of small holes, is this saver
 * than a network with only one big? I've made a try on weighted
 * rules. Hosts with holes get elevated to *100, warnings to *10 and
 * infos stay where they are. 
 */

/*
static int latex_report_category(hosts, holes, warnings, infos)
 int hosts, holes, warnings, infos;
{
 if(((holes*100)/hosts) > 10)return CATEGORY_E;
 if(holes)return CATEGORY_D;
 if(((warnings*100)/hosts) > 10)return CATEGORY_C;
 if(warnings)return CATEGORY_B;
 return CATEGORY_A;
}*/

static int latex_report_category(hosts, holes, warnings, notes)
 int hosts, holes, warnings, notes;
{
  int pholes, pwarnings, pnotes, all = 0;

  pholes = (int) (holes*100)/hosts;
  pwarnings = (int) (warnings*100)/hosts;
  pnotes = (int) (notes*100)/hosts;
   
  all = (pholes * 10) + (pwarnings * 5) + pnotes;

#ifdef DEBUG
  fprintf(stderr,"%s:%d pholes: %d\tpwarnings: %d\tpnotes: %d\tall: %d\n",__FILE__,__LINE__,pholes, pwarnings, pnotes,all);
#endif

  if (all > 1200) return CATEGORY_E;
  else if (all > 600) return CATEGORY_D;
  else if (all > 300) return CATEGORY_C;
  else if (all > 0) return CATEGORY_B;
  else return CATEGORY_A;
}

   
/*
 * Print the LaTeX header
 */
static void latex_print_header(FILE * f)
{
/*
 * Fancy headers
 */
 fprintf(f, "\\documentclass{article}\n");
 fprintf(f, "%% Handle pdflatex nicely\n");
 fprintf(f, "\\ifx\\pdfoutput\\undefined\\else\\usepackage{times}\\fi\n");
 fprintf(f, "\\usepackage{fancyhdr}\n");
 fprintf(f, "\\pagestyle{fancy}\n");
 fprintf(f, "\\fancyhead[LE,RO]{\\textit{Nessus Report}}\n");
 fprintf(f, "\\fancyfoot[LE,RO]{}\n");
 
 /*
  * Print the title on one page, then the
  * table of contents
  */
 fprintf(f, "\\pagenumbering{roman}\n");
 fprintf(f, "\\title{\\vspace*{100pt}\\Huge Report of a Nessus scan\\normalsize}\n");
 fprintf(f, "%%\n%% You might want to change this : \n%%\n");
 fprintf(f, "\\author{Nessus Security Scanner}\n");
 fprintf(f, "\\begin{document}\n");
 fprintf(f, "\\maketitle\n");
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\tableofcontents\n");
}


/*
 * Print the LaTeX footer
 */
static void latex_print_footer(FILE *  f)
{
 fprintf(f, "\\end{document}\n");
}


/****************************************************************************
 
   Introduction
 
 
  We have five different introductions here, that are chosen
  regarding the level of (in)security of the network.
  
  
 ****************************************************************************/

/*
 * Nothing found : excellent
 */
void latex_introduction_a(FILE * f, struct arglist * hosts, int holes, int warnings, int notes)
{
 int num_of_hosts = arglist_length(hosts);
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\section*{Introduction}\n");
 fprintf(f, "In this test, Nessus has tested %d host",num_of_hosts);
 if(num_of_hosts > 1)fprintf(f, "s");
 fprintf(f," and none of the vulnerabilities tested were present on this ");
 fprintf(f,"network ");
 if(Scanners && Plugins)
 {
 fprintf(f, "(see Appendix A and B page \\pageref{appendix_a} and page \\pageref{appendix_b} for the exhaustive ");
 fprintf(f,"list of what was tested).\\\\\n");
 }
 fprintf(f, "On the overall, your network seems to be pretty safe.\n");
 fprintf(f, "However, \\textbf{the result of a security scanner can not garantee your ");
 fprintf(f, "complete safety !}. Security Scanners can not test things such as home made ");
 fprintf(f, "CGIs, so if you want the garantee that you network is secure, we recommand ");
 fprintf(f, "that you check these things manually.\\\\\n");
 fprintf(f, "However, your network was given the highest mark that Nessus can give, ");
 fprintf(f, "that is a A (worst being E). Congratulations !");
}

/*
 * Some things found, but not serious on the overall
 */
void latex_introduction_b(FILE * f, struct arglist * hosts, int holes, int warnings, int notes)
{
 struct arglist * most = most_dangerous_host(hosts);
 int num_of_hosts = arglist_length(hosts);
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\section*{Introduction}\n");
 fprintf(f, "In this test, Nessus has tested %d host", num_of_hosts);
 if(num_of_hosts > 1)fprintf(f, "s");
 fprintf(f, " and found %d security holes, %d warnings and %d notes that can eventually help a cracker ", holes, warnings, notes);
 fprintf(f, "to break into your network. You should have a close look at them and ");
 fprintf(f, "decide of their severity. We strongly suggest that you correct them ");
 fprintf(f, "although we know it is not always possible.\\\\\n");
 if((num_of_hosts > 1)&&most)
 {
  fprintf(f, "We recommand that you take a closer look at %s, as it is the host ",
  		most->name);
  fprintf(f, "the most affected by these warnings.\\\\\n");
 }
 if(Scanners && Plugins)
 {
 fprintf(f, "(see Appendix A and B page \\pageref{appendix_a} and page \\pageref{appendix_b} for the exhaustive ");
 fprintf(f,"list of what was tested).\\\\\n");
 } 
 fprintf(f, "which is a very good thing.\\\\\n");
 fprintf(f, "On the overall, Nessus has given to the security of this network the mark B. (A being the best ");
 fprintf(f, "and E being the worst).");
}


/*
 * A lot of small things have been found. That's not good
 */
int latex_introduction_c(FILE * f, struct arglist * hosts, int holes, int warnings, int notes)
{
 struct arglist * most = most_dangerous_host(hosts);
 int num_of_hosts = arglist_length(hosts);
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\section*{Introduction}\n");
 fprintf(f, "In this test, Nessus has tested %d host", num_of_hosts);
 if(num_of_hosts > 1)fprintf(f, "s");
 fprintf(f, " and found %d security holes, %d warnings an %d notes that can eventually help a cracker ", holes, warnings, notes);
 fprintf(f, "to break into your network. You should have a close look at them and ");
 fprintf(f, "decide of their severity. \\\\\n");
 fprintf(f, "Note that there is a big number of warnings for a single network of this size. ");
 fprintf(f, "What you must know is that what usually compromise the security of a network ");
 fprintf(f, "is the combination of a number of small warnings, which can be used to gain ");
 fprintf(f, "access on a host.\\\\\n");
 fprintf(f, "We strongly suggest that you correct them as soon as you can, ");
 fprintf(f, "although we know it is not always possible.\\\\\n");
 if((num_of_hosts > 1)&&most)
 {
  fprintf(f, "We recommand that you take a closer look at \\verb+%s+, as it is the host ",
  		most->name);
  fprintf(f, "the most affected by these warnings.\\\\\n");
 }

 if(Scanners && Plugins)
 {
 fprintf(f, "(see Appendix A and B page \\pageref{appendix_a} and page \\pageref{appendix_b} for the exhaustive ");
 fprintf(f,"list of what was tested).\\\\\n");
 }
 fprintf(f, " which is a very good thing.\\\\\n");
 fprintf(f, "On the overall, Nessus has given to the security of this network the mark C. (A being the best ");
 fprintf(f, "and E being the worst).");
 return 0;
}


int latex_introduction_d(FILE * f, struct arglist * hosts, int holes, int warnings, int notes)
{
 struct arglist * most = most_dangerous_host(hosts);
 int num_of_hosts = arglist_length(hosts);
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\section*{Introduction}\n");
 fprintf(f, "In this test, Nessus has tested %d host", num_of_hosts);
 if(num_of_hosts > 1)fprintf(f, "s");
 fprintf(f, " and found \\textbf{%d severe security holes}, as well as %d security warnings and %d notes.", holes, warnings, notes);
 fprintf(f, "These problems can easily be used to break ");
 fprintf(f, "into your network. You should have a close look at them and ");
 fprintf(f, "correct them as soon as possible.\\\\\n");
 fprintf(f, "Note that there is a big number of problems for a single network of this size.\\\\\n");
 fprintf(f, "We strongly suggest that you correct them as soon as you can, ");
 fprintf(f, "although we know it is not always possible.\\\\\n");
 if((num_of_hosts > 1)&&most)
 {
  fprintf(f, "We recommand that you take a closer look at \\verb+%s+, as it is the host ",
  		most->name);
  fprintf(f, "that is the most likely to be the entry point of any cracker.\n");
 }
 
 if(Scanners && Plugins)
 {
 fprintf(f, "You should have a look at ");
 fprintf(f, "(see Appendix A and B page \\pageref{appendix_a} and page \\pageref{appendix_b} for the exhaustive ");
 fprintf(f,"list of what was tested).\\\\\n");
 }
  fprintf(f, "On the overall, Nessus has given to the security of this network the mark D. (A being the best ");
 fprintf(f, "and E being the worst). There is room for improvement, and ");
 fprintf(f, "\\textbf{we strongly suggest that you take the appropriate measures to ");
 fprintf(f, "solve these problems \\textit{as soon as possible}}\n");
 return 0 ;
}

int latex_introduction_e(FILE * f, struct arglist * hosts, int holes, int warnings, int notes)
{
 struct arglist * most = most_dangerous_host(hosts);
 int num_of_hosts = arglist_length(hosts);
 fprintf(f, "\\newpage\n");
  fprintf(f, "\\section*{Introduction}\n");
 fprintf(f, "In this test, Nessus has tested %d host", num_of_hosts);
 if(num_of_hosts > 1)fprintf(f, "s");
 fprintf(f, " and found \\textbf{%d severe security holes}, as well as %d security warnings and %d notes.", holes, warnings, notes);
 fprintf(f, "These problems can easily be used to break ");
 fprintf(f, "into your network. You should have a close look at them and ");
 fprintf(f, "correct them as soon as possible.\\\\\n");
 fprintf(f, "Note that there is a big number of problems for a single network of this size.\\\\\n");
 fprintf(f, "We strongly suggest that you correct them as soon as you can, ");
 fprintf(f, "although we know it is not always possible.\\\\\n");
 if((num_of_hosts > 1)&&most)
 {
  fprintf(f, "We recommand that you take a closer look at \\verb+%s+, as it is the host ",
  		most->name);
  fprintf(f, "that is the most likely to be the entry point of any cracker.\n");
 }
if(Scanners && Plugins)
 {
 fprintf(f, "You should have a look at ");
 fprintf(f, "(see Appendix A and B page \\pageref{appendix_a} and page \\pageref{appendix_b} for the exhaustive ");
 fprintf(f,"list of what was tested).\\\\\n");
 }
 
 fprintf(f, "On the overall, Nessus has given to the security of this network the mark E ");
 fprintf(f, "because of the number of vulnerabilities found. A script kid should be ");
 fprintf(f, "able to break into your network rather easily.\\\\\n");
 fprintf(f, "There is room for improvement, and ");
 fprintf(f, "\\textbf{we strongly suggest that you take the appropriate measures to ");
 fprintf(f, "solve these problems \\textit{as soon as possible}}\n");
 fprintf(f, "If you were considering hiring some security consultant to determine ");
 fprintf(f, "the security of your network, we strongly suggest you do so, because ");
 fprintf(f, "this should save your network.\n"); /* ... and your ass :) */
 return 0 ;
}

/****************************************************************************
 
   Content
 
 
  The content is the same for all categories (thanks god). We do not
  classify the hosts by severity, altough we could.
  
  
 ****************************************************************************/
 
 
void latex_print_host_ports(FILE * f, struct arglist * ports)
{
 if(!ports->next)return;
 fprintf(f, "\\item\\verb+%s+\n", ports->name);
 latex_print_host_ports(f,ports->next);
}

void latex_print_host_ports_problems(FILE * f, struct arglist * port)
{
 if(port->next)
 {
 struct arglist * holes = arg_get_value(port->value, "REPORT");
 struct arglist * info = arg_get_value(port->value, "INFO");
 struct arglist * note = arg_get_value(port->value, "NOTE");
 if(!(holes || info || note)){
 	latex_print_host_ports_problems(f, port->next);
	return;
	}
 else {
   fprintf(f, "\\subsubsection{Problems regarding : %s}\n", port->name);
   if(holes)
   {
    fprintf(f, "Security holes :\\\\\n");
    fprintf(f, "\\begin{itemize}\n");
    while(holes->next)
    {
    char * c = holes->value;
    while(c[0]=='\n')c++;
    fprintf(f, "\\item \\begin{verbatim}");
    printf_formatted_text(f, c, 70, NULL);
    fprintf(f, "\n\\end{verbatim}");
    holes = holes->next;
    }
    fprintf(f, "\\end{itemize}\n");
   }
   if(info)
   {
    fprintf(f, "Security warnings :\\\\\n");
    fprintf(f, "\\begin{itemize}\n");
    while(info->next)
    {
     char * c = info->value;
     while(c[0]=='\n')c++;
     fprintf(f, "\\item \\begin{verbatim}");
     printf_formatted_text(f, c, 70, NULL);
     fprintf(f, "\n\\end{verbatim}");
     info = info->next;
    }
    fprintf(f, "\\end{itemize}\n");
   }
   if(note)
   {
    fprintf(f, "Security note :\\\\\n");
    fprintf(f, "\\begin{itemize}\n");
    while(note->next)
    {
     char * c = note->value;
     while(c[0]=='\n')c++;
     fprintf(f, "\\item \\begin{verbatim}");
     printf_formatted_text(f, c, 70, NULL);
     fprintf(f, "\n\\end{verbatim}");
     note = note->next;
    }
    fprintf(f, "\\end{itemize}\n");
   }
  }
  latex_print_host_ports_problems(f, port->next);
 }
}


/*
 * This function will create the new section that has the name
 * of the current host.
 */
void latex_print_hosts(FILE * f, struct arglist * host)
{
  if(!host->next)return;
  fprintf(f, "\\newpage\n");
  fprintf(f, "\\section{%s}\n", host->name);
  
  
  /* 
   * List of open ports
   */
  fprintf(f, "\\subsection{Open ports (TCP and UDP)}\n");
  fprintf(f, "\\verb+%s+ has the following ports that are open : \n", 
  			host->name);
  fprintf(f, "\\begin{itemize}\n");			
  latex_print_host_ports(f, arg_get_value(host->value, "PORTS"));
  fprintf(f, "\\end{itemize}\n");
  fprintf(f, "You should disable the services that you do not use, as they ");
  fprintf(f, "are potential security flaws.\n");
  
  /*
   * Detail of the problems
   */
  if(number_of_holes_by_port(arg_get_value(host->value, "PORTS")) ||
     number_of_notes_by_port(arg_get_value(host->value, "PORTS")) ||
     number_of_warnings_by_port(arg_get_value(host->value, "PORTS")))
   {
     fprintf(f, "\\subsection{Details of the vulnerabilities}\n");
     latex_print_host_ports_problems(f, arg_get_value(host->value, "PORTS"));
   }
   latex_print_hosts(f, host->next);
}

/**************************************************************************
  
  		              Conclusion
		
	Not a lot to say that has not been said before. So, let's write
	some propanda explaining how a security scanner should be used
		
 **************************************************************************/

void latex_conclusion(FILE * f)
{
 fprintf(f, "\\newpage\n");
 fprintf(f, "\\section*{Conclusion}\n");
 fprintf(f, "A security scanner, such as Nessus, is not a garantee  ");
 fprintf(f, "of the security of your network.\\\\\n");
 fprintf(f, "A lot of factors can not be tested by a security scanner : ");
 fprintf(f, "the practices of the users of the network, the home-made ");
 fprintf(f, "services and CGIs, and so on... So, you should not have ");
 fprintf(f, "a false sense of security now that the test are done. ");
 fprintf(f, "We recommand that you monitor actively what happens on ");
 fprintf(f, "your firewall, and that you use some tools such as ");
 fprintf(f, "tripwire to restore your servers more easily in the case ");
 fprintf(f, "of an intrusion.\\\\\n");
 fprintf(f, "In addition to that, you must know that new security holes ");
 fprintf(f, "are found each week. That is why we recommand that you visit ");
 fprintf(f, "\\verb+http://www.nessus.org/scripts.html+, which is a page ");
 fprintf(f, "that contains the test for all the holes that are published ");
 fprintf(f, "on public mailing lists such as BugTraq (see ");
 fprintf(f, "\\verb+http://www.securityfocus.com+ for details) ");
 fprintf(f, "and test the security of your network on a (at least) weekly basis ");
 fprintf(f, "with the checks that are on this page.\\\\\n");
 fprintf(f, "\\textit{This report was generated with Nessus, the open-sourced ");
 fprintf(f, "security scanner. See http://www.nessus.org for more information}");
}

/***************************************************************************


				Appendix
				
  Write down the list of plugins that were activated during the test				
				
 ***************************************************************************/
 
 
void latex_appendix_plugins(FILE * f, struct arglist * plugins)
{
 if(!(plugins && plugins->next))return;
 else
  {
   if(plug_get_launch(plugins->value))
   {
    fprintf(f, "\\item \\verb+%s+\n", 
    			(char*)arg_get_value(plugins->value, "NAME"));
   }
   latex_appendix_plugins(f, plugins->next);
  }
}
void latex_appendix(FILE *f)
{
  if(Scanners || Plugins)
  {
  fprintf(f, "\\newpage\n");
  fprintf(f, "\\label{appendix_a}\n");
  fprintf(f, "\\appendix\n");
  fprintf(f, "\\section{List of port scanners used during this session}\n");
  fprintf(f, "\\begin{itemize}\n");
  latex_appendix_plugins(f, Scanners);
  fprintf(f, "\\end{itemize}\n");
  fprintf(f, "\\label{appendix_b}\n");
  fprintf(f, "\\section{List of plugins used during this session}\n");
  fprintf(f, "\\begin{itemize}\n");
  latex_appendix_plugins(f, Plugins);
  fprintf(f, "\\end{itemize}\n");
 }
}
 				
int arglist_to_latex(struct arglist * list, char * filename)
{
 FILE * f;
 int notes = number_of_notes(list);
 int warnings = number_of_warnings(list);
 int holes = number_of_holes(list);
 int length = arglist_length(list);
 
 if(!strcmp(filename, "-"))f = stdout;
 else f = fopen(filename, "w");
 if(!f){
 	perror("open ");
	return -1;
	}
 latex_print_header(f);
 
 
 /*
  * Rule to determine whether a network is almost safe :
  *
  * 	- 0 holes : see the warnings
  *	- less than 10% of holes : network almost safe		CATEGORY_D
  *	- more than 10% of holes : network unsafe		CATEGORY_E
  *
  * 	- 0 warning : network safe				CATEGORY_A
  *	- less than 10% of warnings : network security can be improved  _B
  *	- more than 10% of warnings : network security must be improved _C
  */
 
  switch(latex_report_category(length, holes, warnings, notes))
  {
   case CATEGORY_A :
   	 latex_introduction_a(f, list, holes, warnings, notes);break;
   case CATEGORY_B :
  	 latex_introduction_b(f, list, holes, warnings, notes);break;
   case CATEGORY_C :
  	 latex_introduction_c(f, list, holes, warnings, notes);break;
   case CATEGORY_D :
  	 latex_introduction_d(f, list, holes, warnings, notes);break;
   default :
   	 latex_introduction_e(f, list, holes, warnings, notes);break;
   
  }
  
  latex_print_hosts(f, list);
  latex_conclusion(f);
  latex_appendix(f);
  latex_print_footer(f);		
  fclose(f);
 return 0;
}
