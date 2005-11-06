/* Nessus
 * Copyright (C) 1998, 1999 Renaud Deraison
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
#include "report_utils.h"
 
 
/*-------------------------------------------------------------------*/
int 
safe_strcmp(a, b)
 char * a, * b;
{
 if(!a && !b)
  return 0;
 if(!a)
  return 1;
 else if(!b)
  return -1;
 else return strcmp(a, b);
}



 /*-------------------------------------------------------------------*/
 
 
 
int arglist_length(struct arglist * arg)
{
 if(!arg)return 0;
 return arg->next ? 1 + arglist_length(arg->next):0;
} 

struct arglist * sort_by_port(hosts) 
     struct arglist * hosts;
{
  struct arglist * by_port;
  struct arglist * sub_port;
  struct arglist * hosts_port;
  struct arglist * sub_arg;
  struct arglist * tmp_port;
  char * comm;
  by_port = emalloc(sizeof(struct arglist));

  if (!hosts || !hosts->next) {
    return by_port;
  }

  while (hosts && hosts->next)
    {
      struct arglist * ports = arg_get_value(hosts->value, "PORTS");
      while(ports && ports->next)
	{
	  struct arglist * reports = arg_get_value(ports->value, "REPORT");
	  struct arglist * infos = arg_get_value(ports->value, "INFO");
	  struct arglist * notes = arg_get_value(ports->value, "NOTE");

	  tmp_port = arg_get_value(by_port, ports->name);
	  if(!tmp_port)
	    {
	      tmp_port = emalloc(sizeof(struct arglist));
	      arg_add_value(by_port, ports->name, ARG_ARGLIST, -1, tmp_port);
	    }

	  hosts_port = arg_get_value(tmp_port,"HOSTS");
	  if (!hosts_port){
	    hosts_port = emalloc(sizeof(struct arglist));
	    arg_add_value(tmp_port, "HOSTS", ARG_ARGLIST, -1, hosts_port);
	  }

	    sub_port = arg_get_value(hosts_port,hosts->name);
	    if (!sub_port){
	      sub_port = emalloc(sizeof(struct arglist));
	      arg_add_value(hosts_port, hosts->name, ARG_ARGLIST, -1, sub_port);
	      /*arg_add_value(sub_port, "STATE", ARG_INT, sizeof(int),(void *)1);*/
	    }
	  if ( reports || infos || notes){
	    if (reports) {
	      sub_arg = arg_get_value(sub_port, "REPORT");
	      if (!sub_arg) {
		sub_arg = emalloc(sizeof(struct arglist));

	      }
	      while (sub_arg && sub_arg->next)sub_arg = sub_arg->next;
		  
	      while (reports && reports->next) {
		comm = emalloc(strlen(reports->value)+1);
		strncpy(comm, reports->value, strlen(reports->value));
		/* arg_add_value(tmp_port, hosts->name, ARG_STRING, strlen(comm),comm); */
		arg_add_value(sub_arg, "REPORT", ARG_STRING, strlen(comm),comm);
		reports = reports->next;
	      }
	      arg_add_value(sub_port, "REPORT", ARG_ARGLIST, -1, sub_arg);
	    }
		
	    if (notes) {
	      sub_arg = arg_get_value(sub_port, "NOTE");
	      if (!sub_arg) {
		sub_arg = emalloc(sizeof(struct arglist));
		arg_add_value(sub_port, "NOTE", ARG_ARGLIST, -1, sub_arg);
	      }
	      while (sub_arg && sub_arg->next)sub_arg = sub_arg->next;
		  
	      while (notes && notes->next) {
		comm = emalloc(strlen(notes->value)+1);
		strncpy(comm, notes->value, strlen(notes->value));
		/* arg_add_value(tmp_port, hosts->name, ARG_STRING, strlen(comm),comm); */
		arg_add_value(sub_arg, "NOTE", ARG_STRING, strlen(comm),comm);
		notes = notes->next;
	      }
	    }

	    if (infos) {
	      sub_arg = arg_get_value(sub_port, "INFO");
	      if (!sub_arg) {
		sub_arg = emalloc(sizeof(struct arglist));
		arg_add_value(sub_port, "INFO", ARG_ARGLIST, -1, sub_arg);
	      }
	      while (sub_arg && sub_arg->next)sub_arg = sub_arg->next;
		  
	      while (infos && infos->next) {
		comm = emalloc(strlen(infos->value)+1);
		strncpy(comm, infos->value, strlen(infos->value));
		/* arg_add_value(tmp_port, hosts->name, ARG_STRING, strlen(comm),comm); */
		arg_add_value(sub_arg, "INFO", ARG_STRING, strlen(comm),comm);
		infos = infos->next;
	      }
	    }
	  }
	  ports = ports->next;
	}
      hosts = hosts->next;
    }

  return by_port;
}



/*
 * Auxilliary functions
 */
int number_of_notes_by_port(struct arglist * arg)
{ 
 if(!arg || !arg->next)return 0;
 else {
  struct arglist * notes = arg_get_value(arg->value, "NOTE");
  return arglist_length(notes) + number_of_notes_by_port(arg->next);
  }
}

int number_of_notes_by_host(struct arglist * arg)
{
 if(!arg || !arg->next)return 0;
 else return number_of_notes_by_port(arg->value) +
  	     number_of_notes_by_host(arg->next);	     
}
 
int number_of_warnings_by_port(struct arglist * arg)
{ 
 if(!arg || !arg->next)return 0;
 else {
  struct arglist * warnings = arg_get_value(arg->value, "INFO");
  return arglist_length(warnings) + number_of_warnings_by_port(arg->next);
  }
}

int number_of_warnings_by_host(struct arglist * arg)
{
 if(!arg || !arg->next)return 0;
 else return number_of_warnings_by_port(arg->value) +
  	     number_of_warnings_by_host(arg->next);	     
}
 

int number_of_holes_by_port(struct arglist * arg)
{ 
 if(!arg || !arg->next)return 0;
 else {
  struct arglist * holes = arg_get_value(arg->value, "REPORT");
  return arglist_length(holes) + number_of_holes_by_port(arg->next);
  }
}

int number_of_holes_by_host(struct arglist * arg)
{
 if(!arg || !arg->next)return 0;
 else return number_of_holes_by_port(arg->value) +
  	     number_of_holes_by_host(arg->next);	     
}


int number_of_notes(struct arglist *  arg)
{
 if(!arg || !arg->next)return 0;
 else return number_of_notes_by_host(arg->value) + 
 	     number_of_notes(arg->next);
}

int number_of_warnings(struct arglist *  arg)
{
 if(!arg || !arg->next)return 0;
 else return number_of_warnings_by_host(arg->value) + 
 	     number_of_warnings(arg->next);
}

int number_of_holes(struct arglist * arg)
{
if(!arg ||!arg->next)return 0;
 else return number_of_holes_by_host(arg->value) + 
 	     number_of_holes(arg->next);
}

/*
 * The most dangerous host
 */
static struct arglist* sub_most_dangerous_host_holes(host, current, number)
	struct arglist * host;
	struct arglist * current;
	int number;
{
 if(!host || !host->next)return current;
 else 
 {
  int holes = number_of_holes_by_host(host->value);
  if(holes > number) return sub_most_dangerous_host_holes(host->next, host,
  							   holes);
	else return sub_most_dangerous_host_holes(host->next, current, number);
 }
}

static struct arglist* sub_most_dangerous_host_warnings(host, current, number)
	struct arglist * host;
	struct arglist * current;
	int number;
{
 if(!host || !host->next)return current;
 else 
 {
  int holes = number_of_warnings_by_host(host->value);
  if(holes > number) return sub_most_dangerous_host_warnings(host->next, host,
  							   holes);
	else return sub_most_dangerous_host_warnings(host->next, current, number);
 }
}

	
static struct arglist* sub_most_dangerous_host_notes(host, current, number)
	struct arglist * host;
	struct arglist * current;
	int number;
{
 if(!host || !host->next)return current;
 else 
 {
  int holes = number_of_notes_by_host(host->value);
  if(holes > number) return sub_most_dangerous_host_notes(host->next, host,
  							   holes);
	else return sub_most_dangerous_host_notes(host->next, current, number);
 }
}

struct arglist *most_dangerous_host(hosts)
 struct arglist * hosts;
{
 struct arglist * most = sub_most_dangerous_host_holes(hosts, NULL, 0);
 if(most)return most;
 most = sub_most_dangerous_host_warnings(hosts, NULL, 0);
 if(most)return most;
 else return sub_most_dangerous_host_notes(hosts, NULL, 0);
}

/************************************************************************
 * 
 * 			 	Insertion sort
 *
 ************************************************************************/


struct arglist * arglist_insert(struct arglist*e, struct arglist** l)
{
 int greater = 0;
 int danger_e = 0;
 int danger_l = 0;
 
 danger_e = number_of_holes_by_host(e->value);
 danger_l = number_of_holes_by_host((*l)->value);
 if(danger_e > danger_l)greater++;

 if(!(danger_e || danger_l))
  {
  danger_e = number_of_warnings_by_host(e->value);
  danger_l = number_of_warnings_by_host((*l)->value);
  if(danger_e > danger_l)greater++;
  }
 if(!(danger_e || danger_l))
  {
  danger_e = number_of_notes_by_host(e->value);
  danger_l = number_of_notes_by_host((*l)->value);
  if(danger_e > danger_l)greater++;
  }
 
 if(!((*l)->next) ||  greater)
 {
  e->next = *l;
  *l = e; 
  return *l;
 }
 else
 {
  arglist_insert(e, &((*l)->next));
  return *l;
 }
}
 
struct arglist * arglist_insert_sort(struct arglist * l)
{
 if(!l->next)
  return l;
 else 
  {
   struct arglist * result_insert;
   
   result_insert = arglist_insert_sort(l->next);
   return arglist_insert(l, &result_insert);
  }
}
 
 


struct arglist * sort_dangerous_hosts(struct arglist * hosts)
{
 struct arglist * ret = emalloc(sizeof(struct arglist));
 arg_dup(ret, hosts);
 return arglist_insert_sort(ret);
}
