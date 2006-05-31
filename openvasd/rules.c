/* OpenVAS
* $Id$
* Description: Read the OpenVAS rules file into memory.
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
#include <pwd.h>
#include "comm.h"
#include "utils.h"
#include "rules.h"
#include "log.h"
static char * rules_get_fname(struct arglist *);

/*
 * Returns the name of the rules file
 */
static char *
rules_get_fname(preferences)
  struct arglist * preferences;
{
  char * t;
  if((t=arg_get_value(preferences, "rules")))return(t);
  else return(OPENVASD_RULES);
}

struct openvas_rules *
rules_new(preferences)
  struct arglist * preferences;
{
  char * filename = rules_get_fname(preferences);
  struct openvas_rules * nr = emalloc(sizeof(*nr));
  FILE * f;
  nr->rule = RULES_ACCEPT;
  
  f = fopen(filename,"w");
  if(!f){
     perror("rules_new():open ");
     return nr;
  }
     
  fprintf(f, "#\n# OpenVAS rules\n#\n\n");
  fprintf(f, "# Syntax : accept|reject address/netmask\n");
  fprintf(f, "\n# Accept to test anything : \n");
  fprintf(f, "default accept\n");
  fclose(f);
  return nr;
}


int rules_init_aux(rules,file, buffer, len,def) 
  struct openvas_rules * rules;
  FILE * file;
  char * buffer;
  int len;
  int def;
{
 buffer[0] = buffer[len - 1 ] = '\0';
 
 if(!(fgets(buffer, len - 1, file))){
   	rules->next = NULL;
	return def;
 }
 else {
   char *t = buffer;
   char *v;
   int t_len;
   if(t[strlen(t)-1]=='\n')t[strlen(t)-1]='\0';
   while((t[0]==' ')||(t[0]=='\t'))t++;
   if((t[0]=='#')||t[0] == '\0')return rules_init_aux(rules,file, buffer, len,def);
   v = strchr(t, ' ');
   if( v == NULL ){
      printf("Parse error in the rules file : %s\n", 
	  			buffer);
      return rules_init_aux(rules, file, buffer, len, def);
   }
   else
   {
     if(!strncmp(t, "accept", 6))
       rules->rule = RULES_ACCEPT;
     else if(!strncmp(t, "default", 7)){
       	if(!strncmp(t+8, "accept", 6))def = RULES_ACCEPT;
	else def = RULES_REJECT;
	return rules_init_aux(rules, file, buffer, len, def);
     }
     else if((!strncmp(t, "reject", 6))||
	     (!strncmp(t, "deny", 4)))rules->rule = RULES_REJECT;
     else {
       	   printf("Parse error in the rules file : %s\n",
	 			buffer);
	   return rules_init_aux(rules, file, buffer, len,def);
     }
     t = v+sizeof(char);
     v = strchr(t, '/');
     if(v)v[0]='\0';
     if(t[0]=='!'){
       	rules->not = 1;
        t++;
     }
     else rules->not = 0;
     t_len = strlen(t);
     while(t[t_len-1]==' ')
     {
      t[t_len-1]='\0';
      t_len --;
     }
     if(!(inet_aton(t,&rules->ip))) 
	 {
	  if(strcmp(t, "client_ip"))
	  {
	  printf("Parse error in the rules file : '%s' is not a valid IP\n",
	      			t);
	  return rules_init_aux(rules, file, buffer, len,def);
	  }
	  else
	  {
	   rules->ip.s_addr = -1;
	   rules->client_ip = 1;
	  }
	 }
	 else rules->client_ip = 0;
	 
     if(v)rules->mask = atoi(v+sizeof(char));
     else rules->mask = 32;
     if(rules->mask < 0 || rules->mask > 32)
     {
       printf("Error in the rules file. %s is not a valid cidr netmask\n",
	   			v+sizeof(char));
       EXIT(1);

     }
     if(rules->mask > 0)
     {
     rules->ip.s_addr = ntohl(rules->ip.s_addr) >> (32 - rules->mask);
     rules->ip.s_addr = htonl(rules->ip.s_addr << (32 - rules->mask));
     }
     else rules->ip.s_addr = 0;
     rules->next = emalloc(sizeof(*rules));
   }
 }
 return rules_init_aux(rules->next, file, buffer, len, def);
}
      

void
rules_init(rules, preferences)
  struct openvas_rules ** rules;
  struct arglist * preferences;
{
 struct openvas_rules * nr = emalloc(sizeof(*nr));
 char * filename = rules_get_fname(preferences);
 FILE * f = fopen(filename, "r");
 int def = RULES_ACCEPT;
 char buffer[1024];
 if( f == NULL ){
   	rules_new(preferences);
	nr->rule = RULES_ACCEPT;
	nr->next = emalloc(sizeof(*nr));
	nr->def = RULES_ACCEPT;
	*rules = nr;
	return;
 	}
 def = rules_init_aux(nr, f, buffer, sizeof(buffer), 0);
 *rules = nr;
 rules_set_def(*rules, def);
 
 fclose(f);
}

struct openvas_rules *
rules_dup_aux(s, r)
  struct openvas_rules * s, *r;
{
  printf("rules_dup called - does not work\n");
  if(!s->next)return r;
  else
  {
    r->ip.s_addr = s->ip.s_addr;
    r->mask = s->mask;
    r->rule = s->rule;
    r->not = s->not;
    r->def  = s->def;
    r->next = emalloc(sizeof(*r));
    return rules_dup_aux(s->next,r->next);
  }
}
struct openvas_rules *
rules_dup(struct openvas_rules *s)
{
  struct openvas_rules * r = emalloc(sizeof(*r));
  return rules_dup_aux(s, r);
}



struct openvas_rules *
rules_cat(struct openvas_rules * a, 
    	struct openvas_rules * b)
{
 struct openvas_rules * s = a;
 if(a)
   while(a->next != NULL && a->next->next != NULL)
   	a=a->next;
 if(a->next){
 	efree(&a->next);
	a->next = b;
	}
 else {
 	if(a)efree(&a);
 	s = b;
       }
 return s;
}


void rules_set_client_ip(struct openvas_rules * r, struct in_addr client)
{
 if(!r)
  return;
 else 
  {
   if(r->client_ip)
      r->ip = client;
   rules_set_client_ip(r->next, client);
  }
}
void rules_set_def(struct openvas_rules * r, int def)
{
  if(!r)return;
  else {
    	r->def = def;
	rules_set_def(r->next, def);
  }
}
 
void rules_add(struct openvas_rules **rules, 
		struct openvas_rules **user, 
		char * username)
{
  struct openvas_rules * accept_rules = emalloc(sizeof(**rules));
  struct openvas_rules * reject_rules = emalloc(sizeof(**rules));
  struct openvas_rules * t, *o, *p;
  int def = (*rules)->def;
  
  if(!def)def = RULES_ACCEPT;
#ifdef DEBUG_RULES  
  t = *rules;
  if(t)while(t->next)
  {
    printf("DEFAULT: %s/%d\n", inet_ntoa(t->ip), t->mask); 
    t = t->next;
  }
#endif
  t = *user;
  o = accept_rules;
  p = reject_rules;
  if(t->def == RULES_REJECT)def = RULES_REJECT;
  
  if(t != NULL)while(t->next != NULL)
  {
#ifdef DEBUG_RULES
    printf("rules_add : %d %s/%d\n", t->rule, inet_ntoa(t->ip), t->mask);
#endif    
    if(t->rule == RULES_ACCEPT)
    {
      if(!username)
      {
      accept_rules->ip.s_addr = t->ip.s_addr;
      accept_rules->client_ip = t->client_ip;
      accept_rules->mask = t->mask;
      accept_rules->rule = t->rule;
      accept_rules->not  = t->not;
      accept_rules->next = emalloc(sizeof(**rules));
      accept_rules = accept_rules->next;
      }
      else
      {
       log_write("user %s : attempted to gain more rights by adding accept %s/%d",
       		username, inet_ntoa(t->ip), t->mask);
      }
    }
    else
    {
      reject_rules->ip.s_addr = t->ip.s_addr;
      reject_rules->client_ip = t->client_ip;
      reject_rules->mask = t->mask;
      reject_rules->rule = t->rule;
      reject_rules->not = t->not;
      reject_rules->next = emalloc(sizeof(**rules));
      reject_rules  = reject_rules->next;
    }
      t = t->next;
  }

  accept_rules = o;
  reject_rules = p;
  if(def == RULES_ACCEPT)
    *rules = rules_cat(rules_cat(reject_rules, *rules),accept_rules);
  else 
    *rules = rules_cat(reject_rules, rules_cat(*rules, accept_rules));

  rules_set_def(*rules, def);
   
#ifdef DEBUG_RULES 
  printf("After rules_cat : \n");
  rules_dump(*rules);
#endif
}

#ifdef DEBUG_RULES
void
rules_dump(struct openvas_rules * rules)
{
  if(!rules->next)return;
  printf("%d %c%s/%d (def %d)\n", rules->rule, rules->not?'!':' ', inet_ntoa(rules->ip), rules->mask,
      				rules->def);
  rules_dump(rules->next);
}
#endif

int get_host_rules(struct openvas_rules * rules, struct in_addr addr, int netmask)
{
  struct in_addr backup;
  
  if(!rules)
  {
     fprintf(stderr, "???? no rules - this is likely to be a bug\n");
     fprintf(stderr, "Please report in to bugs@cvs.nessus.org\n");
     return RULES_ACCEPT;
  }
  if(!rules->next)return rules->def;
  backup.s_addr = addr.s_addr;
  if(rules->mask > 0)
  {
  addr.s_addr = ntohl(addr.s_addr) >> (32 - rules->mask);
  addr.s_addr = htonl(addr.s_addr << (32 - rules->mask));
  }
  else addr.s_addr = 0;

  if(rules->not)
   {
   if(addr.s_addr != rules->ip.s_addr)return(rules->rule);
   }
  else
  {
   if(addr.s_addr == rules->ip.s_addr){
	return(rules->rule);
   }
  }
  return get_host_rules(rules->next, backup, netmask);
}

void
rules_free(rules)
 struct openvas_rules * rules;
{
 while(rules != NULL)
 {
  struct openvas_rules * next = rules->next;
  efree(&rules);
  rules = next;
 }  
}

