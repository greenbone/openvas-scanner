/* OpenVAS
 * Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 */  
 
#ifndef _OPENVAS_RULES_H
#define _OPENVAS_RULES_H

struct openvas_rules
	{
	 struct in_addr ip;
	 int client_ip;	/*  if set to 1, then 'ip' will be replaced by
			    the client ip when appropriate
			 */   

	 int mask;
	 int rule; 
	 int def; 	/* default */
	 int not;	/* not ip  */
	 struct openvas_rules * next;
        };
#define RULES_ACCEPT 1
#define RULES_REJECT 2
#define CAN_TEST(x) (x==RULES_ACCEPT)
void rules_init(struct openvas_rules **, struct arglist *);
void rules_free(struct openvas_rules *);
void rules_add(struct openvas_rules **, struct openvas_rules **, char*);
struct openvas_rules * rules_parse(char * , struct openvas_rules *, int);
struct openvas_rules * rules_dup(struct openvas_rules *);
void rules_set_def(struct openvas_rules *, int);
void rules_set_client_ip(struct openvas_rules *, struct in_addr);
int get_host_rules(struct openvas_rules *, struct in_addr, int);

#endif
