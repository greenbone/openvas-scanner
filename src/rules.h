/* OpenVAS
* $Id$
* Description: rules.c header.
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


#ifndef _OPENVAS_RULES_H
#define _OPENVAS_RULES_H

#include <arpa/inet.h> /* for AF_INET */

#include <openvas/misc/arglists.h>   /* for struct arglist */

/**
 * Representation of a chain of rules.
 */
typedef union inaddrs
{
  struct in_addr ip;
  struct in6_addr ip6;
} inaddrs_t;

struct openvas_rules
{
  inaddrs_t inaddrs;
  int family;
  int client_ip; /**< If set to 1, then 'ip' will be replaced by the client ip
                      when appropriate. */
  int mask;
  int rule;
  int def;  /**< default */
  int not;  /**< not ip  */
  struct openvas_rules *next;
};

#define RULES_ACCEPT 1
#define RULES_REJECT 2
#define CAN_TEST(x) (x==RULES_ACCEPT)
void rules_init (struct openvas_rules **, struct arglist *);
void rules_free (struct openvas_rules *);
void rules_add (struct openvas_rules **, struct openvas_rules **, char *);
struct openvas_rules *rules_parse (char *, struct openvas_rules *, int);
struct openvas_rules *rules_dup (struct openvas_rules *);
void rules_set_def (struct openvas_rules *, int);
void rules_set_client_ip (struct openvas_rules *, inaddrs_t *, int family);
int get_host_rules (struct openvas_rules *, inaddrs_t inaddrs);

#endif
