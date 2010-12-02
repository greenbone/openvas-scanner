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

#include <openvas/misc/system.h>     /* for efree */

#include <pwd.h>
#include "comm.h"
#include "utils.h"
#include "rules.h"
#include "log.h"

static int
rules_validateandgetipaddr (char *ip, int family, struct sockaddr *sa,
                            int numeric)
{
  struct addrinfo hints;
  struct addrinfo *ai;
  int retval;

  memset (&hints, 0, sizeof (hints));
  switch (family)
    {
    case AF_INET:
      hints.ai_family = AF_INET;
      break;
    case AF_INET6:
      hints.ai_family = AF_INET6;
      break;
    default:
      return -1;
    }
  if (numeric)
    hints.ai_flags = AI_NUMERICHOST;

  retval = getaddrinfo (ip, NULL, &hints, &ai);
  if (!retval)
    {
      if (family == AF_INET)
        {
          memcpy (sa, ai->ai_addr, sizeof (struct sockaddr_in));
        }
      else
        {
          memcpy (sa, &((struct sockaddr_in6 *) (ai->ai_addr))->sin6_addr,
                  sizeof (struct sockaddr_in6));
        }
      freeaddrinfo (ai);
      return 0;
    }
  return -1;
}

static void
rules_ipv6addrmask (struct in6_addr *in6addr, int mask)
{
  int wordmask;
  int word;
  uint32_t *ptr;
  uint32_t addr;

  word = mask / 32;
  wordmask = mask % 32;
  ptr = (uint32_t *) in6addr;
  switch (word)
    {
    case 0:
      ptr[1] = ptr[2] = ptr[3] = 0;
      addr = ptr[0];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[0] = addr;
      break;
    case 1:
      ptr[2] = ptr[3] = 0;
      addr = ptr[1];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[1] = addr;
      break;
    case 2:
      ptr[3] = 0;
      addr = ptr[2];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[2] = addr;
      break;
    case 3:
      addr = ptr[3];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[3] = addr;
      break;
    }
}

/**
 * @brief Returns the name of the rules file.
 *
 * @param preferences Preference- arglist (where rules are hooked in).
 *
 * @return Filename of rules file.
 */
static char *
rules_get_fname (struct arglist *preferences)
{
  char *t;
  if ((t = arg_get_value (preferences, "rules")))
    return (t);
  else
    return (OPENVASSD_RULES);
}

struct openvas_rules *
rules_new (preferences)
     struct arglist *preferences;
{
  char *filename = rules_get_fname (preferences);
  struct openvas_rules *nr = emalloc (sizeof (*nr));
  FILE *f;
  nr->rule = RULES_ACCEPT;

  f = fopen (filename, "w");
  if (!f)
    {
      perror ("rules_new():open ");
      return nr;
    }

  fprintf (f, "#\n# OpenVAS rules\n#\n\n");
  fprintf (f, "# Syntax : accept|reject address/netmask\n");
  fprintf (f, "\n# Accept to test anything : \n");
  fprintf (f, "default accept\n");
  fclose (f);
  return nr;
}


int
rules_init_aux (struct openvas_rules *rules, FILE * file, char *buffer, int len,
                int def)
{
  struct sockaddr_in saddr;
  struct sockaddr_in6 s6addr;

  while (1)
    {
      buffer[0] = buffer[len - 1] = '\0';
      if (!(fgets (buffer, len - 1, file)))
        {
          rules->next = NULL;
          return def;
        }
      else
        {
          char *t = buffer;
          char *v;
          int t_len;
          if (t[strlen (t) - 1] == '\n')
            t[strlen (t) - 1] = '\0';
          while ((t[0] == ' ') || (t[0] == '\t'))
            t++;
          if ((t[0] == '#') || t[0] == '\0')
            continue;
          v = strchr (t, ' ');
          if (v == NULL)
            {
              printf ("Parse error in the rules file : %s\n", buffer);
              continue;
            }
          else
            {
              if (!strncmp (t, "accept", 6))
                rules->rule = RULES_ACCEPT;
              else if (!strncmp (t, "default", 7))
                {
                  if (!strncmp (t + 8, "accept", 6))
                    def = RULES_ACCEPT;
                  else
                    def = RULES_REJECT;
                  continue;
                }
              else if ((!strncmp (t, "reject", 6)) || (!strncmp (t, "deny", 4)))
                rules->rule = RULES_REJECT;
              else
                {
                  printf ("Parse error in the rules file : %s\n", buffer);
                  continue;
                }
              t = v + sizeof (char);
              v = strchr (t, '/');
              if (v)
                v[0] = '\0';
              if (t[0] == '!')
                {
                  rules->not = 1;
                  t++;
                }
              else
                rules->not = 0;
              t_len = strlen (t);
              while (t[t_len - 1] == ' ')
                {
                  t[t_len - 1] = '\0';
                  t_len--;
                }

              if (!rules_validateandgetipaddr
                  (t, AF_INET, (struct sockaddr *) &saddr, 1))
                {
                  rules->inaddrs.ip.s_addr = saddr.sin_addr.s_addr;
                  rules->family = AF_INET;
                  rules->client_ip = 0;
                }
              else
                if (!rules_validateandgetipaddr
                    (t, AF_INET6, (struct sockaddr *) &s6addr, 1))
                {
                  memcpy (&rules->inaddrs.ip6, &s6addr,
                          sizeof (struct sockaddr_in6));
                  rules->family = AF_INET6;
                  rules->client_ip = 0;
                }
              else
                {
                  if (strcmp (t, "client_ip"))
                    {
                      printf
                        ("Parse error in the rules file : '%s' is not a valid IP\n",
                         t);
                      continue;
                    }
                  else
                    {
                      rules->client_ip = 1;
                    }
                }

              if (v)
                rules->mask = atoi (v + sizeof (char));
              else
                rules->mask = rules->family == AF_INET ? 32 : 128;

              if (rules->family == AF_INET)
                {
                  if (rules->mask < 0 || rules->mask > 32)
                    {
                      printf
                        ("Error in the rules file. %s is not a valid cidr netmask\n",
                         v + sizeof (char));
                      EXIT (1);
                    }
                  if (rules->mask > 0)
                    {
                      rules->inaddrs.ip.s_addr =
                        ntohl (rules->inaddrs.ip.s_addr) >> (32 - rules->mask);
                      rules->inaddrs.ip.s_addr =
                        htonl (rules->inaddrs.ip.s_addr << (32 - rules->mask));;
                    }
                  else
                    rules->inaddrs.ip.s_addr = 0;
                }
              else
                {
                  if (rules->mask < 0 || rules->mask > 128)
                    {
                      printf
                        ("Error in the rules file. %s is not a valid cidr netmask\n",
                         v + sizeof (char));
                      EXIT (1);
                    }
                  if (rules->mask > 0)
                    rules_ipv6addrmask (&rules->inaddrs.ip6, rules->mask);
                  else
                    {
                      rules->inaddrs.ip6.s6_addr32[0] = 0;
                      rules->inaddrs.ip6.s6_addr32[1] = 0;
                      rules->inaddrs.ip6.s6_addr32[2] = 0;
                      rules->inaddrs.ip6.s6_addr32[3] = 0;
                    }
                }
              rules->next = emalloc (sizeof (*rules));
              rules = rules->next;
            }
        }
    }
}

void
rules_init (rules, preferences)
     struct openvas_rules **rules;
     struct arglist *preferences;
{
  struct openvas_rules *nr = emalloc (sizeof (*nr));
  char *filename = rules_get_fname (preferences);
  FILE *f = fopen (filename, "r");
  int def = RULES_ACCEPT;
  char buffer[1024];
  if (f == NULL)
    {
      rules_new (preferences);
      nr->rule = RULES_ACCEPT;
      nr->next = emalloc (sizeof (*nr));
      nr->def = RULES_ACCEPT;
      *rules = nr;
      return;
    }
  def = rules_init_aux (nr, f, buffer, sizeof (buffer), 0);
  *rules = nr;
  rules_set_def (*rules, def);

  fclose (f);
}

struct openvas_rules *
rules_cat (struct openvas_rules *a, struct openvas_rules *b)
{
  struct openvas_rules *s = a;
  if (a)
    while (a->next != NULL && a->next->next != NULL)
      a = a->next;
  if (a->next)
    {
      efree (&a->next);
      a->next = b;
    }
  else
    {
      if (a)
        efree (&a);
      s = b;
    }
  return s;
}


void
rules_set_client_ip (struct openvas_rules *r, inaddrs_t * addrs, int family)
{
  while (r)
    {
      if (r->client_ip)
        {
          if (family == AF_INET)
            {
              r->inaddrs.ip.s_addr = addrs->ip.s_addr;
            }
          else
            {
              memcpy (&r->inaddrs.ip6, &addrs->ip6, sizeof (struct in6_addr));
            }
        }
      r = r->next;
    }
}

void
rules_set_def (struct openvas_rules *r, int def)
{
  if (!r)
    return;
  else
    {
      r->def = def;
      rules_set_def (r->next, def);
    }
}

void
rules_add (struct openvas_rules **rules, struct openvas_rules **user,
           char *username)
{
  struct openvas_rules *accept_rules = emalloc (sizeof (**rules));
  struct openvas_rules *reject_rules = emalloc (sizeof (**rules));
  struct openvas_rules *t, *o, *p;
  int def = (*rules)->def;

  if (!def)
    def = RULES_ACCEPT;
#ifdef DEBUG_RULES
  t = *rules;
  if (t)
    while (t->next)
      {
        log_write ("DEFAULT: %s/%d\n", inet_ntoa (t->inaddrs.ip), t->mask);
        t = t->next;
      }
#endif
  t = *user;
  o = accept_rules;
  p = reject_rules;
  if (t->def == RULES_REJECT)
    def = RULES_REJECT;

  if (t != NULL)
    while (t->next != NULL)
      {
#ifdef DEBUG_RULES
        log_write ("rules_add : %d %s/%d\n", t->rule, inet_ntoa (t->inaddrs.ip),
                   t->mask);
#endif
        if (t->rule == RULES_ACCEPT)
          {
            if (t->family == AF_INET)
              accept_rules->inaddrs.ip.s_addr = t->inaddrs.ip.s_addr;
            else
              {
                memcpy (&accept_rules->inaddrs.ip6, &t->inaddrs.ip6,
                        sizeof (struct in6_addr));
              }
            accept_rules->family = t->family;
            accept_rules->client_ip = t->client_ip;
            accept_rules->mask = t->mask;
            accept_rules->rule = t->rule;
            accept_rules->not = t->not;
            accept_rules->next = emalloc (sizeof (**rules));
            accept_rules = accept_rules->next;
          }
        else
          {
            if (t->family == AF_INET)
              reject_rules->inaddrs.ip.s_addr = t->inaddrs.ip.s_addr;
            else
              {
                memcpy (&reject_rules->inaddrs.ip6, &t->inaddrs.ip6,
                        sizeof (struct in6_addr));
              }
            reject_rules->family = t->family;
            reject_rules->client_ip = t->client_ip;
            reject_rules->mask = t->mask;
            reject_rules->rule = t->rule;
            reject_rules->not = t->not;
            reject_rules->next = emalloc (sizeof (**rules));
            reject_rules = reject_rules->next;
          }
        t = t->next;
      }

  accept_rules = o;
  reject_rules = p;
  if (def == RULES_ACCEPT)
    *rules = rules_cat (rules_cat (reject_rules, *rules), accept_rules);
  else
    *rules = rules_cat (reject_rules, rules_cat (*rules, accept_rules));

  rules_set_def (*rules, def);

#ifdef DEBUG_RULES
  log_write ("After rules_cat : \n");
  rules_dump (*rules);
#endif
}

#ifdef DEBUG_RULES
void
rules_dump (struct openvas_rules *rules)
{
  struct openvas_rules *r;
  char buf[INET6_ADDRSTRLEN];
  r = rules;
  while (r)
    {
      if (r->family == AF_INET)
        log_write ("rule: ip4 %d %c%s/%d (def %d)\n", r->rule,
                   r->not ? '!' : ' ', inet_ntop (r->family, &r->inaddrs.ip,
                                                  buf, sizeof (buf)), r->mask,
                   r->def);
      else
        log_write ("rule: ip6 %d %c%s/%d (def %d)\n", r->rule,
                   r->not ? '!' : ' ', inet_ntop (r->family, &r->inaddrs.ip6,
                                                  buf, sizeof (buf)), r->mask,
                   r->def);
      r = r->next;
    }
}
#endif

int
get_host_rules (struct openvas_rules *rules, inaddrs_t addr)
{
  struct in_addr tstaddr;
  struct in6_addr tstaddr6;

  tstaddr.s_addr = 0;

  if (!rules)
    {
      fprintf (stderr, "???? no rules - this is likely to be a bug\n");
      fprintf (stderr, "Please report at bugs.openvas.org\n");
      return RULES_ACCEPT;
    }

  while (rules)
    {
      if (!rules->next)
        return rules->def;

      if (rules->family == AF_INET)
        {
          tstaddr.s_addr = addr.ip6.s6_addr32[3];
          if (rules->mask > 0)
            {
              tstaddr.s_addr = ntohl (tstaddr.s_addr) >> (32 - rules->mask);
              tstaddr.s_addr = htonl (tstaddr.s_addr << (32 - rules->mask));
            }
          else
            tstaddr.s_addr = 0;

          if (rules->not)
            {
              if (tstaddr.s_addr != rules->inaddrs.ip.s_addr)
                return (rules->rule);
            }
          else
            {
              if (tstaddr.s_addr == rules->inaddrs.ip.s_addr)
                {
                  return (rules->rule);
                }
            }
        }
      else
        {
          /* Check whether ipv6 address can be scanned */
          memcpy (&tstaddr6, &addr.ip6, sizeof (struct in6_addr));
          if (rules->mask > 0)
            rules_ipv6addrmask (&tstaddr6, rules->mask);
          else
            {
              tstaddr6.s6_addr32[0] = 0;
              tstaddr6.s6_addr32[1] = 0;
              tstaddr6.s6_addr32[2] = 0;
              tstaddr6.s6_addr32[3] = 0;
            }
          if (rules->not)
            {
              /* If not equal return rules->rule */
              if (tstaddr6.s6_addr32[0] != rules->inaddrs.ip6.s6_addr32[0]
                  || tstaddr6.s6_addr32[1] != rules->inaddrs.ip6.s6_addr32[1]
                  || tstaddr6.s6_addr32[2] != rules->inaddrs.ip6.s6_addr32[2]
                  || tstaddr6.s6_addr32[3] != rules->inaddrs.ip6.s6_addr32[3])
                return (rules->rule);
            }
          else
            {
              /* If equal return rules->rule */
              if (tstaddr6.s6_addr32[0] == rules->inaddrs.ip6.s6_addr32[0]
                  && tstaddr6.s6_addr32[1] == rules->inaddrs.ip6.s6_addr32[1]
                  && tstaddr6.s6_addr32[2] == rules->inaddrs.ip6.s6_addr32[2]
                  && tstaddr6.s6_addr32[3] == rules->inaddrs.ip6.s6_addr32[3])
                return (rules->rule);
            }
        }
      rules = rules->next;
    }
  fprintf (stderr, "Rules check ended: May be bug? Please report\n");
  return RULES_ACCEPT;
}

void
rules_free (struct openvas_rules *rules)
{
  while (rules != NULL)
    {
      struct openvas_rules *next = rules->next;
      efree (&rules);
      rules = next;
    }
}
