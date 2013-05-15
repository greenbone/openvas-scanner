/* OpenVAS
* $Id$
* Description: Provides a user authentication mechanism.
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
*/

#include <stdio.h>      /* for fprintf() */
#include <string.h>     /* for strlen() */
#include <stdlib.h>     /* for exit() */
#include <arpa/inet.h>  /* for inet_aton */
#include <sys/param.h>  /* for MAXPATHLEN */

#include <openvas/misc/system.h>     /* for emalloc */

#include "log.h"
#include "users.h"
#include "rules.h"

char *
user_home (struct arglist *globals)
{
  char *user = arg_get_value (globals, "user");
  char *ret;

  if (!user)
    return NULL;

 /** @todo consider using glib functions */
  ret = emalloc (strlen (OPENVAS_USERS_DIR) + strlen (user) + 2);
  sprintf (ret, "%s/%s", OPENVAS_USERS_DIR, user);

  return ret;
}


/**
 * @brief Add rules to the current user, and return the name of the next user.
 */
void
users_add_rule (struct openvas_rules *rules, char *rule)
{
  struct openvas_rules *start = rules;
  int def = rules->def;
  char *t = rule;
  int len;
#ifdef DEBUG_RULES
  log_write ("parse %s\n", rule);
#endif
  while (rules->next)
    rules = rules->next;
  if (!strncmp (t, "default", 7))
    {
      if (!strncmp (t + 8, "accept", 6))
        def = RULES_ACCEPT;
      else
        def = RULES_REJECT;
      rules_set_def (start, def);
      return;
    }

  if (!strncmp (t, "accept", 6))
    rules->rule = RULES_ACCEPT;
  else
    rules->rule = RULES_REJECT;
  rule = strchr (rule, ' ');
  if (rule)
    {
      rule += sizeof (char);
      t = strchr (rule, '/');
      if (t)
        t[0] = '\0';
      if (rule[0] == '!')
        {
          rules->not = 1;
          rule += sizeof (char);
        }
      else
        rules->not = 0;

      len = strlen (rule);

      while (rule[len - 1] == ' ')
        {
          rule[len - 1] = '\0';
          len--;
        }

      rules->family = AF_INET;

      if (!(inet_aton (rule, &rules->inaddrs.ip)))
        {
          if (strcmp (rule, "client_ip"))
            {
              log_write
                ("Parse error in the user rules : %s is not a valid IP\n",
                 rule);
              exit (1);
            }
          else
            {
              rules->client_ip = 1;
              rules->inaddrs.ip.s_addr = -1;
            }
        }
      else
        rules->client_ip = 0;
      rules->def = def;
      if (t)
        rules->mask = atoi (t + sizeof (char));
      else
        rules->mask = 32;
      if (rules->mask < 0 || rules->mask > 32)
        {
          /* The user may have tried to fool us by entering
             a bogus netmask. Just ignore this rule
           */
          log_write ("User entered an invalid netmask - %s/%d\n",
                     inet_ntoa (rules->inaddrs.ip), rules->mask);
          bzero (rules, sizeof (*rules));
        }
      else
        rules->next = emalloc (sizeof (*rules));
#ifdef DEBUG_RULES
      log_write ("Added rule %s/%d\n", inet_ntoa (rules->inaddrs.ip),
                 rules->mask);
#endif
    }
}


struct openvas_rules *
check_user (char *user, char *dname)
{
  FILE *f;
  char fname[MAXPATHLEN];
  int check_pass = 1;


#ifdef OPENVAS_MAX_USERNAME_LEN
  if (strlen (user) >= OPENVAS_MAX_USERNAME_LEN)
    return BAD_LOGIN_ATTEMPT;
#endif

  if (strstr (user, "..") != NULL || strchr (user, '/') != NULL)
    return BAD_LOGIN_ATTEMPT;

  if (dname != NULL && *dname != '\0')
    {
      snprintf (fname, sizeof (fname), "%s/%s/auth/dname", OPENVAS_USERS_DIR,
                user);
      if ((f = fopen (fname, "r")) == NULL)
        perror (fname);
      else
        {
          char dnameref[512], *p;

          while (check_pass
                 && fgets (dnameref, sizeof (dnameref) - 1, f) != NULL)
            {
              if ((p = strchr (dnameref, '\n')) != NULL)
                *p = '\0';
              if (strcmp (dname, dnameref) == 0)
                check_pass = 0;
            }
          if (check_pass)
            log_write
              ("check_user: Bad DN for user %s\nGiven DN=%s\nLast tried DN=%s\n",
               user, dname, dnameref);
          (void) fclose (f);
        }
    }

  return emalloc (sizeof (struct openvas_rules));
}
