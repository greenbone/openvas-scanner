/* OpenVAS
* $Id$
* Description: A bunch of miscellaneous functions, mostly file conversions.
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

#include <stdio.h>     /* for fprintf() */
#include <stdlib.h>    /* for atoi() */
#include <string.h>    /* for strchr() */
#include <sys/wait.h>  /* for waitpid() */
#include <errno.h>     /* for errno() */
#include <sys/ioctl.h> /* for ioctl() */
#include <sys/stat.h>  /* for stat() */

#include <openvas/misc/network.h>    /* for stream_zero */
#include <openvas/misc/plugutils.h>  /* for plug_get_launch */
#include <openvas/misc/system.h>     /* for emalloc */

#include "log.h"
#include "comm.h"
#include "ntp_11.h"
#include "utils.h"
#include "preferences.h"
#include "pluginscheduler.h"

extern int global_max_hosts;
extern int global_max_checks;


/**
 * @brief Returns 1 if the two arglists have a name in common.
 *
 * @return 0 if l1 and l2 have a name in common, 0 otherwise.
 */
int
common (l1, l2)
     struct arglist *l1, *l2;
{
  struct arglist *l2_start = l2;
  if (!l1 || !l2)
    {
      return 0;
    }
  while (l1->next != NULL)
    {
      l2 = l2_start;
      while (l2->next != NULL)
        {
          if (strcmp (l1->name, l2->name) == 0)
            return 1;
          l2 = l2->next;
        }
      l1 = l1->next;
    }
  return 0;
}

/**
 * Converts a user comma delimited input (1,2,3) into an
 * arglist.
 */
struct arglist *
list2arglist (list)
     char *list;
{
  struct arglist *ret = emalloc (sizeof (struct arglist));
  char *t = strchr (list, ',');

  if (!list)
    {
      efree (&ret);
      return ret;
    }


  while ((t = strchr (list, ',')) != NULL)
    {
      t[0] = 0;
      while (list[0] == ' ')
        list++;
      if (list[0] != '\0')
        {
          arg_add_value (ret, list, ARG_INT, 0, (void *) 1);
        }
      list = t + 1;
    }

  while (list[0] == ' ')
    list++;
  if (list[0] != '\0')
    {
      arg_add_value (ret, list, ARG_INT, 0, (void *) 1);
    }
  return ret;
}




/**
 * Get the max number of hosts to test at the same time.
 */
int
get_max_hosts_number (preferences)
     struct arglist *preferences;
{
  int max_hosts;
  if (arg_get_value (preferences, "max_hosts"))
    {
      max_hosts = atoi (arg_get_value (preferences, "max_hosts"));
      if (max_hosts <= 0)
        {
          log_write ("Error ! max_hosts = %d -- check %s\n", max_hosts,
                     (char *) arg_get_value (preferences, "config_file"));
          max_hosts = global_max_hosts;
        }
      else if (max_hosts > global_max_hosts)
        {
          log_write ("Client tried to raise the maximum hosts number - %d. Using %d. Change 'max_hosts' in openvassd.conf if \
you believe this is incorrect\n", max_hosts,
                     global_max_hosts);
          max_hosts = global_max_hosts;
        }
    }
  else
    max_hosts = global_max_hosts;
  return (max_hosts);
}

/**
 * Get the max number of plugins to launch against the remote
 * host at the same time
 */
int
get_max_checks_number (preferences)
     struct arglist *preferences;
{
  int max_checks;
  if (arg_get_value (preferences, "max_checks"))
    {
      max_checks = atoi (arg_get_value (preferences, "max_checks"));
      if (max_checks <= 0)
        {
          log_write ("Error ! max_hosts = %d -- check %s\n", max_checks,
                     (char *) arg_get_value (preferences, "config_file"));
          max_checks = global_max_checks;
        }
      else if (max_checks > global_max_checks)
        {
          log_write ("Client tried to raise the maximum checks number - %d. Using %d. Change 'max_checks' in openvassd.conf if \
you believe this is incorrect\n", max_checks,
                     global_max_checks);
          max_checks = global_max_checks;
        }
    }
  else
    max_checks = global_max_checks;
  return (max_checks);
}


/**
 * @brief Returns the number of plugins that will be launched.
 */
int
get_active_plugins_number (struct arglist *plugins)
{
  int num = 0;

  if (plugins != NULL)
    while (plugins->next != NULL)
      {
        if (plug_get_launch (plugins->value) != LAUNCH_DISABLED)
          num++;
        plugins = plugins->next;
      }

  return num;
}

/*--------------------------------------------------------------------*/


/**
 * Converts a hostnames arglist
 * to a space delimited lists of hosts
 * in one string and returns it.
 */
char *
hosts_arglist_to_string (struct arglist *hosts)
{
  int num_hosts = 0;
  struct arglist *start = hosts;
  int hosts_len = 0;
  char *ret;

  while (hosts && hosts->next)
    {
      if (hosts->value)
        {
          num_hosts++;
          hosts_len += strlen (hosts->value);
        }
      hosts = hosts->next;
    }

  ret = emalloc (hosts_len + 2 * num_hosts + 1);

  hosts = start;

  while (hosts && hosts->next)
    {
      if (hosts->value)
        {
          strcat (ret, hosts->value);
          strcat (ret, " ");
        }
      hosts = hosts->next;
    }
  return (ret);
}


/**
 * Determines if a process is alive - as reliably as we can
 */
int
process_alive (pid_t pid)
{
  int i, ret;
  if (pid == 0)
    return 0;

  for (i = 0, ret = 1; (i < 10) && (ret > 0); i++)
    ret = waitpid (pid, NULL, WNOHANG);

  return kill (pid, 0) == 0;
}


/**
 * Determines if the client is still connected.
 * @return 1 if the client is here, 0 if it's not.
 */
int
is_client_present (soc)
     int soc;
{
  fd_set rd;
  struct timeval tv;
  int m;
  int e;

  stream_zero (&rd);
  m = stream_set (soc, &rd);
again:
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  e = select (m + 1, &rd, NULL, NULL, &tv);
  if (e < 0 && errno == EINTR)
    goto again;

  if (e > 0)
    {
      int len = data_left (openvas_get_socket_from_connection (soc));
      if (!len)
        {
          log_write ("Communication closed by client\n");
          return 0;
        }
    }
  return 1;
}

int
data_left (soc)
     int soc;
{
  int data = 0;
  ioctl (soc, FIONREAD, &data);
  return data;
}

void
wait_for_children1 ()
{
  int e, n = 0;
  do
    {
      errno = 0;
      e = waitpid (-1, NULL, WNOHANG);
      n++;
    }
  while ((e > 0 || errno == EINTR) && n < 20);
}
