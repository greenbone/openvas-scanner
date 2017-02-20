/* OpenVAS
 * $Id$
 * Description: Header file for module ftp_funcs.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* this works for libc6 systems, unclear
 * wether it will not work on other systems */
#include <netinet/in.h>

#include "network.h"

int
ftp_log_in (int soc, char *username, char *passwd)
{
  char buf[1024];
  int n;
  int counter;

  buf[sizeof (buf) - 1] = '\0';
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    return (1);

  if (strncmp (buf, "220", 3) != 0)
    {
      return 1;
    }

  counter = 0;
  while (buf[3] == '-' && n > 0 && counter < 1024)
    {
      n = recv_line (soc, buf, sizeof (buf) - 1);
      counter++;
    }

  if (counter >= 1024)
    return 1;                   /* Rogue FTP server */

  if (n <= 0)
    return 1;


  snprintf (buf, sizeof (buf), "USER %s\r\n", username);
  write_stream_connection (soc, buf, strlen (buf));
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    return 1;
  if (strncmp (buf, "230", 3) == 0)
    {
      counter = 0;
      while (buf[3] == '-' && n > 0 && counter < 1024)
        {
          n = recv_line (soc, buf, sizeof (buf) - 1);
          counter++;
        }
      return 0;
    }

  if (strncmp (buf, "331", 3) != 0)
    {
      return 1;
    }

  counter = 0;
  n = 1;
  while (buf[3] == '-' && n > 0 && counter < 1024)
    {
      n = recv_line (soc, buf, sizeof (buf) - 1);
      counter++;
    }

  if (counter >= 1024)
    return 1;


  snprintf (buf, sizeof (buf), "PASS %s\r\n", passwd);
  write_stream_connection (soc, buf, strlen (buf));
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    return 1;

  if (strncmp (buf, "230", 3) != 0)
    {
      return 1;
    }

  counter = 0;
  n = 1;
  while (buf[3] == '-' && n > 0 && counter < 1024)
    {
      n = recv_line (soc, buf, sizeof (buf) - 1);
      counter++;
    }

  return 0;
}


int
ftp_get_pasv_address (int soc, struct sockaddr_in *addr)
{
  char buf[512];
  char *t, *s;
  unsigned char l[6];
  unsigned long *a;
  unsigned short *p;

  snprintf (buf, 7, "PASV\r\n");
  write_stream_connection (soc, buf, strlen (buf));
  bzero (buf, sizeof (buf));
  bzero (addr, sizeof (struct sockaddr_in));
  recv_line (soc, buf, sizeof (buf) - 1);

  if (strncmp (buf, "227", 3) != 0)
    return 1;

  t = strchr (buf, '(');
  if (t == NULL)
    return 1;
  t++;
  s = strchr (t, ',');
  if (s == NULL)
    return 1;

  s[0] = '\0';

  l[0] = (unsigned char) atoi (t);
  s++;
  t = strchr (s, ',');
  if (t == NULL)
    return 1;
  t[0] = 0;
  l[1] = (unsigned char) atoi (s);
  t++;
  s = strchr (t, ',');
  if (s == NULL)
    return 1;
  s[0] = 0;
  l[2] = (unsigned char) atoi (t);
  s++;
  t = strchr (s, ',');
  if (t == NULL)
    return 1;
  t[0] = 0;
  l[3] = (unsigned char) atoi (s);
  t++;
  s = strchr (t, ',');
  if (s == NULL)
    return 1;
  s[0] = 0;
  l[4] = (unsigned char) atoi (t);
  s++;
  t = strchr (s, ')');
  if (t == NULL)
    return 1;
  t[0] = 0;
  l[5] = (unsigned char) atoi (s);
  a = (unsigned long *) l;
  p = (unsigned short *) (l + 4);

  addr->sin_addr.s_addr = *a;
  addr->sin_port = *p;
  addr->sin_family = AF_INET;
  return 0;
}
