/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

/**
 * @file comm.c
 * @brief Communication manager; it manages the NTP Protocol version 1.0
 * and 1.1.
 */

#include "comm.h"

#include "../misc/network.h"        /* for recv_line */
#include "../misc/nvt_categories.h" /* for ACT_INIT */
#include "../misc/plugutils.h"
#include "../nasl/nasl.h"
#include "ntp.h"
#include "pluginload.h" /* for current_loading_plugins */
#include "pluginscheduler.h"
#include "sighand.h"
#include "utils.h"

#include <errno.h> /* for errno */
#include <glib.h>
#include <gvm/base/prefs.h>     /* for preferences_get() */
#include <gvm/util/nvticache.h> /* for nvticache_t */
#include <stdio.h>              /* for FILE */
#include <stdlib.h>             /* for atoi() */
#include <string.h>             /* for strchr() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Initializes the communication between the scanner (us) and the client.
 *
 * @return 0 if success, -1 if error.
 */
int
comm_init (int soc)
{
  char buf[1024];
  int n;

  /* We must read the version of the OTP the client
     wants us to use */
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    {
      g_debug ("Failed reading client-requested OTP version.");
      return -1;
    }

  buf[sizeof (buf) - 1] = '\0';
  if (strncmp (buf, "< OTP/2.0 >", 11))
    {
      if (g_str_is_ascii (buf))
        g_debug ("Unknown client-requested OTP version: %s.", buf);
      else
        g_debug ("Unknown client-requested OTP version.");
      return -1;
    }
  nsend (soc, "< OTP/2.0 >\n", 12, 0);
  return 0;
}

/**
 * @brief Informs the client that the scanner is still loading.
 *
 * @param[in]   soc Socket to send and receive from.
 *
 * @return 0 if success, -1 if error.
 */
int
comm_loading (int soc)
{
  int n, len;
  char buf[256];
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    {
      g_debug ("Failed reading client input.");
      return -1;
    }
  /* Always respond with SCANNER_LOADING. */
  g_snprintf (buf, sizeof (buf), "SCANNER_LOADING <|> %d <|> %d\n",
              current_loading_plugins (), total_loading_plugins ());
  len = strlen (buf);
  n = nsend (soc, buf, len, 0);
  if (n != len)
    return -1;
  while (n > 0)
    n = recv_line (soc, buf, sizeof (buf) - 1);

  return 0;
}

/**
 * Determines if the client is still connected.
 * @return 1 if the client is here, 0 if it's not.
 */
static int
is_client_present (int soc)
{
  fd_set rd;
  struct timeval tv;
  int e;

  FD_ZERO (&rd);
  FD_SET (soc, &rd);
again:
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  errno = 0;
  e = select (soc + 1, &rd, NULL, NULL, &tv);
  if (e < 0)
    {
      if (errno == EINTR)
        goto again;
      return 0;
    }

  if (e > 0 && !data_left (soc))
    return 0;
  return 1;
}

/**
 * @brief This function must be called at the end of a session.
 */
void
comm_terminate (int soc)
{
  send_printf (soc, "SERVER <|> BYE <|> BYE <|> SERVER\n");
  while (is_client_present (soc))
    {
      char buffer[4096];
      int n;

      n = recv_line (soc, buffer, sizeof (buffer) - 1);
      if (n < 0 || *buffer == '\0')
        return;
    }
}

/**
 * @brief This function waits for the attack order of the client.
 * Meanwhile, it processes all the messages the client could send.
 */
int
comm_wait_order (struct scan_globals *globals)
{
  int soc = globals->global_socket;

  for (;;)
    {
      static char str[2048];
      int n;

      memset (str, '\0', sizeof (str));
      n = recv_line (soc, str, sizeof (str) - 1);
      if (n < 0)
        {
          g_warning ("Client closed the communication");
          return -1;
        }
      if (str[0] == '\0' && !is_client_present (soc))
        return -1;

      n = ntp_parse_input (globals, str);
      if (n == 0)
        return 0;
      else if (n == -1)
        {
          g_warning ("Client input parsing error: %s", str);
          return -1;
        }
    }
}
