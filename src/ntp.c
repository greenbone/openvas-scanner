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
 * @file ntp.c
 * @brief OpenVAS Transfer Protocol handling.
 */

#include "ntp.h"

#include <string.h> /* for strlen() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/*----------------------------------------------------------

   Communication protocol: timestamps

 ----------------------------------------------------------*/

static int
__ntp_timestamp_scan_host (kb_t kb, char *msg)
{
  char timestr[1024];
  char *tmp;
  time_t t;
  int len;

  t = time (NULL);
  tmp = ctime (&t);
  timestr[sizeof (timestr) - 1] = '\0';
  strncpy (timestr, tmp, sizeof (timestr) - 1);
  len = strlen (timestr);
  if (timestr[len - 1] == '\n')
    timestr[len - 1] = '\0';

  /* For external tools */
  if (!strcmp (msg, "HOST_START"))
    kb_item_push_str (kb, "internal/start_time", timestr);
  else
    kb_item_push_str (kb, "internal/end_time", timestr);

  return 0;
}

int
ntp_timestamp_host_scan_starts (kb_t kb)
{
  return __ntp_timestamp_scan_host (kb, "HOST_START");
}

int
ntp_timestamp_host_scan_ends (kb_t kb)
{
  return __ntp_timestamp_scan_host (kb, "HOST_END");
}
