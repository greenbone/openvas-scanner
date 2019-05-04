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
 * @brief Sends a plugin info.
 */
void
send_plug_info (int soc, const char *oid)
{
  int category;
  char *name = NULL, *family = NULL;
  char *cve_id = NULL, *bid = NULL, *xref = NULL, *tag = NULL;
  nvti_t *nvti;

  nvti = nvticache_get_nvt (oid);
  if (!nvti)
    {
      g_warning ("Couldn't fetch plugin %s", oid);
      goto send_cleanup;
    }

  category = nvti_category (nvti);
  assert (category >= ACT_INIT && category <= ACT_END);
  name = nvti_name (nvti);
  if (!name || strchr (name, '\n'))
    {
      g_warning ("Erroneous name for plugin %s", oid);
      goto send_cleanup;
    }
  family = nvti_family (nvti);
  if (!family)
    {
      g_warning ("Missing family for plugin %s", oid);
      goto send_cleanup;
    }

  cve_id = nvti_refs (nvti, "cve");
  bid = nvti_refs (nvti, "bid");
  xref = nvti_xref (nvti);
  tag = nvti_tag (nvti);
  if (tag)
    {
      char *index = tag;
      while (*index)
        {
          if (*index == '\n')
            *index = ';';
          index++;
        }
    }

  send_printf (soc, "%s <|> %s <|> %d <|>  %s <|> %s <|> %s <|> %s <|> %s\n",
               oid, name, category, family,
               (cve_id && *cve_id) ? cve_id : "NOCVE",
               (bid && *bid) ? bid : "NOBID", (xref && *xref) ? xref : "NOXREF",
               (tag && *tag) ? tag : "NOTAG");

  g_free (cve_id);
  g_free (bid);

send_cleanup:
  nvti_free (nvti);
}

/**
 * @brief Sends the list of plugins that the scanner could load to the client,
 * @brief using the OTP format (calls send_plug_info for each).
 * @param soc    Socket to use for sending list of plugins.
 * @param oids   List of OIDs to send.
 * @see send_plug_info
 */
static void
comm_send_pluginlist (int soc, GSList *oids)
{
  send_printf (soc, "SERVER <|> PLUGIN_LIST <|>\n");
  while (oids)
    {
      send_plug_info (soc, oids->data);
      oids = oids->next;
    }
  send_printf (soc, "<|> SERVER\n");
}

/**
 * @brief Sends the list of plugins preferences to the client.
 * @param soc   Socket to use for sending list of preferences.
 * @param oids  List OIDs to send.
 */
static void
send_plugins_preferences (int soc, GSList *oids)
{
  while (oids)
    {
      char *oid = oids->data;
      GSList *nprefs = nvticache_get_prefs (oid);
      int timeout = nvticache_get_timeout (oid);

      if (nprefs || (timeout > 0))
        {
          GSList *tmp = nprefs;

          if (timeout > 0)
            send_printf (soc, "%s:0:entry:Timeout <|> %d\n", oid, timeout);
          while (tmp)
            {
              nvtpref_t *pref = tmp->data;
              send_printf (soc, "%s:%d:%s:%s <|> %s\n", oid, nvtpref_id (pref),
                           nvtpref_type (pref),
                           g_strchomp (nvtpref_name (pref)),
                           nvtpref_default (pref));
              tmp = tmp->next;
            }
        }
      g_slist_free_full (nprefs, (void (*) (void *)) nvtpref_free);
      oids = oids->next;
    }
}

/**
 * @brief Sends the preferences of the scanner.
 * @param soc   Socket to use for sending.
 * @param oids  List of OIDs to send.
 */
static void
comm_send_preferences (int soc, GSList *oids)
{
  GHashTableIter iter;
  void *itername, *itervalue;
  GHashTable *prefs = preferences_get ();

  if (!is_client_present (soc))
    return;
  /* We have to be backward compatible with the NTP/1.0 */
  send_printf (soc, "SERVER <|> PREFERENCES <|>\n");

  g_hash_table_iter_init (&iter, prefs);
  while (g_hash_table_iter_next (&iter, &itername, &itervalue))
    {
      if (!is_scanner_only_pref (itername))
        send_printf (soc, "%s <|> %s\n", (char *) itername, (char *) itervalue);
    }
  send_plugins_preferences (soc, oids);
  send_printf (soc, "<|> SERVER\n");
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

/*-------------------------------------------------------------------------------*/

/**
 * @brief Determine whether a buffer contains a valid feed version.
 *
 * @param[in] feed_version Buffer containing feed_version.
 *
 * @return 1 is valid feed_version, 0 otherwise.
 */
static int
is_valid_feed_version (const char *feed_version)
{
  if (feed_version == NULL)
    return 0;

  while (*feed_version)
    if (!g_ascii_isdigit (*feed_version++))
      return 0;
  return 1;
}

/**
 * @brief Send the OTP NVT_INFO message and then handle any COMPLETE_LIST.
 */
void
comm_send_nvt_info (int soc)
{
  char buf[2048], *feed_version;
  GSList *oids;

  feed_version = nvticache_feed_version ();
  send_printf (soc, "SERVER <|> NVT_INFO <|> %s <|> SERVER\n",
               is_valid_feed_version (feed_version) ? feed_version
                                                    : "NOVERSION");
  g_free (feed_version);

  if (!is_client_present (soc))
    return;
  oids = nvticache_get_oids ();
  for (;;)
    {
      bzero (buf, sizeof (buf));
      if (recv_line (soc, buf, sizeof (buf) - 1) < 0)
        g_warning ("recv_line: %s", strerror (errno));
      if (strstr (buf, "COMPLETE_LIST"))
        comm_send_pluginlist (soc, oids);
      else
        break;
    }
  comm_send_preferences (soc, oids);
  g_slist_free_full (oids, g_free);
}
