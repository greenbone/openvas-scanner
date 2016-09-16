/* OpenVAS
* $Id$
* Description: OpenVAS Transfer Protocol handling.
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

#include <string.h> /* for strlen() */
#include <stdlib.h> /* for atoi() */

#include <glib.h>

#include <openvas/misc/network.h>    /* for recv_line */
#include <openvas/misc/internal_com.h> /* for INTERNAL_COMM_MSG_TYPE_DATA */
#include <openvas/misc/prefs.h>        /* for prefs_set() */

#include "ntp.h"
#include "otp.h"
#include "comm.h"
#include "log.h"
#include "utils.h"
#include "hosts.h"

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x):(y))
#endif


static int ntp_read_prefs (int);
static int ntp_long_attack (int);
static int ntp_recv_file (struct arglist *);

/**
 * @brief Parses the input sent by the client before the NEW_ATTACK message.
 */
int
ntp_parse_input (struct arglist *globals, char *input)
{
  char *str;
  int result = 1;               /* default return value is 1 */
  int soc = arg_get_value_int (globals, "global_socket");

  if (*input == '\0')
    return -1;
  str = strstr (input, " <|> ");
  if (str == NULL)
    return 1;

  str[0] = '\0';

  if (strcmp (input, "CLIENT") == 0)
    {
      input = str + 5;
      str = strchr (input, ' ');
      if (str != NULL)
        str[0] = '\0';

      if (input[strlen (input) - 1] == '\n')
        input[strlen (input) - 1] = '\0';

      switch (otp_get_client_request (input))
        {
        case CREQ_ATTACHED_FILE:
          ntp_recv_file (globals);
          break;

        case CREQ_LONG_ATTACK:
          result = ntp_long_attack (soc);
          break;

        case CREQ_PREFERENCES:
          ntp_read_prefs (soc);
          break;

        case CREQ_STOP_WHOLE_TEST:
          log_write ("Stopping the whole test (requested by client)");
          hosts_stop_all ();
          break;

        case CREQ_NVT_INFO:
          {
            comm_send_nvt_info (soc);
            comm_send_preferences (soc);
            break;
          }

        case CREQ_UNKNOWN:
          break;
        }
    }

  return (result);
}

static int
ntp_long_attack (int soc)
{
  char input[16384];
  int size;
  char *target;
  int n;

  n = recv_line (soc, input, sizeof (input) - 1);
  if (n <= 0)
    return -1;

#if DEBUGMORE
  log_write ("long_attack :%s\n", input);
#endif
  if (!strncmp (input, "<|> CLIENT", sizeof ("<|> CLIENT")))
    return 1;
  size = atoi (input);
  target = g_malloc0 (size + 1);

  n = 0;
  while (n < size)
    {
      int e;
      e = nrecv (soc, target + n, size - n, 0);
      if (e > 0)
        n += e;
      else
        {
          g_free (target);
          return -1;
        }
    }

  prefs_set ("TARGET", target);

  g_free (target);

  return 0;
}

/**
 * @brief Reads in "server" prefs sent by client.
 *
 * @param int   Socket to read from.
 * @return Always 0.
 */
static int
ntp_read_prefs (int soc)
{
  char *input;
  int input_sz = 1024 * 1024 * 2; /* this is sufficient for a plugin_set
                                     for upto 69K OIDs */ 

  input = g_malloc0 (input_sz);
  for (;;)
    {
      int n;
      input[0] = '\0';
      n = recv_line (soc, input, input_sz - 1);

      if (n < 0 || input[0] == '\0')
        {
          log_write ("Empty data string -- closing comm. channel");
          exit (0);
        }

      if (strstr (input, "<|> CLIENT") != NULL) /* finished = 1; */
        break;
      /* else */

      {
        char *pref;
        char *v;
        pref = input;
        v = strchr (input, '<');
        if (v)
          {
            char *value;
            v -= 1;
            v[0] = 0;

            value = v + 5;
            /*
             * "system" prefs can't be changed
             */
            if (is_scanner_only_pref (pref))
              continue;

            if (value[0] != '\0')
              value[strlen (value) - 1] = '\0';

            prefs_set (pref, value);
          }
      }
    }

  g_free (input);
  return (0);
}

/**
 * @brief Adds a 'translation' entry for a file sent by the client.
 *
 * Files sent by the client are stored in memory on the server side.
 * In order to access these files, their original name ('local' to the client)
 * can be 'translated' into the file contents of the in-memory copy of the
 * file on the server side.
 *
 * @param globals    Global arglist.
 * @param remotename Name of the file as referenced by the client.
 * @param contents   Contents of the file.
 */
static void
files_add_translation (struct arglist *globals, const char *remotename,
                       char *contents)
{
  GHashTable *trans = arg_get_value (globals, "files_translation");
  // Register the mapping table if none there yet
  if (trans == NULL)
    {
      trans = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
      arg_add_value (globals, "files_translation", ARG_PTR, trans);
    }

  g_hash_table_insert (trans, g_strdup (remotename), contents);
}

/**
 * @brief Adds a 'content size' entry for a file sent by the client.
 *
 * Files sent by the client are stored in memory on the server side.
 * Because they may be binary we need to store the size of the uploaded file as
 * well. This function sets up a mapping from the original name sent by the
 * client to the file size.
 *
 * @param globals    Global arglist.
 * @param remotename Name of the file as referenced by the client.
 * @param filesize   Size of the file in bytes.
 */
static void
files_add_size_translation (struct arglist *globals, const char *remotename,
                            const long filesize)
{
  GHashTable *trans = arg_get_value (globals, "files_size_translation");
  gchar *filesize_str = g_strdup_printf ("%ld", filesize);

  // Register the mapping table if none there yet
  if (trans == NULL)
    {
      trans = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
      arg_add_value (globals, "files_size_translation", ARG_PTR, trans);
    }

  g_hash_table_insert (trans, g_strdup (remotename), g_strdup (filesize_str));
}

/**
 * @brief Receive a file sent by the client.
 *
 * @return 0 if successful, -1 in case of errors.
 */
int
ntp_recv_file (struct arglist *globals)
{
  int soc = arg_get_value_int (globals, "global_socket");
  char input[4096];
  char *origname, *contents;
  gchar *cont_ptr = NULL;
  int n;
  size_t bytes = 0, tot = 0;

  n = recv_line (soc, input, sizeof (input) - 1);
  if (n <= 0)
    return -1;

  if (strncmp (input, "name: ", strlen ("name: ")) == 0)
    {
      origname = g_strdup (input + sizeof ("name: ") - 1);
      if (origname[strlen (origname) - 1] == '\n')
        origname[strlen (origname) - 1] = '\0';
    }
  else
    return -1;

  n = recv_line (soc, input, sizeof (input) - 1);
  if (n <= 0)
    {
      g_free (origname);
      return -1;
    }
  /* XXX content: message. Ignored for the moment */

  n = recv_line (soc, input, sizeof (input) - 1);
  if (n <= 0)
    {
      g_free (origname);
      return -1;
    }

  if (strncmp (input, "bytes: ", sizeof ("bytes: ") - 1) == 0)
    {
      char *t = input + sizeof ("bytes: ") - 1;
      bytes = atol (t);
    }
  else
    {
      g_free (origname);
      return -1;
    }

  /* We now know that we have to read <bytes> bytes from the remote socket. */

  contents = g_try_malloc0 (bytes);

  if (contents == NULL)
    {
      log_write ("ntp_recv_file: Failed to allocate memory for uploaded file.");
      g_free (origname);
      return -1;
    }

  cont_ptr = contents;
  while (tot < bytes)
    {
      bzero (input, sizeof (input));
      n = nrecv (soc, input, MIN (sizeof (input) - 1, bytes - tot), 0);
      if (n < 0)
        {
          log_write ("11_recv_file: nrecv(%d)", soc);
          break;
        }
      else
        {
          memcpy ((cont_ptr + (tot * sizeof (char))), &input, n);
          tot += n;
        }
    }
  send_printf (soc, "SERVER <|> FILE_ACCEPTED <|> SERVER\n");
  /* Add the fact that what the remote client calls <filename> is actually
   * stored in <contents> here and has a size of <bytes> bytes. */
  files_add_translation (globals, origname, contents);
  files_add_size_translation (globals, origname, bytes);

  g_free (origname);
  return 0;
}

/*----------------------------------------------------------

   Communication protocol: timestamps

 ----------------------------------------------------------*/


static int
__ntp_timestamp_scan (int soc, char *msg)
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

  send_printf (soc, "SERVER <|> TIME <|> %s <|> %s <|> SERVER\n", msg, timestr);
  return 0;
}


static int
__ntp_timestamp_scan_host (int soc, char *msg, char *host)
{
  char timestr[1024];
  char *tmp;
  time_t t;
  int len;
  char buf[1024];

  t = time (NULL);
  tmp = ctime (&t);
  timestr[sizeof (timestr) - 1] = '\0';
  strncpy (timestr, tmp, sizeof (timestr) - 1);
  len = strlen (timestr);
  if (timestr[len - 1] == '\n')
    timestr[len - 1] = '\0';

  snprintf (buf, sizeof (buf),
            "SERVER <|> TIME <|> %s <|> %s <|> %s <|> SERVER\n", msg, host,
            timestr);

  internal_send (soc, buf, INTERNAL_COMM_MSG_TYPE_DATA);

  return 0;
}


int
ntp_timestamp_scan_starts (int soc)
{
  return __ntp_timestamp_scan (soc, "SCAN_START");
}

int
ntp_timestamp_scan_ends (int soc)
{
  return __ntp_timestamp_scan (soc, "SCAN_END");
}

int
ntp_timestamp_host_scan_starts (int soc, char *host)
{
  return __ntp_timestamp_scan_host (soc, "HOST_START", host);
}

int
ntp_timestamp_host_scan_ends (int soc, char *host)
{
  return __ntp_timestamp_scan_host (soc, "HOST_END", host);
}
