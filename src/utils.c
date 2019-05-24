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
 * @file utils.c
 * @brief A bunch of miscellaneous functions, mostly file conversions.
 */

#include "utils.h"

#include "../misc/network.h" /* for stream_zero */
#include "comm.h"
#include "ntp.h"
#include "pluginscheduler.h"

#include <errno.h>          /* for errno() */
#include <gvm/base/prefs.h> /* for prefs_get() */
#include <stdlib.h>         /* for atoi() */
#include <string.h>         /* for strchr() */
#include <sys/ioctl.h>      /* for ioctl() */
#include <sys/stat.h>       /* for stat() */
#include <sys/wait.h>       /* for waitpid() */

extern int global_max_hosts;
extern int global_max_checks;
int global_scan_type = 1;

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Check the scan type
 * @return 1 if OTP type, 0 if OSP.
 */
int
is_otp_scan ()
{
  return global_scan_type;
}

/**
 * @brief Set the scan type
 */
void
set_scan_type (int type)
{
  global_scan_type = type;
}

/**
 * Get the max number of hosts to test at the same time.
 */
int
get_max_hosts_number (void)
{
  int max_hosts;
  if (prefs_get ("max_hosts"))
    {
      max_hosts = atoi (prefs_get ("max_hosts"));
      if (max_hosts <= 0)
        {
          g_debug ("Error ! max_hosts = %d -- check %s", max_hosts,
                   (char *) prefs_get ("config_file"));
          max_hosts = global_max_hosts;
        }
      else if (max_hosts > global_max_hosts)
        {
          g_debug ("Client tried to raise the maximum hosts number - %d."
                   " Using %d. Change 'max_hosts' in openvassd.conf if you"
                   " believe this is incorrect",
                   max_hosts, global_max_hosts);
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
get_max_checks_number (void)
{
  int max_checks;
  if (prefs_get ("max_checks"))
    {
      max_checks = atoi (prefs_get ("max_checks"));
      if (max_checks <= 0)
        {
          g_debug ("Error ! max_hosts = %d -- check %s", max_checks,
                   (char *) prefs_get ("config_file"));
          max_checks = global_max_checks;
        }
      else if (max_checks > global_max_checks)
        {
          g_debug ("Client tried to raise the maximum checks number - %d."
                   " Using %d. Change 'max_checks' in openvassd.conf if you"
                   " believe this is incorrect",
                   max_checks, global_max_checks);
          max_checks = global_max_checks;
        }
    }
  else
    max_checks = global_max_checks;
  return (max_checks);
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

int data_left (soc) int soc;
{
  int data = 0;
  ioctl (soc, FIONREAD, &data);
  return data;
}

void
wait_for_children1 (void)
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

/*
 * @brief Checks if a provided preference is scanner-only and can't be
 * read/written by the client.
 *
 * @return 1 if pref is scanner-only, 0 otherwise.
 */
int
is_scanner_only_pref (const char *pref)
{
  if (pref == NULL)
    return 0;
  if (!strcmp (pref, "logfile") || !strcmp (pref, "config_file")
      || !strcmp (pref, "plugins_folder")
      || !strcmp (
           pref,
           "kb_location") // old name of db_address, ignore from old conf's
      || !strcmp (pref, "db_address") || !strcmp (pref, "negot_timeout")
      || !strcmp (pref, "force_pubkey_auth")
      || !strcmp (pref, "log_whole_attack")
      || !strcmp (pref, "log_plugins_name_at_load")
      || !strcmp (pref, "nasl_no_signature_check")
      /* Preferences starting with sys_ are scanner-side only. */
      || !strncmp (pref, "sys_", 4))
    return 1;
  return 0;
}

/**
 * @brief Writes data to a socket.
 */
static void
auth_send (int soc, char *data)
{
  unsigned int sent = 0;
  gsize length;

  if (soc < 0)
    return;

  /* Convert to UTF-8 before sending to Manager. */
  data = g_convert (data, -1, "UTF-8", "ISO_8859-1", NULL, &length, NULL);
  while (sent < length)
    {
      int n = nsend (soc, data + sent, length - sent, 0);
      if (n < 0)
        {
          if ((errno != ENOMEM) && (errno != ENOBUFS))
            {
              g_free (data);
              return;
            }
        }
      else
        sent += n;
    }
  g_free (data);
}

/**
 * @brief Writes data to a socket.
 */
void
send_printf (int soc, char *data, ...)
{
  va_list param;
  char *buffer;

  va_start (param, data);
  buffer = g_strdup_vprintf (data, param);
  va_end (param);

  auth_send (soc, buffer);
  g_free (buffer);
}
