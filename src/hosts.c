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
 * @file hosts.c
 * @brief Basically creates a new process for each tested host.
 */

#include "hosts.h" /* for hosts_new() */

#include "../misc/network.h" /* for internal_recv */
#include "ntp.h"             /* for ntp_parse_input() */
#include "utils.h"           /* for data_left() */

#include <errno.h>    /* for errno() */
#include <glib.h>     /* for g_free() */
#include <string.h>   /* for strlen() */
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>   /* for close() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Host information, implemented as doubly linked list.
 */
struct host
{
  char *name;
  char *ip;
  pid_t pid;
  kb_t host_kb;
  struct host *next;
  struct host *prev;
};
/** @TODO struct hosts could be stripped down and put in a g_list, or,
 *        as a g_hash_table (name -> [soc,pid]), see hosts_get.*/

static struct host *hosts = NULL;
static int g_soc = -1;
static int g_max_hosts = 15;

/*-------------------------------------------------------------------------*/

static int
send_to_client (int out, char *buf)
{
  int n, len = strlen (buf);

  assert (out);
  for (n = 0; n < len;)
    {
      int e;
      e = nsend (out, buf + n, len - n, 0);
      if (e < 0 && errno == EINTR)
        continue;
      else if (e < 0)
        return -1;
      else
        n += e;
    }
  return 0;
}

static int
forward_status (struct host *h, int out)
{
  char *status = NULL, *buf = NULL;

  /* Send the message to the client only if it is a OTP scan. */
  if (!is_otp_scan ())
    return 0;

  status = kb_item_pop_str (h->host_kb, "internal/status");
  if (!status)
    return 0;
  buf = g_strdup_printf ("SERVER <|> STATUS <|> %s <|> %s <|> SERVER\n", h->ip,
                         status);
  g_free (status);
  if (send_to_client (out, buf) < 0)
    {
      g_free (buf);
      return -1;
    }
  g_free (buf);
  return 0;
}

static int
forward (struct host *h, int out)
{
  /* Send the message to the client only if it is a OTP scan. */
  if (!is_otp_scan ())
    return 0;

  forward_status (h, out);
  while (1)
    {
      char **values, *buf = kb_item_pop_str (h->host_kb, "internal/results");
      if (!buf)
        return 0;

      /* Type|||Hostname|||Port/Proto|||OID|||Message */
      values = g_strsplit (buf, "|||", 5);
      assert (values && values[0] && !values[5]);
      g_free (buf);
      /* OTP: Type <|> IP <|> Hostname <|> Port/Proto <|> Message <|> OID */
      buf = g_strdup_printf (
        "SERVER <|> %s <|> %s <|> %s <|> %s <|> %s <|> %s <|> SERVER\n",
        values[0], h->ip, values[1], values[2], values[4], values[3]);
      if (send_to_client (out, buf) < 0)
        {
          g_free (buf);
          return -1;
        }
      g_free (buf);
    }

  return 1;
}

/*-------------------------------------------------------------------*/
extern int global_scan_stop;

static void
host_rm (struct host *h)
{
  if (h->pid != 0)
    waitpid (h->pid, NULL, WNOHANG);

  while (forward (h, g_soc) > 0)
    ;
  ntp_timestamp_host_scan_ends (g_soc, h->host_kb, h->ip);
  if (h->next != NULL)
    h->next->prev = h->prev;

  if (h->prev != NULL)
    h->prev->next = h->next;

  if (is_otp_scan () || global_scan_stop == 1)
    kb_delete (h->host_kb);

  g_free (h->name);
  g_free (h->ip);
  g_free (h);
}

/*-----------------------------------------------------------------*/

/**
 * @brief Returns the number of entries in the global hosts list.
 */
static int
hosts_num (void)
{
  struct host *h = hosts;
  int num;

  for (num = 0; h != NULL; num++, h = h->next)
    ;

  return num;
}

/**
 * @brief Retrieves a host specified by its name from the global host list.
 */
static struct host *
hosts_get (char *name)
{
  struct host *h = hosts;
  while (h != NULL)
    {
      if (strcmp (h->name, name) == 0)
        return h;
      h = h->next;
    }
  return NULL;
}

int
hosts_init (int soc, int max_hosts)
{
  g_soc = soc;
  g_max_hosts = max_hosts;
  return 0;
}

int
hosts_new (struct scan_globals *globals, char *name, kb_t kb)
{
  struct host *h;

  while (hosts_num () >= g_max_hosts)
    {
      if (hosts_read (globals) < 0)
        return -1;
    }
  if (global_scan_stop)
    return 0;

  h = g_malloc0 (sizeof (struct host));
  h->name = g_strdup (name);
  h->pid = 0;
  h->host_kb = kb;
  if (hosts != NULL)
    hosts->prev = h;
  h->next = hosts;
  h->prev = NULL;
  hosts = h;
  return 0;
}

int
hosts_set_pid (char *name, pid_t pid)
{
  struct host *h = hosts_get (name);
  if (h == NULL)
    {
      g_debug ("host_set_pid() failed!\n");
      return -1;
    }

  h->pid = pid;
  return 0;
}

/*-----------------------------------------------------------------*/
static int
hosts_stop_host (struct host *h)
{
  if (h == NULL)
    return -1;

  g_message ("Stopping host %s scan", h->name);
  kill (h->pid, SIGUSR1);
  return 0;
}

void
hosts_stop_all (void)
{
  struct host *host = hosts;

  global_scan_stop = 1;
  while (host)
    {
      hosts_stop_host (host);
      host = host->next;
    }
}

/*-----------------------------------------------------------------*/

static void
hosts_read_data (void)
{
  struct host *h = hosts;

  waitpid (-1, NULL, WNOHANG);

  if (h == NULL)
    return;

  while (h)
    {
      if (!h->ip)
        {
          /* Scan started. */
          h->ip = kb_item_get_str (h->host_kb, "internal/ip");
          if (h->ip)
            ntp_timestamp_host_scan_starts (g_soc, h->host_kb, h->ip);
        }
      if (h->ip)
        {
          forward (h, g_soc);
          if (kill (h->pid, 0) < 0) /* Process is dead */
            {
              if (!h->prev)
                hosts = hosts->next;
              host_rm (h);
              h = hosts;
              if (!h)
                break;
            }
        }
      h = h->next;
    }
}

/**
 * Returns -1 if no socket, error or client asked to stop tests, 0 otherwise.
 */
static int
hosts_read_client (struct scan_globals *globals)
{
  struct timeval tv;
  int e = 0;
  fd_set rd;

  if (g_soc == -1)
    return 0;

  FD_ZERO (&rd);
  FD_SET (g_soc, &rd);

  for (;;)
    {
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      e = select (g_soc + 1, &rd, NULL, NULL, &tv);
      if (e < 0 && errno == EINTR)
        continue;
      else
        break;
    }

  if (e > 0 && FD_ISSET (g_soc, &rd) != 0)
    {
      int result;
      char buf[4096];

      result = recv_line (g_soc, buf, sizeof (buf) - 1);
      if (result <= 0)
        return -1;
      result = ntp_parse_input (globals, buf);
      if (result == -1)
        return -1;
    }

  return 0;
}

/**
 * @brief Returns -1 if client asked to stop all tests or connection was lost or
 * error. 0 otherwise.
 */
int
hosts_read (struct scan_globals *globals)
{
  if (hosts_read_client (globals) < 0 && is_otp_scan ())
    {
      hosts_stop_all ();
      g_debug ("Client abruptly closed the communication");
      return -1;
    }

  if (hosts == NULL)
    return -1;

  hosts_read_data ();
  usleep (500000);

  return 0;
}
