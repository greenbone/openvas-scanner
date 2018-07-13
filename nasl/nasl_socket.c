/* openvas-scanner/nasl/nasl_socket.c
 * $Id$
 * Description: NASL socket API
 *
 * Authors:
 * Unknown
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2002 - 2004 Tenable Network Security
 * Copyright (C) 2012 Greenbone Networks GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/**
 * @file nasl_socket.c
 *
 * @brief The NASL socket API.
 *
 * This file contains all the functions related to the handling of the
 * sockets within a NASL script - for example the implementation of
 * the NASL built-ins open_sock_tcp, send, recv, recv_line, and close.
 */


/*--------------------------------------------------------------------------*/
#include <arpa/inet.h>          /* for inet_aton */
#include <errno.h>              /* for errno */
#include <fcntl.h>              /* for fnctl */
#include <netinet/in.h>         /* for sockaddr_in */
#include <string.h>             /* for bzero */
#include <unistd.h>             /* for close */
#include <stdlib.h>             /* for atoi() */
#include <sys/time.h>


#include <gnutls/gnutls.h>
#include <gvm/base/networking.h> /* for gvm_source_set_socket */
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h>      /* for prefs_get */

#include "../misc/network.h"
#include "../misc/plugutils.h"          /* for plug_get_host_ip */

#include "nasl.h"

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_packet_forgery.h"
#include "nasl_debug.h"

#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL EADDRINUSE
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/*----------------------- Private functions ---------------------------*/

static int
unblock_socket (int soc)
{
  int flags = fcntl (soc, F_GETFL, 0);
  if (flags < 0)
    {
      perror ("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl (soc, F_SETFL, O_NONBLOCK | flags) < 0)
    {
      perror ("fcntl(F_SETFL,O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static int
block_socket (int soc)
{
  int flags = fcntl (soc, F_GETFL, 0);
  if (flags < 0)
    {
      perror ("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl (soc, F_SETFL, (~O_NONBLOCK) & flags) < 0)
    {
      perror ("fcntl(F_SETFL,~O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static void
wait_before_next_probe ()
{
  const char *time_between_request;
  int minwaittime = 0;

  time_between_request = prefs_get ("time_between_request");
  if (time_between_request)
    minwaittime = atoi (time_between_request);

  if (minwaittime > 0)
    {
      static double lastprobesec = 0;
      static double lastprobeusec = 0;
      struct timeval tvnow, tvdiff;
      double diff_msec;
      int time2wait = 0;

      gettimeofday (&tvnow, NULL);
      if (lastprobesec <= 0)
        {
          lastprobesec = tvnow.tv_sec - 10;
          lastprobeusec = tvnow.tv_usec;
        }

      tvdiff.tv_sec = tvnow.tv_sec - lastprobesec;
      tvdiff.tv_usec = tvnow.tv_usec - lastprobeusec;
      if (tvdiff.tv_usec <= 0)
        {
          tvdiff.tv_sec += 1;
          tvdiff.tv_usec *= -1;
        }

      diff_msec = tvdiff.tv_sec * 1000 + tvdiff.tv_usec / 1000;
      time2wait  = (minwaittime - diff_msec) * 1000;
      if (time2wait > 0)
        usleep (time2wait);

      gettimeofday(&tvnow, NULL);
      lastprobesec = tvnow.tv_sec;
      lastprobeusec = tvnow.tv_usec;
    }
}

/*
 * NASL automatically re-send data when a recv() on a UDP packet
 * fails. The point is to take care of packets lost en route.
 *
 * To do this, we store a copy of the data sent by a given socket
 * each time send() is called, and we re-send() it each time
 * recv() is called and fails
 *
 */

struct udp_record {
  int len;
  char * data;
};

/* add udp data in our cache */
static int
add_udp_data (struct script_infos *script_infos, int soc, char *data, int len)
{
  GHashTable * udp_data = script_infos->udp_data;
  struct udp_record * data_record = g_malloc0 (sizeof(struct udp_record));
  int * key = g_memdup (&soc, sizeof(int));

  data_record->len = len;
  data_record->data = g_memdup ((gconstpointer)data, (guint)len);

  if (udp_data == NULL)
    {
      udp_data = g_hash_table_new_full (g_int_hash, g_int_equal, g_free, g_free);
      script_infos->udp_data = udp_data;
    }

  g_hash_table_replace (udp_data, (gpointer)key, (gpointer)data_record);

  return 0;
}

/* get the udp data for socket <soc> */
static char *
get_udp_data (struct script_infos *script_infos, int soc, int *len)
{
  GHashTable *udp_data;
  struct udp_record *data_record;

  if ((udp_data = script_infos->udp_data) == NULL)
    {
      udp_data = g_hash_table_new_full (g_int_hash, g_int_equal, g_free, g_free);
      script_infos->udp_data = udp_data;
      return NULL;
    }
  data_record = g_hash_table_lookup (udp_data, (gconstpointer)&soc);

  if (!data_record) return NULL;

  *len = data_record->len;
  return data_record->data;
}

/* remove the udp data for socket <soc> */
static void
rm_udp_data (struct script_infos *script_infos, int soc)
{
  GHashTable *udp_data = script_infos->udp_data;

  if (udp_data)
    g_hash_table_remove (udp_data, (gconstpointer)&soc);
}


/*-------------------------------------------------------------------*/

int lowest_socket = 0;

static tree_cell *
nasl_open_privileged_socket (lex_ctxt * lexic, int proto)
{
  struct script_infos *script_infos = lexic->script_infos;
  int sport, current_sport = -1;
  int dport;
  int sock;
  int e;
  struct sockaddr_in addr, daddr;
  struct sockaddr_in6 addr6, daddr6;
  struct in6_addr *p;
  int to = get_int_local_var_by_name (lexic, "timeout", lexic->recv_timeout);
  tree_cell *retc;
  struct timeval tv;
  fd_set rd;
  int opt;
  unsigned int opt_sz;
  int family;



  sport = get_int_local_var_by_name (lexic, "sport", -1);
  dport = get_int_local_var_by_name (lexic, "dport", -1);
  if (dport <= 0)
    {
      nasl_perror (lexic,
                   "open_private_socket: missing or undefined parameter dport!\n");
      return NULL;
    }

  if (sport < 0)
    current_sport = 1023;


restart:
  if (proto == IPPROTO_TCP)
    wait_before_next_probe ();
  p = plug_get_host_ip (script_infos);
  if (IN6_IS_ADDR_V4MAPPED (p))
    {
      family = AF_INET;
      bzero (&addr, sizeof (addr));
      if (proto == IPPROTO_TCP)
        sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
      else
        sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
  else
    {
      family = AF_INET6;
      bzero (&addr6, sizeof (addr6));
      if (proto == IPPROTO_TCP)
        sock = socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
      else
        sock = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    }


  /*
   * We will bind to a privileged port. Let's declare
   * our socket ready for reuse
   */

  if (sock < 0)
    return NULL;

tryagain:
  if (current_sport < 128 && sport < 0)
    {
      close (sock);
      return NULL;
    }
  e =
    gvm_source_set_socket (sock, sport > 0 ? sport : current_sport--, family);

  /*
   * bind() failed - try again on a lower port
   */
  if (e < 0)
    {
      if (sport > 0)
        {
          close (sock);
          return NULL;
        }
      else
        goto tryagain;
    }


  /*
   * Connect to the other end
   */
  p = plug_get_host_ip (script_infos);

  if (IN6_IS_ADDR_V4MAPPED (p))
    {
      bzero (&daddr, sizeof (daddr));
      daddr.sin_addr.s_addr = p->s6_addr32[3];
      daddr.sin_family = AF_INET;
      daddr.sin_port = htons (dport);
      unblock_socket (sock);
      e = connect (sock, (struct sockaddr *) &daddr, sizeof (daddr));
    }
  else
    {
      bzero (&daddr6, sizeof (daddr6));
      memcpy (&daddr6.sin6_addr, p, sizeof (struct in6_addr));
      daddr6.sin6_family = AF_INET6;
      daddr6.sin6_port = htons (dport);
      unblock_socket (sock);
      e = connect (sock, (struct sockaddr *) &daddr6, sizeof (daddr6));
    }


  if (e < 0)
    {
      if (errno == EADDRINUSE || errno == EADDRNOTAVAIL)
        {
          close (sock);
          if (sport < 0)
            goto restart;
          else
            return NULL;
        }
      else if (errno != EINPROGRESS)
        {
          close (sock);
          return NULL;
        }
    }

  do
    {
      tv.tv_sec = to;
      tv.tv_usec = 0;
      FD_ZERO (&rd);
      FD_SET (sock, &rd);
      e = select (sock + 1, NULL, &rd, NULL, to > 0 ? &tv : NULL);
    }
  while (e < 0 && errno == EINTR);

  if (e <= 0)
    {
      close (sock);
      return FAKE_CELL;
    }

  block_socket (sock);
  opt_sz = sizeof (opt);

  if (getsockopt (sock, SOL_SOCKET, SO_ERROR, &opt, &opt_sz) < 0)
    {
      g_message ("[%d] open_priv_sock()->getsockopt() failed : %s",
                 getpid (), strerror (errno));
      close (sock);
      return NULL;
    }


  switch (opt)
    {
    case EADDRINUSE:
    case EADDRNOTAVAIL:
      close (sock);
      if (sport < 0)
        goto restart;
      else
        return FAKE_CELL;

    case 0:
      break;
    default:
      close (sock);
      return FAKE_CELL;
      break;
    }

  if (lowest_socket == 0)
    lowest_socket = sock;
  if (proto == IPPROTO_TCP)
    sock = openvas_register_connection (sock, NULL, NULL, OPENVAS_ENCAPS_IP);

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = sock < 0 ? 0 : sock;
  return retc;
}


tree_cell *
nasl_open_priv_sock_tcp (lex_ctxt * lexic)
{
  return nasl_open_privileged_socket (lexic, IPPROTO_TCP);
}

tree_cell *
nasl_open_priv_sock_udp (lex_ctxt * lexic)
{
  return nasl_open_privileged_socket (lexic, IPPROTO_UDP);
}


/*--------------------------------------------------------------------------*/

tree_cell *
nasl_open_sock_tcp_bufsz (lex_ctxt * lexic, int bufsz)
{
  int soc = -1;
  struct script_infos *script_infos = lexic->script_infos;
  int to, port;
  int transport = -1;
  const char *priority;
  tree_cell *retc;

  to = get_int_local_var_by_name (lexic, "timeout", lexic->recv_timeout * 2);
  if (to < 0)
    to = 10;

  transport = get_int_local_var_by_name (lexic, "transport", -1);

  if (transport == OPENVAS_ENCAPS_TLScustom)
    {
      int type;
      priority = get_str_local_var_by_name (lexic, "priority");
      if (!priority)
        priority = NULL;
      type = get_local_var_type_by_name (lexic, "priority");
      if (type != VAR2_STRING && type != VAR2_DATA)
        priority = NULL;
    }
  else
    priority = NULL;

  if (bufsz < 0)
    bufsz = get_int_local_var_by_name (lexic, "bufsz", 0);

  port = get_int_var_by_num (lexic, 0, -1);
  if (port < 0)
    return NULL;

  wait_before_next_probe ();

  /* If "transport" has not been given, use auto detection if enabled
     in the KB. if "transport" has been given with a value of 0 force
     autodetection reagardless of what the KB tells.  */
  if (transport < 0)
    soc = open_stream_auto_encaps_ext (script_infos, port, to, 0);
  else if (transport == 0)
    soc = open_stream_auto_encaps_ext (script_infos, port, to, 1);
  else
    soc = open_stream_connection_ext (script_infos, port, transport, to,
                                      priority);
  if (bufsz > 0 && soc >= 0)
    {
      if (stream_set_buffer (soc, bufsz) < 0)
        nasl_perror (lexic, "stream_set_buffer: soc=%d,bufsz=%d\n", soc, bufsz);
    }

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = soc < 0 ? 0 : soc;

  return retc;
}

/**
 * @brief Open a TCP socket to the target host
 * @naslfn{open_sock_tcp}
 *
 * This function is used to create a TCP connection to the target
 * host.  It requires the port number as its argument and has various
 * optional named arguments to control encapsulation, timeout and
 * buffering.
 *
 * @nasluparam
 *
 * - A non-negative integer with the TCP port number.
 *
 * @naslnparam
 *
 * - @a bufsz An integer with the the size buffer size.  Note that by
 *    default, no buffering is used.
 *
 * - @a timeout An integer with the timeout value in seconds.  The
 *    default timeout is controlled by a global value.
 *
 * - @a transport One of the ENCAPS_* constants to force a specific
 *    encapsulation mode or force trying of all modes (ENCAPS_AUTO).
 *    This is for example useful to select a specific TLS or SSL
 *    version or use specific TLS connection setup priorities.  See
 *    \ref get_port_transport for a description of the ENCAPS
 *    constants.
 *
 * - @a priority A string value with priorities for an TLS
 *    encapsulation.  For the syntax of the priority string see the
 *    GNUTLS manual.  This argument is only used in @a
 *    ENCAPS_TLScustom encapsulation.
 *
 * @naslret A positive integer as a NASL socket, 0 on connection error or
 * NULL on other errors.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_open_sock_tcp (lex_ctxt * lexic)
{
  return nasl_open_sock_tcp_bufsz (lexic, -1);
}

/*
 * Opening a UDP socket is a little more tricky, since
 * UDP works in a way which is different from TCP...
 *
 * Our goal is to hide this difference for the end-user
 */
tree_cell *
nasl_open_sock_udp (lex_ctxt * lexic)
{
  int soc;
  tree_cell *retc;
  int port;
  struct sockaddr_in soca;
  struct sockaddr_in6 soca6;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *ia;

  port = get_int_var_by_num (lexic, 0, -1);
  if (port < 0)
    return NULL;

  ia = plug_get_host_ip (script_infos);
  if (ia == NULL)
    return NULL;
  if (IN6_IS_ADDR_V4MAPPED (ia))
    {
      bzero (&soca, sizeof (soca));
      soca.sin_addr.s_addr = ia->s6_addr32[3];
      soca.sin_port = htons (port);
      soca.sin_family = AF_INET;

      soc = socket (AF_INET, SOCK_DGRAM, 0);
      if (soc < 0)
        return NULL;
      gvm_source_set_socket (soc, 0, AF_INET);
      if (connect (soc, (struct sockaddr *) &soca, sizeof (soca)) < 0)
        {
          close (soc);
          return NULL;
        }
    }
  else
    {
      bzero (&soca6, sizeof (soca6));
      memcpy (&soca6.sin6_addr, ia, sizeof (struct in6_addr));
      soca6.sin6_port = htons (port);
      soca6.sin6_family = AF_INET6;

      soc = socket (AF_INET6, SOCK_DGRAM, 0);
      if (soc < 0)
        return NULL;
      gvm_source_set_socket (soc, 0, AF_INET6);
      if (connect (soc, (struct sockaddr *) &soca6, sizeof (soca6)) < 0)
        {
          close (soc);
          return NULL;
        }
    }

  if (soc > 0 && lowest_socket == 0)
    lowest_socket = soc;

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = soc;
  return retc;
}

tree_cell *
nasl_socket_negotiate_ssl (lex_ctxt * lexic)
{
  int soc, transport, ret;
  tree_cell *retc;


  soc = get_int_local_var_by_name (lexic, "socket", -1);
  transport = get_int_local_var_by_name (lexic, "transport",
                                         OPENVAS_ENCAPS_TLScustom);
  if (soc < 0)
    {
      nasl_perror (lexic, "socket_ssl_negotiate: Erroneous socket value %d\n",
                   soc);
      return NULL;
    }
  if (transport == -1)
    transport = OPENVAS_ENCAPS_TLScustom;
  else if (!IS_ENCAPS_SSL (transport))
    {
      nasl_perror (lexic, "socket_ssl_negotiate: Erroneous transport value %d\n",
                   transport);
      return NULL;
    }
  ret = socket_negotiate_ssl (soc, transport, lexic->script_infos);
  if (ret < 0)
    return NULL;

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = ret;
  return retc;
}

tree_cell *
nasl_socket_get_cert (lex_ctxt * lexic)
{
  int soc, cert_len = 0;
  tree_cell *retc;
  void *cert;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  if (soc < 0)
    {
      nasl_perror (lexic, "socket_get_cert: Erroneous socket value %d\n",
                   soc);
      return NULL;
    }
  socket_get_cert (soc, &cert, &cert_len);
  if (cert_len <= 0)
    return NULL;
  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->x.str_val = cert;
  retc->size = cert_len;
  return retc;
}

tree_cell *
nasl_socket_get_ssl_session_id (lex_ctxt * lexic)
{
  int soc;
  size_t sid_len = 0;
  tree_cell *retc;
  void *sid;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  if (soc < 0)
    {
      nasl_perror (lexic, "socket_get_cert: Erroneous socket value %d\n",
                   soc);
      return NULL;
    }
  socket_get_ssl_session_id (soc, &sid, &sid_len);
  if (sid == NULL || sid_len == 0)
    return NULL;
  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->x.str_val = sid;
  retc->size = sid_len;
  return retc;
}

tree_cell *
nasl_socket_get_ssl_compression (lex_ctxt * lexic)
{
  int soc;
  tree_cell *retc;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  if (soc < 0)
    {
      nasl_perror (lexic, "socket_get_cert: Erroneous socket value %d\n",
                   soc);
      return NULL;
    }
  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = socket_get_ssl_compression (soc);
  return retc;
}

tree_cell *
nasl_socket_get_ssl_version (lex_ctxt * lexic)
{
  int soc;
  int version;
  tree_cell *retc;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  version = socket_get_ssl_version (soc);
  if (version < 0)
    return NULL;
  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = version;
  return retc;
}

tree_cell *
nasl_socket_get_ssl_ciphersuite (lex_ctxt * lexic)
{
  int soc, result;
  tree_cell *retc;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  result = socket_get_ssl_ciphersuite (soc);
  if (result < 0)
    return NULL;
  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = result;
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_recv (lex_ctxt * lexic)
{
  char *data;
  int len = get_int_local_var_by_name (lexic, "length", -1);
  int min_len = get_int_local_var_by_name (lexic, "min", -1);
  int soc = get_int_local_var_by_name (lexic, "socket", 0);
  int to = get_int_local_var_by_name (lexic, "timeout", lexic->recv_timeout);
  fd_set rd;
  struct timeval tv;
  int new_len = 0;
  int type = -1;
  unsigned int opt_len = sizeof (type);
  int e;

  if (len <= 0 || soc <= 0)
    return NULL;

  tv.tv_sec = to;
  tv.tv_usec = 0;

  data = g_malloc0 (len);
  if (!fd_is_stream (soc))
    e = getsockopt (soc, SOL_SOCKET, SO_TYPE, &type, &opt_len);
  else
    e = -1;

  if (e == 0 && type == SOCK_DGRAM)
    {
      /* As UDP packets may be lost, we retry up to 5 times */
      int retries = 5;
      int i;

      tv.tv_sec = to / retries;
      tv.tv_usec = (to % retries) * 100000;

      for (i = 0; i < retries; i++)
        {
          FD_ZERO (&rd);
          FD_SET (soc, &rd);

          if (select (soc + 1, &rd, NULL, NULL, &tv) > 0)
            {
              int e;
              e = recv (soc, data + new_len, len - new_len, 0);

              if (e <= 0)
                {
                  if (!new_len)
                    {
                      g_free (data);
                      return NULL;
                    }
                }
              else
                new_len += e;

              break;            /* UDP data is never fragmented */
            }
          else
            {
              /* The packet may have been lost en route - we resend it */
              char *data;
              int len;

              data = get_udp_data (lexic->script_infos, soc, &len);
              if (data != NULL)
                send (soc, data, len, 0);
              tv.tv_sec = to / retries;
              tv.tv_usec = (to % retries) * 100000;
            }
        }
    }
  else
    {
      int old = stream_set_timeout (soc, tv.tv_sec);
      new_len = read_stream_connection_min (soc, data, min_len, len);
      stream_set_timeout (soc, old);
    }
  if (new_len > 0)
    {
      tree_cell *retc = alloc_tree_cell ();
      retc->type = CONST_DATA;
      retc->x.str_val = g_memdup (data, new_len);
      retc->size = new_len;
      g_free (data);
      return retc;
    }
  else
    {
      g_free (data);
      return NULL;
    }
}



tree_cell *
nasl_recv_line (lex_ctxt * lexic)
{
  int len = get_int_local_var_by_name (lexic, "length", -1);
  int soc = get_int_local_var_by_name (lexic, "socket", 0);
  int timeout = get_int_local_var_by_name (lexic, "timeout", -1);
  char *data;
  int new_len = 0;
  int n = 0;
  tree_cell *retc;
  time_t t1 = 0;

  if (len == -1 || soc <= 0)
    {
      nasl_perror (lexic, "recv_line: missing or undefined parameter"
                          " length or socket\n");
      return NULL;
    }

  if (timeout >= 0)             /* sycalls are much more expensive than simple tests */
    t1 = time (NULL);

  if (fd_is_stream (soc) != 0)
    {
      int bufsz = stream_get_buffer_sz (soc);
      if (bufsz <= 0)
        stream_set_buffer (soc, len + 1);
    }

  data = g_malloc0 (len + 1);
  for (;;)
    {
      int e = read_stream_connection_min (soc, data + n, 1, 1);
      if (e < 0)
        break;
      if (e == 0)
        {
          if (timeout >= 0 && time (NULL) - t1 < timeout)
            continue;
          else
            break;
        }
      n++;
      if ((data[n - 1] == '\n') || (n >= len))
        break;
    }



  if (n <= 0)
    {
      g_free (data);
      return NULL;
    }

  new_len = n;



  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->size = new_len;
  retc->x.str_val = g_memdup (data, new_len + 1);

  g_free (data);

  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_send (lex_ctxt * lexic)
{
  int soc = get_int_local_var_by_name (lexic, "socket", 0);
  char *data = get_str_local_var_by_name (lexic, "data");
  int option = get_int_local_var_by_name (lexic, "option", 0);
  int length = get_int_local_var_by_name (lexic, "length", 0);
  int data_length = get_var_size_by_name (lexic, "data");
  int n;
  tree_cell *retc;
  int type;
  unsigned int type_len = sizeof (type);

  if (soc <= 0 || data == NULL)
    {
      nasl_perror (lexic, "Syntax error with the send() function\n");
      nasl_perror (lexic,
                   "Correct syntax is : send(socket:<soc>, data:<data>\n");
      return NULL;
    }

  if (length <= 0 || length > data_length)
    length = data_length;


  if (!fd_is_stream (soc)
      && getsockopt (soc, SOL_SOCKET, SO_TYPE, &type, &type_len) == 0
      && type == SOCK_DGRAM)
    {
      n = send (soc, data, length, option);
      add_udp_data (lexic->script_infos, soc, data, length);
    }
  else
    {
      wait_before_next_probe ();
      n = nsend (soc, data, length, option);
    }

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = n;

  return retc;
}


/*---------------------------------------------------------------------*/
tree_cell *
nasl_close_socket (lex_ctxt * lexic)
{
  int soc;
  int type;
  unsigned int opt_len = sizeof (type);
  int e;

  soc = get_int_var_by_num (lexic, 0, -1);
  if (fd_is_stream (soc))
    {
      wait_before_next_probe ();
      return close_stream_connection (soc) < 0 ? NULL : FAKE_CELL;
    }
  if (lowest_socket == 0 || soc < lowest_socket)
    {
      nasl_perror (lexic, "close(%d): Invalid socket value\n", soc);
      return NULL;
    }

  e = getsockopt (soc, SOL_SOCKET, SO_TYPE, &type, &opt_len);
  if (e == 0)
    {
      if (type == SOCK_DGRAM)
        {
          rm_udp_data (lexic->script_infos, soc);
          return FAKE_CELL;
        }
      close (soc);
      return FAKE_CELL;
    }
  else
    nasl_perror (lexic, "close(%d): %s\n", soc, strerror (errno));

  return NULL;
}


static struct jmg
{
  struct in_addr in;
  int count;
  int s;
} *jmg_desc = NULL;
static int jmg_max = 0;

tree_cell *
nasl_join_multicast_group (lex_ctxt * lexic)
{
  char *a;
  int i, j;
  struct ip_mreq m;
  tree_cell *retc = NULL;

  a = get_str_var_by_num (lexic, 0);
  if (a == NULL)
    {
      nasl_perror (lexic, "join_multicast_group: missing parameter\n");
      return NULL;
    }
  if (!inet_aton (a, &m.imr_multiaddr))
    {
      nasl_perror (lexic, "join_multicast_group: invalid parameter '%s'\n", a);
      return NULL;
    }
  m.imr_interface.s_addr = INADDR_ANY;

  j = -1;
  for (i = 0; i < jmg_max; i++)
    if (jmg_desc[i].in.s_addr == m.imr_multiaddr.s_addr
        && jmg_desc[i].count > 0)
      {
        jmg_desc[i].count++;
        break;
      }
    else if (jmg_desc[i].count <= 0)
      j = i;


  if (i >= jmg_max)
    {
      int s = socket (AF_INET, SOCK_DGRAM, 0);
      if (s < 0)
        {
          nasl_perror (lexic, "join_multicast_group: socket: %s\n",
                       strerror (errno));
          return NULL;
        }

      if (setsockopt (s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof (m)) < 0)
        {
          nasl_perror (lexic,
                       "join_multicast_group: setsockopt(IP_ADD_MEMBERSHIP): %s\n",
                       strerror (errno));
          close (s);
          return NULL;
        }

      if (j < 0)
        {
          jmg_desc = g_realloc (jmg_desc, sizeof (*jmg_desc) * (jmg_max + 1));
          j = jmg_max++;
        }
      jmg_desc[j].s = s;
      jmg_desc[j].in = m.imr_multiaddr;
      jmg_desc[j].count = 1;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 1;
  return retc;
}


tree_cell *
nasl_leave_multicast_group (lex_ctxt * lexic)
{
  char *a;
  struct in_addr ia;
  int i;

  a = get_str_var_by_num (lexic, 0);
  if (a == NULL)
    {
      nasl_perror (lexic, "leave_multicast_group: missing parameter\n");
      return NULL;
    }
  if (!inet_aton (a, &ia))
    {
      nasl_perror (lexic, "leave_multicast_group: invalid parameter '%s'\n", a);
      return NULL;
    }

  for (i = 0; i < jmg_max; i++)
    if (jmg_desc[i].count > 0 && jmg_desc[i].in.s_addr == ia.s_addr)
      {
        if (--jmg_desc[i].count <= 0)
          close (jmg_desc[i].s);
        return FAKE_CELL;
      }

  nasl_perror (lexic, "leave_multicast_group: never joined group %s\n", a);
  return NULL;
}


/* Fixme: Merge this into nasl_get_sock_info.  */
tree_cell *
nasl_get_source_port (lex_ctxt * lexic)
{
  struct sockaddr_in ia;
  int s, fd;
  unsigned int l;
  tree_cell *retc;
  int type;
  unsigned int type_len = sizeof (type);

  s = get_int_var_by_num (lexic, 0, -1);
  if (s < 0)
    {
      nasl_perror (lexic, "get_source_port: missing socket parameter\n");
      return NULL;
    }
  if (!fd_is_stream (s)
      && getsockopt (s, SOL_SOCKET, SO_TYPE, &type, &type_len) == 0
      && type == SOCK_DGRAM)
    fd = s;
  else
    fd = openvas_get_socket_from_connection (s);


  if (fd < 0)
    {
      nasl_perror (lexic, "get_source_port: invalid socket parameter %d\n", s);
      return NULL;
    }
  l = sizeof (ia);
  if (getsockname (fd, (struct sockaddr *) &ia, &l) < 0)
    {
      nasl_perror (lexic, "get_source_port: getsockname(%d): %s\n", fd,
                   strerror (errno));
      return NULL;
    }
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ntohs (ia.sin_port);
  return retc;
}



tree_cell *
nasl_socket_get_error (lex_ctxt * lexic)
{
  int soc = get_int_var_by_num (lexic, 0, -1);
  tree_cell *retc;
  int err;

  if (soc < 0 || !fd_is_stream (soc))
    return NULL;

  err = stream_get_err (soc);
  retc = alloc_typed_cell (CONST_INT);

  switch (err)
    {
    case 0:
      retc->x.i_val = NASL_ERR_NOERR;
      break;
    case ETIMEDOUT:
      retc->x.i_val = NASL_ERR_ETIMEDOUT;
      break;
    case EBADF:
    case EPIPE:
    case ECONNRESET:
    case ENOTSOCK:
      retc->x.i_val = NASL_ERR_ECONNRESET;
      break;

    case ENETUNREACH:
    case EHOSTUNREACH:
      retc->x.i_val = NASL_ERR_EUNREACH;
      break;
    case -1:
      g_message ("socket_get_error: Erroneous socket value %d", soc);
      break;

    default:
      g_message ("Unknown error %d %s", err, strerror (err));
    }

  return retc;
}


/**
 * @brief Get info pertaining to a socket.
 * @naslfn{get_sock_info}
 *
 * This function is used to retrieve various information about an
 * active socket.  It requires the NASL socket number and a string to
 * select the information to retrieve.
 *
 * Supported keywords are:
 *
 * - @a dport Return the destination port.  This is an integer.  NOTE:
 *   Not yet implemented.
 *
 * - @a sport Return the source port.  This is an integer.  NOTE: Not
 *   yet implemented.
 *
 * - @a encaps Return the encapsulation of the socket.  Example
 *   output: "TLScustom".
 *
 * - @a tls-proto Return a string with the actual TLS protocol in use.
 *   n/a" is returned if no SSL/TLS session is active.  Example
 *   output: "TLSv1".
 *
 * - @a tls-kx Return a string describing the key exchange algorithm.
 *   Example output: "RSA".
 *
 * - @a tls-certtype Return the type of the certificate in use by the
 *   session.  Example output: "X.509"
 *
 * - @a tls-cipher Return the cipher algorithm in use by the session;
 *   Example output: "AES-256-CBC".
 *
 * - @a tls-mac Return the message authentication algorithms used by
 *   the session.  Example output: "SHA1".
 *
 * - @a tls-comp Return the compression algorithms in use by the
 *   session.  Example output: "DEFLATE".
 *
 * - @a tls-auth Return the peer's authentication type.  Example
 *   output: "CERT".
 *
 * - @a tls-cert Return the peer's certificates for an SSL or TLS
 *   connection.  This is an array of binary strings or NULL if no
 *   certificate is known.
 *
 * @nasluparam
 *
 * - A NASL socket
 *
 * - A string keyword; see above.
 *
 * @naslnparam
 *
 * - @a asstring If true return a human readable string instead of
 *   an integer.  Used only with these keywords: encaps.
 *
 * @naslret An integer or a string or NULL on error.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_get_sock_info (lex_ctxt * lexic)
{
  int sock;
  int type;
  int err;
  const char *keyword, *s;
  tree_cell *retc;
  int as_string;
  int transport;
  gnutls_session_t tls_session;
  char *strval;
  int intval;

  sock = get_int_var_by_num (lexic, 0, -1);
  if (sock <= 0)
    {
      nasl_perror (lexic, "error: socket %d is not valid\n");
      return NULL;
    }

  keyword = get_str_var_by_num (lexic, 1);
  if (!keyword || !((type = get_var_type_by_num (lexic, 1)) == VAR2_STRING
                    || type == VAR2_DATA))
    {
      nasl_perror (lexic, "error: second argument is not of type string\n");
      return NULL;
    }

  as_string = !!get_int_local_var_by_name (lexic, "asstring", 0);

  transport = 0;
  strval = NULL;
  intval = 0;
  retc = FAKE_CELL; /* Dummy value to detect retc == NULL.  */

  {
    void *tmp = NULL;
    err = get_sock_infos (sock, &transport, &tmp);
    tls_session = tmp;
  }
  if (err)
    {
      nasl_perror (lexic, "error retrieving infos for socket %d: %s\n",
                   sock, strerror (err));
      retc = NULL;
    }
  else if (!strcmp (keyword, "encaps"))
    {
      if (as_string)
        strval = g_strdup (get_encaps_name (transport));
      else
        intval = transport;
    }
  else if (!strcmp (keyword, "tls-proto"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_protocol_get_name
          (gnutls_protocol_get_version (tls_session));
      strval = g_strdup (s?s:"[?]");
    }
  else if (!strcmp (keyword, "tls-kx"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_kx_get_name (gnutls_kx_get (tls_session));
      strval = g_strdup (s?s:"");
    }
  else if (!strcmp (keyword, "tls-certtype"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_certificate_type_get_name
          (gnutls_certificate_type_get (tls_session));
      strval = g_strdup (s?s:"");
    }
  else if (!strcmp (keyword, "tls-cipher"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_cipher_get_name (gnutls_cipher_get (tls_session));
      strval = g_strdup (s?s:"");
    }
  else if (!strcmp (keyword, "tls-mac"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_mac_get_name (gnutls_mac_get (tls_session));
      strval = g_strdup (s?s:"");
    }
  else if (!strcmp (keyword, "tls-comp"))
    {
      if (!tls_session)
        s = "n/a";
      else
        s = gnutls_compression_get_name
          (gnutls_compression_get (tls_session));
      strval = g_strdup (s?s:"");
    }
  else if (!strcmp (keyword, "tls-auth"))
    {
      if (!tls_session)
        s = "n/a";
      else
        {
          switch (gnutls_auth_get_type (tls_session))
            {
            case GNUTLS_CRD_ANON:        s = "ANON"; break;
            case GNUTLS_CRD_CERTIFICATE: s = "CERT"; break;
            case GNUTLS_CRD_PSK:         s = "PSK";  break;
            case GNUTLS_CRD_SRP:         s = "SRP";  break;
            default:                     s = "[?]";  break;
            }
        }
      strval = g_strdup (s);
    }
  else if (!strcmp (keyword, "tls-cert"))
    {
      /* We only support X.509 for now.  GNUTLS also allows for
         OpenPGP, but we are not prepared for that.  */
      if (tls_session
          && gnutls_certificate_type_get (tls_session) == GNUTLS_CRT_X509)
        {
          const gnutls_datum_t *list;
          unsigned int nlist = 0;
          nasl_array *a;
          anon_nasl_var v;

          list = gnutls_certificate_get_peers (tls_session, &nlist);
          if (!list)
            retc = NULL;  /* No certificate or other error.  */
          else
            {
              unsigned int i;
              retc = alloc_tree_cell ();
              retc->type = DYN_ARRAY;
              retc->x.ref_val = a = g_malloc0 (sizeof *a);

              for (i=0; i < nlist; i++)
                {
                  memset (&v, 0, sizeof v);
                  v.var_type = VAR2_DATA;
                  v.v.v_str.s_val = list[i].data;
                  v.v.v_str.s_siz = list[i].size;
                  add_var_to_list (a, i, &v);
                }
            }
        }
    }
  else
    {
      nasl_perror (lexic, "unknown keyword '%s'\n", keyword);
      retc = NULL;
    }

  if (!retc)
    ;
  else if (retc != FAKE_CELL)
    ; /* Already allocated.  */
  else if (strval)
    {
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = strval;
      retc->size = strlen (strval);
    }
  else
    {
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = intval;
    }

  return retc;
}

/**
 * @brief Verify a certificate.
 * @naslfn{socket_cert_verify}
 *
 * This function is used to retrieve and verify a certificate from an
 * active socket. It requires the NASL socket number.
 *
 * @nasluparam
 *
 * - A NASL socket.
 *
 * @naslret 0 in case of successfully verification. A positive integer in
 * case of verification error or NULL on other errors.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_socket_cert_verify (lex_ctxt *lexic)
{
  int soc, err;
  int ret;
  tree_cell *retc;
  gnutls_x509_crt_t *cert = NULL;
  gnutls_x509_trust_list_t ca_list;
  unsigned int ca_list_size = 0;
  unsigned int i, cert_n = 0;
  unsigned int voutput;
  const gnutls_datum_t *certs;

  int transport;
  gnutls_session_t tls_session;

  soc = get_int_local_var_by_name (lexic, "socket", -1);
  if (soc < 0)
    {
      nasl_perror (lexic, "socket_get_cert: Erroneous socket value %d\n",
                   soc);
      return NULL;
    }

  {
    void *tmp = NULL;
    err = get_sock_infos (soc, &transport, &tmp);
    tls_session = tmp;
  }
  if (err)
    {
      nasl_perror (lexic, "error retrieving tls_session for socket %d: %s\n",
                   soc, strerror (err));
      return NULL;
    }

  /* We only support X.509 for now.  GNUTLS also allows for
     OpenPGP, but we are not prepared for that.  */
  if (tls_session
      && gnutls_certificate_type_get (tls_session) == GNUTLS_CRT_X509)
    {
      certs = gnutls_certificate_get_peers (tls_session, &cert_n);
      if (!certs)
        return NULL;  /* No certificate or other error.  */
    }
  else
    return NULL;

  cert = g_malloc0 (sizeof(*cert) * cert_n);
  for (i = 0; i < cert_n; i++ )
    {
      if (gnutls_x509_crt_init (&cert[i]) != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_import (cert[i], &certs[i], GNUTLS_X509_FMT_DER)
          != GNUTLS_E_SUCCESS)
        return NULL;
    }

  /* Init ca_list and load system CA trust list */
  if ((ret = gnutls_x509_trust_list_init (&ca_list, ca_list_size)) < 0)
    return NULL;
  ret = gnutls_x509_trust_list_add_system_trust (ca_list, 0, 0);
  if (ret < 0)
    return NULL;

  /* Certificate verification against a trust list*/
  if (gnutls_x509_trust_list_verify_crt (ca_list, cert, cert_n,
                                         0, &voutput ,
                                         NULL)
      != GNUTLS_E_SUCCESS)
    return NULL;

  ret = voutput;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}
