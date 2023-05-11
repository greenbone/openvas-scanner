/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2004 Michel Arboi <mikhail@nessus.org>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "../misc/network.h"
#include "../misc/plugutils.h"
#include "nasl_builtin_plugins.h"
#include "nasl_lex_ctxt.h"

#include <errno.h> /* for errno() */
#include <fcntl.h> /* for fcntl() */
#include <glib.h>
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <netdb.h>          /* for getprotobyname() */
#include <stdio.h>          /* for fprintf() */
#include <stdlib.h>         /* for atoi() */
#include <string.h>         /* for strcmp() */
#include <sys/resource.h>   /* for getrlimit() */
#include <sys/socket.h>     /* for socket() */
#include <sys/time.h>       /* for gettimeofday() */
#include <sys/types.h>      /* for socket() */
#include <unistd.h>         /* for close() */

#ifdef LINUX
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif
#include <limits.h>
#include <math.h> /* for sqrt(), floor() */

#if !defined FD_SETSIZE || FD_SETSIZE > 1024
#define GRAB_MAX_SOCK 1024
#else
#define GRAB_MAX_SOCK FD_SETSIZE
#endif

#if !defined FD_SETSIZE || FD_SETSIZE > 32
#define GRAB_MIN_SOCK 32
#else
#define GRAB_MIN_SOCK FD_SETSIZE
#warn "FD_SETSIZE is lower than 32"
#endif

#if !defined FD_SETSIZE || FD_SETSIZE > 128
#define GRAB_MAX_SOCK_SAFE 128
#else
#define GRAB_MAX_SOCK_SAFE FD_SETSIZE
#warn "FD_SETSIZE is lower than 128"
#endif

#define MAX_PASS_NB 16

#ifndef MAXINT
#define MAXINT 0x7fffffffL
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

typedef struct
{
  int fd;
  struct timeval tictac; /* open time */
  unsigned short port;
  unsigned char state;
} grab_socket_t;

#define DIFFTV(t1, t2) \
  (t1.tv_sec - t2.tv_sec + (t1.tv_usec - t2.tv_usec) / 1000000)
#define DIFFTVu(t1, t2) \
  ((t1.tv_sec - t2.tv_sec) * 1000000.0 + (t1.tv_usec - t2.tv_usec))

#define GRAB_SOCKET_UNUSED 0
#define GRAB_SOCKET_OPENING 1
#define GRAB_SOCKET_OPEN 2

#define GRAB_PORT_UNKNOWN 0
#define GRAB_PORT_CLOSED 1
#define GRAB_PORT_OPEN 2
#define GRAB_PORT_SILENT 3
#define GRAB_PORT_REJECTED 4
#define GRAB_PORT_NOT_TESTED 254
#define GRAB_PORT_TESTING 255

#define COMPUTE_RTT
/*
 * RTT is always estimated (at least, the maximum is remembered)
 * If you want to enable the "statistics", define COMPUTE_RTT and link
 * the plugin with libm (we need sqrt)
 */
/* Linux re-sends a SYN packet after 3 s
 * anyway, I don't think that we can have a RTT bigger than 2 s
 */
#define MAX_SANE_RTT 2000000 /* micro-seconds */

static int
my_socket_close (int s)
{
#ifndef SO_LINGER
  shutdown (s, 2);
#endif
  return close (s);
}

static int
std_port (int port)
{
  (void) port;
  return 0; /** @todo: We are not able anymore to judge whether a port is a
             * standard port. Previously a port was believed to be a standard
             * port when it occurred in the currently configured list of ports.
             * This needs to be resolved.
             */
}

static int
double_check_std_ports (unsigned char *ports_states)
{
  int port, tbd_nb = 0;

  for (port = 1; port <= 65535; port++)
    if (std_port (port) && ports_states[port] == GRAB_PORT_SILENT)
      {
        ports_states[port] = GRAB_PORT_UNKNOWN;
        tbd_nb++;
      }
    else if (ports_states[port] == GRAB_PORT_UNKNOWN)
      {
        g_message ("openvas_tcp_scanner: bug in double_check_std_ports!"
                   " Unknown port %d status",
                   port);
        tbd_nb++;
      }
  return tbd_nb;
}

static int
banner_grab (const struct in6_addr *pia, const char *portrange,
             const int read_timeout, int min_cnx, int max_cnx,
             struct script_infos *desc)
{
  char buf[2048], kb[64];
  int s, tcpproto, pass;
  struct protoent *proto;
  fd_set rfs, wfs, efs;
  struct timeval timeout, ti;
  struct sockaddr_in sa;
  struct sockaddr_in6 sa6;
  int len;
  int retval;
  int port = 23;
  int imax, i, j, scanned_ports, x, opt;
  unsigned int optsz;
  int minport;
  unsigned char ports_states[65536];
  grab_socket_t sockets[GRAB_MAX_SOCK];
  int open_sock_nb, open_sock_max, open_sock_max2;
  int unfiltered_ports_nb, filtered_ports_nb;
  int dropped_nb, timeout_nb, dropped_flag = 0;
  int old_filtered = -1, old_opened = -1;
  int open_ports_nb, closed_ports_nb;
  int untested_ports_nb, total_ports_nb;
  int cnx_max[3], rtt_max[3], rtt_min[3], ping_rtt = 0;
#if defined COMPUTE_RTT
  double rtt_sum[3], rtt_sum2[3];
  int rtt_nb[3];
  static const char *rtt_type[] = {"unfiltered", "open", "closed"};
#endif
  time_t start_time = time (NULL), start_time_1pass, end_time;
  long diff_time, diff_time1;
  int rst_rate_limit_flag = 0, doublecheck_flag = 0;
#if defined COMPUTE_RTT
  double mean, sd = -1.0, emax = -1.0;
#endif

  proto = getprotobyname ("tcp");
  if (proto == NULL)
    {
      perror ("tcp");
      return -1;
    }
  tcpproto = proto->p_proto;

  for (i = 0; i < (int) (sizeof (ports_states) / sizeof (*ports_states)); i++)
    ports_states[i] = GRAB_PORT_NOT_TESTED;
  scanned_ports = 0;
  for (i = 0; i < 3; i++)
    {
#if defined COMPUTE_RTT
      rtt_sum[i] = rtt_sum2[i] = 0.0;
      rtt_nb[i] = 0;
#endif
      rtt_max[i] = cnx_max[i] = 0;
      rtt_min[i] = MAXINT;
    }

  {
    char *k;
    int type = 0;
    k = plug_get_key (desc, "/tmp/ping/RTT", &type, NULL, 0);
    if (type == ARG_STRING && k != NULL)
      ping_rtt = atoi (k);
    else if (type == ARG_INT)
      ping_rtt = GPOINTER_TO_SIZE (k);
    else if (type >= 0)
      g_message ("openvas_tcp_scanner: unknown key type %d", type);
    g_free (k);
    if (ping_rtt < 0 || ping_rtt > MAX_SANE_RTT)
      ping_rtt = 0;
  }

  {
    char *p, *q;
    int po1, po2 = 0;
    p = (char *) portrange;
    untested_ports_nb = 0;

    if (p)
      while (*p != '\0')
        {
          while (*p == ',')
            p++;

          /* Scanner accepts only T:1-3,6,U:103-333,770 due to getpts. */

          if (*p == 'T' && p[1] && p[1] == ':')
            /* Skip over the leading "T:". */
            p += 2;
          else if (*p == 'U' && p[1] && p[1] == ':')
            /* "U:" for UDP.  Skip the rest. */
            break;

          if (*p == '-')
            {
              po1 = 1;
              q = p + 1;
              po2 = strtol (q, &p, 10);
              if (q == p)
                {
                  g_message ("openvas_tcp_scanner: Cannot parse '%s'", p);
                  return -1;
                }
            }
          else
            {
              po1 = strtol (p, &q, 10);
              if (q == p)
                {
                  g_message ("openvas_tcp_scanner: Cannot parse '%s'", p);
                  return -1;
                }
              if (*q == ',')
                {
                  p = q + 1;
                  po2 = po1;
                }
              else if (*q == '\0')
                {
                  p = q;
                  po2 = po1;
                }
              else if (*q == '-')
                {
                  if (q[1] == '\0')
                    {
                      po2 = 65535;
                      p = q + 1;
                    }
                  else
                    {
                      po2 = strtol (q + 1, &p, 10);
                      if (q + 1 == p)
                        {
                          g_message ("openvas_tcp_scanner: Cannot parse '%s'",
                                     p);
                          return -1;
                        }
                    }
                }
            }
          for (i = po1; i <= po2; i++)
            {
              ports_states[i] = GRAB_PORT_UNKNOWN;
              untested_ports_nb++;
            }
        }
    else
      {
        g_message ("openvas_tcp_scanner: port list empty");
        return -1;
      }
  }

  for (i = 0; i < max_cnx; i++)
    {
      sockets[i].state = GRAB_SOCKET_UNUSED;
      sockets[i].fd = -1;
    }

  open_sock_nb = 0;
  open_sock_max = min_cnx;
  open_sock_max2 = max_cnx;

  open_ports_nb = closed_ports_nb = filtered_ports_nb = unfiltered_ports_nb = 0;

  for (pass = 1; pass <= MAX_PASS_NB; pass++)
    {
      int open_ports_nb1 = 0, closed_ports_nb1 = 0;
      int wait_sock_nb = 0;

      minport = 1;
      start_time_1pass = time (NULL);
      FD_ZERO (&rfs);
      FD_ZERO (&wfs);
      imax = -1;

      while (scanned_ports < 65535)
        {
          total_ports_nb =
            unfiltered_ports_nb + filtered_ports_nb + untested_ports_nb;
          while (open_sock_nb < open_sock_max)
            {
              for (port = minport;
                   port <= 65535 && ports_states[port] != GRAB_PORT_UNKNOWN;
                   port++)
                ;
              if (port > 65535)
                break;
              minport = port;

              ports_states[port] = GRAB_PORT_TESTING;
              if (IN6_IS_ADDR_V4MAPPED (pia))
                {
                  s = socket (PF_INET, SOCK_STREAM, tcpproto);
                }
              else
                {
                  s = socket (PF_INET6, SOCK_STREAM, tcpproto);
                }
              if (s < 0)
                {
                  if (errno == ENFILE) /* File table overflow */
                    {
                      open_sock_max = open_sock_max2 = open_sock_nb / 2 - 1;
                      /* NB: if open_sock_max2 < 0, the scanner aborts */
                      /* DEBUG: otherwise, we print a less frigthtening message
                       */
                      continue;
                    }
                  else if (errno == EMFILE) /* Too many open files */
                    {
                      x = open_sock_nb / 16; /* 6.25% */
                      open_sock_max = open_sock_max2 =
                        open_sock_nb - (x > 0 ? x : 1);
                      /* NB: if open_sock_max2 < 0, the scanner aborts */
                      /* DEBUG: otherwise, we print a less frigthtening message
                       */
                      continue;
                    }
                  else
                    {
                      perror ("socket");
                      return -1;
                    }
                }
#if defined FD_SETSIZE
              if (s >= FD_SETSIZE)
                {
                  open_sock_max--;
                  open_sock_max2--;
                  if (close (s) < 0)
                    perror ("close");
                  continue;
                }
#endif

              if ((x = fcntl (s, F_GETFL)) < 0)
                {
                  perror ("fcntl(F_GETFL)");
                  close (s);
                  return -1;
                }
              if (fcntl (s, F_SETFL, x | O_NONBLOCK) < 0)
                {
                  perror ("fcntl(F_SETFL)");
                  close (s);
                  return -1;
                }

#ifdef SO_LINGER
              {
                struct linger l;

                l.l_onoff = 0;
                l.l_linger = 0;
                if (setsockopt (s, SOL_SOCKET, SO_LINGER, &l, sizeof (l)) < 0)
                  perror ("setsockopt(SO_LINGER)");
              }
#endif
#if defined LINUX && defined IPTOS_RELIABILITY
              /*
               * IP TOS (RFC791) is obsoleted by RFC2474
               * RFC3168 deprecates IPTOS_MINCOST, as it conflicts with
               * the "ECN capable" flags
               */
              x = IPTOS_RELIABILITY;
              if (setsockopt (s, SOL_IP, IP_TOS, &x, sizeof (x)) < 0)
                perror ("setsockopt(IP_TOS");
#endif
              bzero (&sa, sizeof (sa));
              bzero (&sa6, sizeof (sa6));
              if (IN6_IS_ADDR_V4MAPPED (pia))
                {
                  sa.sin_addr.s_addr = pia->s6_addr32[3];
                  sa.sin_family = AF_INET;
                  sa.sin_port = htons (port);
                  len = sizeof (struct sockaddr_in);
                  retval = connect (s, (struct sockaddr *) &sa, len);
                }
              else
                {
                  memcpy (&sa6.sin6_addr, pia, sizeof (struct in6_addr));
                  sa6.sin6_family = AF_INET6;
                  sa6.sin6_port = htons (port);
                  len = sizeof (struct sockaddr_in6);
                  retval = connect (s, (struct sockaddr *) &sa6, len);
                }
              if (retval < 0)
                {
                  switch (errno)
                    {
                    case EINPROGRESS:
                    case EALREADY:
                      sockets[open_sock_nb].fd = s;
                      sockets[open_sock_nb].port = port;
                      sockets[open_sock_nb].state = GRAB_SOCKET_OPENING;
                      (void) gettimeofday (&sockets[open_sock_nb].tictac, NULL);
                      open_sock_nb++;
                      FD_SET (s, &wfs);
                      if (s > imax)
                        imax = s;
                      break;

                    case EAGAIN:
                      x = open_sock_nb / 16; /* 6.25% */
                      open_sock_max = open_sock_max2 =
                        open_sock_nb - (x > 0 ? x : 1);
                      /* If open_sock_max2 < 0, the scanner aborts */
                      continue;

                    case ECONNREFUSED:
                      ports_states[port] = GRAB_PORT_CLOSED;
                      my_socket_close (s);
                      unfiltered_ports_nb++;
                      closed_ports_nb++;
                      closed_ports_nb1++;
                      untested_ports_nb--;
                      continue;

                    case ENETUNREACH:
                    case EHOSTUNREACH:
                      ports_states[port] = GRAB_PORT_REJECTED;
                      my_socket_close (s);
                      filtered_ports_nb++;
                      untested_ports_nb--;
                      continue;

                    default:
                      perror ("connect");
                      return -1;
                    }
                }
              else /* This should not happen! */
                {
                  sockets[open_sock_nb].fd = s;
                  sockets[open_sock_nb].port = port;
                  sockets[open_sock_nb].state = GRAB_SOCKET_OPEN;
                  (void) gettimeofday (&sockets[open_sock_nb].tictac, NULL);
                  open_sock_nb++;
                  ports_states[port] = GRAB_PORT_OPEN;
                  unfiltered_ports_nb++;
                  open_ports_nb++;
                  open_ports_nb1++;
                  wait_sock_nb++;
                  untested_ports_nb--;
                  scanner_add_port (desc, port, "tcp");
                }
              if (imax >= 0)
                {
                  timeout.tv_sec = timeout.tv_usec = 0;
                  if (select (imax + 1, NULL, &wfs, NULL, &timeout) > 0)
                    break;
                }
            }

          if (open_sock_max2 <= 0) /* file table is full */
            return -1;

          if (open_sock_nb == 0)
            goto end;

          FD_ZERO (&rfs);
          FD_ZERO (&wfs);
          FD_ZERO (&efs);
          imax = -1;

          for (i = 0; i < open_sock_nb; i++)
            {
              if (sockets[i].fd >= 0)
                {
                  switch (sockets[i].state)
                    {
                    case GRAB_SOCKET_OPEN:
                      FD_SET (sockets[i].fd, &rfs);
                      break;
                    case GRAB_SOCKET_OPENING:
                      FD_SET (sockets[i].fd, &wfs);
                      break;
                    default:
                      break;
                    }
                  if (sockets[i].fd > imax)
                    imax = sockets[i].fd;
                }
            }

          if (imax < 0)
            {
              if (untested_ports_nb > 0)
                return -1;
              else
                goto end;
            }

          timeout_nb = 0;
          dropped_nb = 0;
          dropped_flag = 0;
#if defined COMPUTE_RTT
          if (rtt_nb[0] > 1)
            {
              /* All values are in micro-seconds */
              int em, moy;

              mean = rtt_sum[0] / (double) rtt_nb[0];
              if ((double) rtt_max[0] > mean)
                {
                  sd = sqrt ((rtt_sum2[0] / rtt_nb[0] - mean * mean)
                             * (double) rtt_nb[0] / (rtt_nb[0] - 1));
                  emax = mean + 3 * sd;
                  em = floor (emax + 0.5);
                  moy = floor (rtt_sum[0] / rtt_nb[0] + 0.5);
                  if (em <= moy)
                    em = moy;
                  if (rtt_max[0] > em)
                    rtt_max[0] = em;
                }
              if (rtt_max[0] < rtt_min[0])
                rtt_max[0] = rtt_min[0];
            }
#endif
          /*
           * Some randomness is added to the timeout so that not all
           * scanners fire at the same time when several firewalled
           * machines are scanned in parallel.
           */
          if (wait_sock_nb == 0)
            if (rtt_max[0] > 0 || ping_rtt > 0)
              {
                if (rtt_max[0] > 0)
                  x = rtt_max[0];
                else
                  x = ping_rtt;

                if (doublecheck_flag)
                  {
                    x = 3 * x + 20000;
                    if (x > MAX_SANE_RTT)
                      x = MAX_SANE_RTT;
                  }
                if (x > 1000000) /* more that 1 s */
                  x += (unsigned) (lrand48 () & 0x7FFFFFFF) % 100000;
                else if (x > 20000) /* between 20 ms and 1 s */
                  x += (unsigned) (lrand48 () & 0x7FFFFFFF) % 50000;
                else /* less than 20 ms */
                  x = 20000 + (unsigned) (lrand48 () & 0x7FFFFFFF) % 20000;
                timeout.tv_sec = x / 1000000;
                timeout.tv_usec = x % 1000000;
              }
            else
              {
                /* Max RTT = 2 s ? */
                timeout.tv_sec = 2;
                timeout.tv_usec = (unsigned) (lrand48 () & 0x7FFFFFFF) % 250000;
              }
          else
            {
              timeout.tv_sec = read_timeout; /* * 2 ? */
              timeout.tv_usec = (unsigned) (lrand48 () & 0x7FFFFFFF) % 500000;
            }
          i = 0;
          do
            x = select (imax + 1, &rfs, &wfs, NULL, &timeout);
          while (i++ < 10 && x < 0 && errno == EINTR);

          if (x < 0)
            {
              perror ("select");
              return -1;
            }
          else if (x == 0) /* timeout */
            {
              for (i = 0; i < open_sock_nb; i++)
                {
                  if (sockets[i].fd > 0)
                    {
                      my_socket_close (sockets[i].fd);
                      sockets[i].fd = -1;
                      switch (sockets[i].state)
                        {
                        case GRAB_SOCKET_OPENING:
                          ports_states[sockets[i].port] = GRAB_PORT_SILENT;
                          filtered_ports_nb++;
                          dropped_nb++;
                          untested_ports_nb--;
                          break;
                        case GRAB_SOCKET_OPEN:
                          wait_sock_nb--;
                          break;
                        }
                    }
                  sockets[i].state = GRAB_SOCKET_UNUSED;
                }
            }
          else /* something to do */
            {
              (void) gettimeofday (&ti, NULL);
              for (i = 0; i < open_sock_nb; i++)
                {
                  if (sockets[i].fd > 0)
                    {
                      if (FD_ISSET (sockets[i].fd, &wfs))
                        {
                          opt = 0;
                          optsz = sizeof (opt);
                          if (getsockopt (sockets[i].fd, SOL_SOCKET, SO_ERROR,
                                          &opt, &optsz)
                              < 0)
                            {
                              perror ("getsockopt");
                              return -1;
                            }

                          x = DIFFTVu (ti, sockets[i].tictac);
                          if (opt != 0)
                            {
                              errno = opt;
                              if (x > cnx_max[2])
                                cnx_max[2] = x;
                              if (x < rtt_min[2])
                                rtt_min[2] = x;
                              if (x < MAX_SANE_RTT)
                                {
                                  if (x > rtt_max[2])
                                    rtt_max[2] = x;
#if defined COMPUTE_RTT
                                  rtt_nb[2]++;
                                  rtt_sum[2] += (double) x;
                                  rtt_sum2[2] += (double) x * (double) x;
#endif
                                }

                              my_socket_close (sockets[i].fd);
                              sockets[i].fd = -1;
                              sockets[i].state = GRAB_SOCKET_UNUSED;

                              untested_ports_nb--;
                              switch (opt)
                                {
                                case ENETUNREACH:
                                case EHOSTUNREACH:
                                  ports_states[sockets[i].port] =
                                    GRAB_PORT_REJECTED;
                                  filtered_ports_nb++;
                                  break;

                                case ECONNREFUSED:
                                default:
                                  ports_states[sockets[i].port] =
                                    GRAB_PORT_CLOSED;
                                  unfiltered_ports_nb++;
                                  closed_ports_nb++;
                                  closed_ports_nb1++;
                                  break;
                                }
                            }
                          else
                            {
                              sockets[i].state = GRAB_SOCKET_OPEN;
                              if (x > cnx_max[1])
                                cnx_max[1] = x;
                              if (x < rtt_min[1])
                                rtt_min[1] = x;
                              if (x < MAX_SANE_RTT)
                                {
                                  if (x > rtt_max[1])
                                    rtt_max[1] = x;
#if defined COMPUTE_RTT
                                  rtt_nb[1]++;
                                  rtt_sum[1] += (double) x;
                                  rtt_sum2[1] += (double) x * (double) x;
#endif
                                }

                              unfiltered_ports_nb++;
                              open_ports_nb++;
                              open_ports_nb1++;
                              untested_ports_nb--;
                              ports_states[sockets[i].port] = GRAB_PORT_OPEN;
                              scanner_add_port (desc, sockets[i].port, "tcp");
                              wait_sock_nb++;
                              snprintf (kb, sizeof (kb),
                                        "TCPScanner/CnxTime1000/%u",
                                        sockets[i].port);
                              plug_set_key (desc, kb, ARG_INT,
                                            GSIZE_TO_POINTER (x / 1000));
                              snprintf (kb, sizeof (kb),
                                        "TCPScanner/CnxTime/%u",
                                        sockets[i].port);
                              plug_set_key (
                                desc, kb, ARG_INT,
                                GSIZE_TO_POINTER ((x + 500000) / 1000000));
                              sockets[i].tictac = ti;
                            }
                          if (x > cnx_max[0])
                            cnx_max[0] = x;
                          if (x < rtt_min[0])
                            rtt_min[0] = x;
                          if (x < MAX_SANE_RTT)
                            {
                              if (x > rtt_max[0])
                                rtt_max[0] = x;
#if defined COMPUTE_RTT
                              rtt_nb[0]++;
                              rtt_sum[0] += (double) x;
                              rtt_sum2[0] += (double) x * (double) x;
#endif
                            }
                        }
                      else if (FD_ISSET (sockets[i].fd, &rfs))
                        {
                          x = read (sockets[i].fd, buf, sizeof (buf) - 1);
                          if (x > 0)
                            {
                              char buf2[sizeof (buf) * 2 + 1];
                              int y, flag = 0;

                              for (y = 0; y < x; y++)
                                {
                                  sprintf (buf2 + 2 * y, "%02x",
                                           (unsigned char) buf[y]);
                                  if (buf[y] == '\0')
                                    flag = 1;
                                }
                              buf2[2 * x - 1] = '\0';
                              if (flag)
                                {
                                  snprintf (kb, sizeof (kb), "BannerHex/%u",
                                            sockets[i].port);
                                  plug_set_key (desc, kb, ARG_STRING, buf2);
                                }

                              buf[x] = '\0';
                              snprintf (kb, sizeof (kb), "Banner/%u",
                                        sockets[i].port);
                              plug_set_key (desc, kb, ARG_STRING, buf);
                              x = DIFFTVu (ti, sockets[i].tictac) / 1000;
                              snprintf (kb, sizeof (kb),
                                        "TCPScanner/RwTime1000/%u",
                                        sockets[i].port);
                              plug_set_key (desc, kb, ARG_INT,
                                            GSIZE_TO_POINTER (x));
                              snprintf (kb, sizeof (kb), "TCPScanner/RwTime/%u",
                                        sockets[i].port);
                              plug_set_key (
                                desc, kb, ARG_INT,
                                GSIZE_TO_POINTER ((x + 500) / 1000));
                            }
                          wait_sock_nb--;
                          my_socket_close (sockets[i].fd);
                          sockets[i].fd = -1;
                          sockets[i].state = GRAB_SOCKET_UNUSED;
                        }
                    }
                }
            }

          (void) gettimeofday (&ti, NULL);
          for (i = 0; i < open_sock_nb; i++)
            if (sockets[i].fd >= 0
                && DIFFTV (ti, sockets[i].tictac) >= read_timeout)
              {
                switch (sockets[i].state)
                  {
                  case GRAB_SOCKET_OPEN:
                    timeout_nb++;
                    wait_sock_nb--;
                    snprintf (kb, sizeof (kb), "/tmp/NoBanner/%u",
                              sockets[i].port);
                    plug_set_key (desc, kb, ARG_INT, (void *) 1);
                    break;
                  case GRAB_SOCKET_OPENING:
                    ports_states[sockets[i].port] = GRAB_PORT_SILENT;
                    filtered_ports_nb++;
                    dropped_nb++;
                    untested_ports_nb--;
                    break;
                  default:
                    g_message (
                      "openvas_tcp_scanner: Unhandled case %d at %s:%d",
                      sockets[i].state, __FILE__, __LINE__);
                    break;
                  }
                my_socket_close (sockets[i].fd);
                sockets[i].fd = -1;
                sockets[i].state = GRAB_SOCKET_UNUSED;
              }

          if (dropped_nb > 0 && dropped_nb >= (open_sock_nb * 3) / 4
              && (dropped_nb < filtered_ports_nb
                  || dropped_nb > unfiltered_ports_nb))
            {
              /* firewalled machine? */
              open_sock_max += dropped_nb;
              if (open_sock_max2 < max_cnx)
                open_sock_max2++;
            }
          else if (dropped_nb > 0)
            {
              dropped_flag = 1;
              open_sock_max -= (dropped_nb + 2) / 3;
              if (open_sock_max < min_cnx)
                open_sock_max = min_cnx;
              open_sock_max2 = (open_sock_max + 3 * open_sock_max2) / 4;
            }
          else if (dropped_nb == 0 && dropped_flag)
            {
              /* re-increase number of open sockets */
              open_sock_max++;
            }
          open_sock_max += timeout_nb;
          if (open_sock_max > open_sock_max2)
            {
              open_sock_max = open_sock_max2;
            }
          if (open_sock_max < min_cnx)
            open_sock_max = min_cnx;
          for (i = 0; i < open_sock_nb;)
            if (sockets[i].state == GRAB_SOCKET_UNUSED || sockets[i].fd < 0)
              {
                for (j = i + 1; j < open_sock_nb
                                && (sockets[j].state == GRAB_SOCKET_UNUSED
                                    || sockets[j].fd < 0);
                     j++)
                  ;
                if (j < open_sock_nb)
                  memmove (sockets + i, sockets + j,
                           sizeof (*sockets) * (max_cnx - j));
                open_sock_nb -= j - i;
              }
            else
              i++;
        }

    end:
      end_time = time (NULL);
      diff_time1 = end_time - start_time_1pass;
      diff_time = end_time - start_time;
      if (dropped_flag
          || (pass == 1 && filtered_ports_nb > 10 && closed_ports_nb > 10)
          || (pass > 1 && filtered_ports_nb > 0))
        {
          if (doublecheck_flag && rst_rate_limit_flag
              && open_ports_nb == old_opened)
            break;
          old_opened = open_ports_nb;

          doublecheck_flag = 0;
          if (filtered_ports_nb == old_filtered)
            break;

          if (pass > 1 && open_ports_nb1 == 0 && closed_ports_nb1 >= min_cnx &&
              /*
               * Default value is 100 RST per second on OpenBSD,
               * 200 on FreeBSD and 40 on Solaris
               */
              /* 1st check on this pass only */
              closed_ports_nb1 >= (diff_time1 + 1) * 10
              && closed_ports_nb1 < (diff_time1 + 1) * 201 &&
              /* 2nd check on all passes */
              closed_ports_nb >= (diff_time + 1) * 10
              && closed_ports_nb < (diff_time + 1) * 201)
            {
              /* BSD-like system */
              int break_flag =
                (open_sock_max2 <= GRAB_MAX_SOCK_SAFE) || rst_rate_limit_flag;
              int tbd = break_flag && !doublecheck_flag
                          ? double_check_std_ports (ports_states)
                          : 0;
              if (tbd > 0)
                {
                  doublecheck_flag = 1;
                  break_flag = 0;
                }
              rst_rate_limit_flag++;
              if (break_flag)
                break;
            }
          /*
           * With doublecheck_flag, the range of tested port is different, so
           * we'd better count the number of filtered ports
           */
          old_filtered = 0;
          for (port = 1; port <= 65535; port++)
            if (ports_states[port] == GRAB_PORT_SILENT)
              {
                ports_states[port] = GRAB_PORT_UNKNOWN;
                old_filtered++;
              }
          untested_ports_nb = old_filtered;
          filtered_ports_nb = 0;
          open_sock_max = min_cnx / (pass + 1);
          if (open_sock_max < 1)
            open_sock_max = 1;
          if (!dropped_flag)
            {
              open_sock_max2 *= 2;
              open_sock_max2 /= 3;
            }
          else if (rst_rate_limit_flag)
            {
              if (open_sock_max2 > GRAB_MAX_SOCK_SAFE)
                open_sock_max2 = GRAB_MAX_SOCK_SAFE;
              if (open_sock_max > GRAB_MAX_SOCK_SAFE)
                open_sock_max = GRAB_MAX_SOCK_SAFE;
            }
          else if (open_sock_max2 <= open_sock_max)
            open_sock_max2 = open_sock_max * 2;
        }
      else if (filtered_ports_nb > 0)
        {
          int tbd_nb = 0;
          doublecheck_flag = 1;
          /* Double check standard ports, just to avoid being ridiculous */

          if ((tbd_nb = double_check_std_ports (ports_states)) == 0)
            break;
          old_filtered = untested_ports_nb = tbd_nb;
          filtered_ports_nb = 0;
          open_sock_max = min_cnx / pass;
          if (open_sock_max2 <= open_sock_max)
            open_sock_max2 = open_sock_max * 2;
          if (open_sock_max2 > GRAB_MAX_SOCK_SAFE)
            open_sock_max2 = GRAB_MAX_SOCK_SAFE;
          if (open_sock_max > GRAB_MAX_SOCK_SAFE)
            open_sock_max = GRAB_MAX_SOCK_SAFE;
        }
      else
        break;
    } /* for pass = ... */

  if (pass > MAX_PASS_NB)
    {
      pass--;
      filtered_ports_nb = old_filtered;
    }

  plug_set_key (desc, "TCPScanner/NbPasses", ARG_INT, GSIZE_TO_POINTER (pass));

#if defined COMPUTE_RTT
  for (i = 0; i < 3; i++)
    if (rtt_nb[i] > 0)
      {
        char rep[64];
        double crtt_mean, crtt_sd = -1.0, crtt_emax = -1.0;

        /* Convert from micro-seconds to seconds */
        rtt_sum[i] /= 1e6;
        rtt_sum2[i] /= 1e12;

        crtt_mean = rtt_sum[i] / rtt_nb[i];
        snprintf (rep, sizeof (rep), "%6g", crtt_mean);
        snprintf (kb, sizeof (kb), "TCPScanner/%s/MeanRTT", rtt_type[i]);
        plug_set_key (desc, kb, ARG_STRING, rep);
        x = floor (crtt_mean * 1000 + 0.5);
        snprintf (kb, sizeof (kb), "TCPScanner/%s/MeanRTT1000", rtt_type[i]);
        plug_set_key (desc, kb, ARG_INT, GSIZE_TO_POINTER (x));
        /* rtt_max is integer (uS) */
        snprintf (kb, sizeof (kb), "TCPScanner/%s/MaxRTT1000", rtt_type[i]);
        plug_set_key (desc, kb, ARG_INT,
                      GSIZE_TO_POINTER ((rtt_max[i] + 500) / 1000));
        snprintf (rep, sizeof (rep), "%6g",
                  (rtt_max[i] + 500000.0) / 1000000.0);
        snprintf (kb, sizeof (kb), "TCPScanner/%s/MaxRTT", rtt_type[i]);
        plug_set_key (desc, kb, ARG_STRING, rep);
        if (rtt_nb[i] > 1)
          {
            crtt_sd = sqrt ((rtt_sum2[i] / rtt_nb[i] - crtt_mean * crtt_mean)
                            * rtt_nb[i] / (rtt_nb[i] - 1));
            crtt_emax = crtt_mean + 3 * crtt_sd;
            snprintf (rep, sizeof (rep), "%6g", crtt_sd);
            snprintf (kb, sizeof (kb), "TCPScanner/%s/SDRTT", rtt_type[i]);
            plug_set_key (desc, kb, ARG_STRING, rep);
            x = floor (crtt_sd * 1000 + 0.5);
            snprintf (kb, sizeof (kb), "TCPScanner/%s/SDRTT1000", rtt_type[i]);
            plug_set_key (desc, kb, ARG_INT, GSIZE_TO_POINTER (x));
            snprintf (rep, sizeof (rep), "%6g", crtt_emax);
            snprintf (kb, sizeof (kb), "TCPScanner/%s/EstimatedMaxRTT",
                      rtt_type[i]);
            plug_set_key (desc, kb, ARG_STRING, rep);
            x = floor (crtt_emax * 1000 + 0.5);
            snprintf (kb, sizeof (kb), "TCPScanner/%s/EstimatedMaxRTT1000",
                      rtt_type[i]);
            plug_set_key (desc, kb, ARG_INT, GSIZE_TO_POINTER (x));
          }
      }
#endif
  plug_set_key (desc, "TCPScanner/OpenPortsNb", ARG_INT,
                GSIZE_TO_POINTER (open_ports_nb));
  plug_set_key (desc, "TCPScanner/ClosedPortsNb", ARG_INT,
                GSIZE_TO_POINTER (closed_ports_nb));
  plug_set_key (desc, "TCPScanner/FilteredPortsNb", ARG_INT,
                GSIZE_TO_POINTER (filtered_ports_nb));
  plug_set_key (desc, "TCPScanner/RSTRateLimit", ARG_INT,
                GSIZE_TO_POINTER (rst_rate_limit_flag));
  if (untested_ports_nb <= 0)
    plug_set_key (desc, "Host/full_scan", ARG_INT, GSIZE_TO_POINTER (1));
  plug_set_key (desc, "Host/num_ports_scanned", ARG_INT,
                GSIZE_TO_POINTER ((total_ports_nb - untested_ports_nb)));
  return 0;
}

tree_cell *
plugin_run_openvas_tcp_scanner (lex_ctxt *lexic)
{
  struct script_infos *desc = lexic->script_infos;
  const char *port_range = prefs_get ("port_range");
  const char *p;
  struct in6_addr *p_addr;
  unsigned int timeout = 0, max_cnx, min_cnx, x;
  int safe_checks = prefs_get_bool ("safe_checks");

  p = prefs_get ("checks_read_timeout");
  if (p != NULL)
    timeout = atoi (p);
  if (timeout <= 0)
    timeout = 5;
  {
    int max_host = 0, max_checks = 0, cur_sys_fd = 0, max_sys_fd = 0;
    struct rlimit rlim;
    FILE *fp;
    int i;
    double loadavg[3], maxloadavg = -1.0;
    int stderr_fd = dup (2);
    int devnull_fd = open ("/dev/null", O_WRONLY);
    /* Avoid error messages from sysctl */
    if (devnull_fd <= 0)
      {
        if (stderr_fd != -1)
          close (stderr_fd);
        return NULL;
      }
    dup2 (devnull_fd, 2);

    p = prefs_get ("max_hosts");
    if (p != NULL)
      max_host = atoi (p);
    if (max_host <= 0)
      max_host = 15;

    p = prefs_get ("max_checks");
    if (p != NULL)
      max_checks = atoi (p);
    if (max_checks <= 0 || max_checks > 5)
      {
        max_checks = 5; /* bigger values do not make sense */
        g_debug ("openvas_tcp_scanner: max_checks forced to %d", max_checks);
      }

    min_cnx = 8 * max_checks;
    if (safe_checks)
      max_cnx = 24 * max_checks;
    else
      max_cnx = 80 * max_checks;

    getloadavg (loadavg, 3);
    for (i = 0; i < 3; i++)
      if (loadavg[i] > maxloadavg)
        maxloadavg = loadavg[i];

    if (max_sys_fd <= 0)
      {
        fp = popen ("sysctl fs.file-nr", "r");
        if (fp != NULL)
          {
            if (fscanf (fp, "%*s = %*d %d %d", &cur_sys_fd, &max_sys_fd) == 1)
              max_sys_fd -= cur_sys_fd;
            else
              max_sys_fd = 0;
            pclose (fp);
          }
      }
    if (max_sys_fd <= 0)
      {
        fp = popen ("sysctl fs.file-max", "r");
        if (fp != NULL)
          {
            if (fscanf (fp, "%*s = %d", &max_sys_fd) < 1)
              max_sys_fd = 0;
            pclose (fp);
          }
      }

    if (max_sys_fd <= 0)
      {
        fp = popen ("sysctl kern.maxfiles", "r");
        if (fp != NULL)
          {
            if (fscanf (fp, "%*s = %d", &max_sys_fd) < 1)
              max_sys_fd = 0;
            pclose (fp);
          }
      }

    /* Restore stderr */
    close (devnull_fd);
    dup2 (stderr_fd, 2);
    close (stderr_fd);

    if (maxloadavg >= 0.0)
      max_cnx /= (1.0 + maxloadavg);

    if (max_sys_fd <= 0)
      max_sys_fd = 16384; /* reasonable default */
    /* Let's leave at least 1024 FD for other processes */
    if (max_sys_fd < 1024)
      x = GRAB_MIN_SOCK;
    else
      {
        max_sys_fd -= 1024;
        x = max_sys_fd / max_host;
      }
    if (max_cnx > x)
      max_cnx = x;
    if (max_cnx > GRAB_MAX_SOCK)
      max_cnx = GRAB_MAX_SOCK;
    if (max_cnx < GRAB_MIN_SOCK)
      max_cnx = GRAB_MIN_SOCK;

    if (safe_checks && max_cnx > GRAB_MAX_SOCK_SAFE)
      max_cnx = GRAB_MAX_SOCK_SAFE;

    if (getrlimit (RLIMIT_NOFILE, &rlim) < 0)
      perror ("getrlimit(RLIMIT_NOFILE)");
    else
      {
        /* value = one greater than the maximum  file  descriptor number */
        if (rlim.rlim_cur != RLIM_INFINITY && max_cnx >= rlim.rlim_cur)
          max_cnx = rlim.rlim_cur - 1;
      }
    x = max_cnx / 2;
    if (min_cnx > x)
      min_cnx = x > 0 ? x : 1;
  }

  p_addr = desc->ip;
  if (p_addr == NULL)
    return NULL; // TODO: before it returned "1";
  if (banner_grab (p_addr, port_range, timeout, min_cnx, max_cnx, desc) < 0)
    return NULL; // TODO: before it returned "1";
  plug_set_key (desc, "Host/scanned", ARG_INT, (void *) 1);
  plug_set_key (desc, "Host/scanners/openvas_tcp_scanner", ARG_INT, (void *) 1);
  return NULL;
}
