/* 
 * Copyright (C) 2004 Michel Arboi <mikhail@nessus.org>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <includes.h>

#include <glib.h>

#ifdef LINUX
#include <netinet/tcp.h>
#include <netinet/ip.h>
#endif
#include <limits.h>
#include <math.h>

#if defined STANDALONE && defined __STDC__
#include <stdarg.h>
#endif

#if ! defined FD_SETSIZE || FD_SETSIZE > 1024
#define GRAB_MAX_SOCK		1024
#else
#define GRAB_MAX_SOCK		FD_SETSIZE
#endif

#if ! defined FD_SETSIZE || FD_SETSIZE > 32
#define GRAB_MIN_SOCK		32
#else
#define GRAB_MIN_SOCK		FD_SETSIZE
#warn "FD_SETSIZE is lower than 32"
#endif

#if ! defined FD_SETSIZE || FD_SETSIZE > 128
#define GRAB_MAX_SOCK_SAFE	128
#else
#define GRAB_MAX_SOCK_SAFE	FD_SETSIZE
#warn "FD_SETSIZE is lower than 128"
#endif

#define MAX_PASS_NB	16

#ifndef MAXINT
#define MAXINT 0x7fffffffL
#endif

#if ! defined STANDALONE
int plugin_init(struct arglist * desc)
{
 plug_set_id(desc, 10335);
 plug_set_version(desc, "$Revision: 1741 $");
   
         
 plug_set_name(desc, "OpenVAS TCP scanner");
 plug_set_summary(desc, "Look for open TCP ports & services banners");
 plug_set_description(desc, "\
This plugin is a classical TCP port scanner\n\
It shall be reasonably quick even against a firewalled target.\n\
\n\
Once a TCP connection is open, it grabs any available banner\n\
for the service identification plugins\n\
\n\
Note that TCP scanners are more intrusive than \n\
SYN (half open) scanners\
");
 
 plug_set_copyright(desc, "(C) 2004 Michel Arboi <mikhail@nessus.org>");
 plug_set_category(desc, ACT_SCANNER);
 plug_set_family(desc, "Port scanners");

 /* 	commented out dependency on proprietary plugin, once when
	 we implement it, we can uncomment it */
 /* plug_set_dep(desc, "ping_host.nasl"); */
 return(0);
}
#endif 

typedef struct {
  int			fd;
  struct timeval	tictac;		/* open time */
  unsigned short	port;
  unsigned char		state;
} grab_socket_t;

#define DIFFTV(t1,t2)	(t1.tv_sec - t2.tv_sec + (t1.tv_usec - t2.tv_usec) / 1000000)
#define DIFFTVu(t1,t2)	((t1.tv_sec - t2.tv_sec) * 1000000.0 + (t1.tv_usec - t2.tv_usec))

#define GRAB_SOCKET_UNUSED	0
#define GRAB_SOCKET_OPENING	1
#define GRAB_SOCKET_OPEN	2

#define GRAB_PORT_UNKNOWN	0
#define GRAB_PORT_CLOSED	1
#define GRAB_PORT_OPEN		2
#define GRAB_PORT_SILENT	3
#define GRAB_PORT_REJECTED	4
#define GRAB_PORT_NOT_TESTED	254
#define GRAB_PORT_TESTING	255

#ifndef DEBUG
#define DEBUG 0
#endif
#if DEBUG > 2
# define DISPLAY
#endif
#define COMPUTE_RTT
/*
 * RTT is always estimated (at least, the maximum is remembered)
 * If you want to enable the "statistics", define COMPUTE_RTT and link 
 * the plugin with libm (we need sqrt)
 */
/* Linux re-sends a SYN packet after 3 s 
 * anyway, I don't think that we can have a RTT bigger than 2 s
 */
#define MAX_SANE_RTT 2000000	/* micro-seconds */

static int
my_socket_close(int s)
{
#ifndef SO_LINGER
  if (shutdown(s, 2) < 0)
#if DEBUG > 0
    perror("shutdown")
#endif
      ;
#endif
  return close(s);
}

static int std_port(int port)
{
  const char	*name;
  extern char*	nessus_get_svc_name();

  if (port < 1 || port > 65535) return 0;
  name = nessus_get_svc_name(port, NULL);
  if  (name == NULL || strcmp(name, "unknown") == 0)
    return 0;
#if DEBUG > 2
  fprintf(stderr, "openvas_tcp_scanner: std_port(%d)=%s\n", port, name != NULL ? name : "(null)");
#endif
  return 1;
}

static int
double_check_std_ports(unsigned char* ports_states)
{
  int	port, tbd_nb = 0;

  for (port = 1; port <= 65535; port ++)
    if (std_port(port) && ports_states[port] == GRAB_PORT_SILENT)
      {
	ports_states[port] = GRAB_PORT_UNKNOWN;
	tbd_nb ++;
      }
    else if (ports_states[port] == GRAB_PORT_UNKNOWN)
      {
	fprintf(stderr, "openvas_tcp_scanner: bug in double_check_std_ports! Unknown port %d status\n", port);
	tbd_nb ++;
      }
#if DEBUG > 0
  fprintf(stderr, "opanvas_tcp_scanner: double_check_std_ports found %d filtered standard ports\n", tbd_nb);
#endif
  return tbd_nb;
}

static int
banner_grab(const struct in_addr *pia, const char* portrange, 
	    const int read_timeout,
	    int		min_cnx,
	    int		max_cnx,
	    struct arglist *globals, 
	    struct arglist *desc,
	    struct arglist *hostinfos)
{
  char			buf[2048], kb[64];
  int			s, tcpproto, pass;
  struct protoent	*proto;
  fd_set		rfs, wfs, efs;
  struct timeval	timeout, ti, ti1;
  struct sockaddr_in	sa;
  int			port = 23;
  int			imax, i, j, scanned_ports, x, opt;
  unsigned int		optsz;
  int			minport;
  unsigned char		ports_states[65536];
  grab_socket_t		sockets[GRAB_MAX_SOCK];
  int			open_sock_nb, open_sock_max, open_sock_max2;
  int			unfiltered_ports_nb, filtered_ports_nb;
  int			dropped_nb, timeout_nb, dropped_flag = 0;
  int			old_filtered = -1, old_opened = -1;
  int			open_ports_nb, closed_ports_nb;
  int			untested_ports_nb, total_ports_nb, done_ports_nb;
  int			scanned_port_nb;
  int			cnx_max[3], rtt_max[3], rtt_min[3], ping_rtt = 0;
#if defined COMPUTE_RTT
  double		rtt_sum[3], rtt_sum2[3];
  int			rtt_nb[3];
  static const char	*rtt_type[] = {"unfiltered", "open", "closed" };
#endif
  time_t		start_time = time(NULL), start_time_1pass, end_time;
  long			diff_time, diff_time1;
  int			rst_rate_limit_flag = 0, doublecheck_flag = 0;
#if defined COMPUTE_RTT
  double		mean, sd = -1.0, emax = -1.0;
#endif

  proto = getprotobyname("tcp");
  if (proto == NULL)
    {
      perror("tcp");
      return -1;
    }
  tcpproto = proto->p_proto;

  for (i = 0; i < sizeof(ports_states) / sizeof(*ports_states); i ++)
    ports_states[i] = GRAB_PORT_NOT_TESTED;
  scanned_ports = 0;
  for (i = 0; i < 3; i ++)
    {
#if defined COMPUTE_RTT
      rtt_sum[i] = rtt_sum2[i] = 0.0;
      rtt_nb[i] = 0;
#endif
      rtt_max[i] = cnx_max[i] = 0;
      rtt_min[i] = MAXINT;
    }


  {
    char	*k;
    int		type = 0;
    k = plug_get_key(desc, "/tmp/ping/RTT", &type);
    if (type == ARG_STRING && k != NULL)
      ping_rtt = atoi(k);
    else if (type == ARG_INT)
      ping_rtt = GPOINTER_TO_SIZE(k);
    else if (type >= 0)
      fprintf(stderr, "openvas_tcp_scanner: unknown key type %d\n", type);
    if (ping_rtt < 0 || ping_rtt > MAX_SANE_RTT)
      ping_rtt = 0;
#if DEBUG > 0
    else
	fprintf(stderr, "openvas_tcp_scanner(%s): ping_rtt=%g s\n", inet_ntoa(*pia), ping_rtt / 1e6);
#endif
  }

  {
    char	*p, *q;
    int		po1, po2;
    p = (char*)portrange;
    untested_ports_nb = 0;

    if (p == NULL || *p == '\0' || strcmp(p, "default") == 0)
      {
	int	last_num = 0;
	unsigned short * nums = GSIZE_TO_POINTER(get_tcp_svcs(&last_num));

	if (nums == NULL)
	  {
	    fprintf(stderr, "openvas_tcp_scanner: Cannot get list of default services\n");
	    return -1;
	  }
	for (i = 0; i < last_num; i ++)
	    {
	      ports_states[nums[i]] = GRAB_PORT_UNKNOWN;
	      untested_ports_nb ++;
	    }
	efree(&nums);
      }
    else
      while (*p != '\0')
	{
	  while (*p == ',')
	    p ++;

	  if (*p == '-')
	    {
	      po1 = 1;
	      q = p + 1;
	      po2 = strtol(q, &p, 10);
	      if (q == p)
		{
		  fprintf(stderr, "openvas_tcp_scanner: Cannot parse '%s'\n", p);
		  return -1;
		}
	    }
	  else
	    {
	      po1 = strtol(p, &q, 10);
	      if (q == p)
		{
		  fprintf(stderr, "openvas_tcp_scanner: Cannot parse '%s'\n", p);
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
		      p = q+1;
		    }
		  else
		    {
		      po2 = strtol(q+1, &p, 10);
		      if (q+1 == p)
			{
			  fprintf(stderr, "openvas_tcp_scanner: Cannot parse '%s'\n", p);
			  return -1;
			}
		    }
		}
	    }
	  for (i = po1; i <= po2; i ++)
	    {
	      ports_states[i] = GRAB_PORT_UNKNOWN;
	      untested_ports_nb ++;
	    }
	}
  }

  for (i = 0; i < max_cnx; i ++)
    {
      sockets[i].state = GRAB_SOCKET_UNUSED;
      sockets[i].fd = -1;
    }

  open_sock_nb = 0; 
  open_sock_max = min_cnx; open_sock_max2 = max_cnx;

  open_ports_nb = closed_ports_nb = filtered_ports_nb = unfiltered_ports_nb = 0;

  for (pass = 1; pass <= MAX_PASS_NB; pass ++)
    {
      int	open_ports_nb1 = 0, closed_ports_nb1 = 0;
      int	wait_sock_nb = 0;
      int	prev_scanned_port_nb = 0;

      minport = 1;
      start_time_1pass = time(NULL);
#if DEBUG > 0
      fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d: open_sock_max=%d\topen_sock_max2=%d\n", inet_ntoa(*pia), pass, open_sock_max, open_sock_max2);
#endif

      FD_ZERO(&rfs); FD_ZERO(&wfs); imax = -1;
     
      while (scanned_ports < 65535)
	{
	  total_ports_nb = unfiltered_ports_nb + filtered_ports_nb + untested_ports_nb;
	  scanned_port_nb = unfiltered_ports_nb + filtered_ports_nb;
	  if (scanned_port_nb > prev_scanned_port_nb + 99)
	    {
	      if ( globals != NULL ) comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan", 
			   scanned_port_nb, 
			   total_ports_nb);
	      prev_scanned_port_nb = scanned_port_nb;
	    }

#if DEBUG > 0
	  fprintf(stderr, "openvas_tcp_scanner(%s): %d / %d = %02d%% - %d ports remaining\n", 
		  inet_ntoa(*pia), 
		  unfiltered_ports_nb + filtered_ports_nb,
		  total_ports_nb,
		  (unfiltered_ports_nb + filtered_ports_nb) * 100 / 
		  (total_ports_nb > 0 ? total_ports_nb : 1),
		  untested_ports_nb);
#endif
	  while (open_sock_nb < open_sock_max)
	    {
	      for (port = minport; port <= 65535 && ports_states[port] != GRAB_PORT_UNKNOWN; port ++)
		;
	      if (port > 65535)
		break;
	      minport = port;

	      ports_states[port] = GRAB_PORT_TESTING;
#if DEBUG > 2
	      fprintf(stderr, "openvas_tcp_scanner: Trying %s:%d\n", inet_ntoa(*pia), port);
#endif
	      s = socket(PF_INET, SOCK_STREAM, tcpproto);
	      if (s < 0)
		{
		  if (errno == ENFILE) /* File table overflow */
		    {
		      open_sock_max = open_sock_max2 = open_sock_nb / 2 - 1;
		      /* NB: if open_sock_max2 < 0, the scanner aborts */
#if DEBUG > 0
		      /* DEBUG: otherwise, we print a less frigthtening message */
		      perror("socket");
		      fprintf(stderr, "openvas_tcp_scanner(%s): Reducing the number of maximum open connections to %d [ENFILE]\n", inet_ntoa(*pia), open_sock_max);
#endif
		      continue;
		    }
		  else if (errno == EMFILE)	/* Too many open files */
		    {
		      x = open_sock_nb  / 16;	/* 6.25% */
		      open_sock_max = open_sock_max2 = 
			open_sock_nb - (x > 0 ? x : 1);
		      /* NB: if open_sock_max2 < 0, the scanner aborts */
#if DEBUG > 0
		      /* DEBUG: otherwise, we print a less frigthtening message */
		      perror("socket");
		      fprintf(stderr, "openvas_tcp_scanner(%s): Reducing the number of maximum open connections to %d [EMFILE]\n", inet_ntoa(*pia), open_sock_max);
#endif
		      continue;
		    }
		  else
		    {
		      perror("socket");
		      return -1;
		    }
		}
#if defined FD_SETSIZE
	      if (s >= FD_SETSIZE)
		{
		  open_sock_max --; 
		  open_sock_max2 --;
#if DEBUG > 0
		  fprintf(stderr, "openvas_tcp_scanner(%s): socket=%d > FD_SETSIZE=%d - reducing the number of maximum open connections to %d\n", inet_ntoa(*pia), s, FD_SETSIZE, open_sock_max);
#endif
		  if (close(s) < 0)
		    perror("close");
		  continue;
		}
#endif

	      if ((x = fcntl(s, F_GETFL)) < 0)
		{
		  perror("fcntl(F_GETFL)");
		  return -1;
		}
	      if (fcntl(s, F_SETFL, x | O_NONBLOCK) < 0)
		{
		  perror("fcntl(F_SETFL)");
		  return -1;
		}

#ifdef SO_LINGER
	      {
		struct linger	l;

		l.l_onoff = 0; l.l_linger = 0;
		if (setsockopt(s, SOL_SOCKET,  SO_LINGER,  &l, sizeof(l)) < 0)
		  perror("setsockopt(SO_LINGER)");
	      }
#endif
#if 0 /* defined TCP_NODELAY */
	      x = 1;
	      if (setsockopt(s, SOL_TCP, TCP_NODELAY, &x, sizeof(x)) < 0)
		perror("setsockopt(TCP_NODELAY");
#endif
#if 0 /* defined TCP_QUICKACK */
	      x = 1;
	      if (setsockopt(s, SOL_TCP, TCP_QUICKACK, &x, sizeof(x)) < 0)
		perror("setsockopt(TCP_QUICKACK");
#endif
#if defined LINUX && defined IPTOS_RELIABILITY
	      /*
	       * IP TOS (RFC791) is obsoleted by RFC2474
	       * RFC3168 deprecates IPTOS_MINCOST, as it conflicts with 
	       * the "ECN capable" flags 
	       */
	      x = IPTOS_RELIABILITY;
	      if (setsockopt(s, SOL_IP, IP_TOS, &x, sizeof(x)) < 0)
		perror("setsockopt(IP_TOS");
#endif
	      sa.sin_addr = *pia;
	      sa.sin_family = AF_INET;
	      sa.sin_port = htons(port);

	      if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		{
		  switch (errno)
		    {
		    case EINPROGRESS:
		    case EALREADY:
		      sockets[open_sock_nb].fd = s;
		      sockets[open_sock_nb].port = port;
		      sockets[open_sock_nb].state = GRAB_SOCKET_OPENING;
		      (void) gettimeofday(&sockets[open_sock_nb].tictac, NULL);
		      open_sock_nb ++;
		      FD_SET(s, &wfs);
		      if (s > imax) imax = s;
		      break;
		  
		    case EAGAIN:
		      x = open_sock_nb  / 16;	/* 6.25% */
		      open_sock_max = open_sock_max2 = 
			open_sock_nb - (x > 0 ? x : 1);
		      /* If open_sock_max2 < 0, the scanner aborts */
#if DEBUG > 0
		      fprintf(stderr, "openvas_tcp_scanner(%s): Reducing the number of maximum open connections to %d [EAGAIN]\n", inet_ntoa(*pia), open_sock_max);
#endif
		      continue;

		    case ECONNREFUSED:
		      ports_states[port] = GRAB_PORT_CLOSED;
#ifdef DISPLAY
		      printf(">>> %d: CLOSED\n", sockets[i].port);
#endif
		      my_socket_close(s);
		      unfiltered_ports_nb ++;
		      closed_ports_nb ++;
		      closed_ports_nb1 ++;
		      untested_ports_nb --;
		      continue;
		  
		    case ENETUNREACH:
		    case EHOSTUNREACH:
		      ports_states[port] = GRAB_PORT_REJECTED;
#ifdef DISPLAY
		      printf(">>> %d: FILTERED\n", sockets[i].port);
#endif
		      my_socket_close(s);
		      filtered_ports_nb ++;
		      untested_ports_nb --;
		      continue;

		    default:
		      perror("connect");
		      return -1;
		    }
		}
	      else			/* This should not happen! */
		{
		  sockets[open_sock_nb].fd = s;
		  sockets[open_sock_nb].port = port;
		  sockets[open_sock_nb].state = GRAB_SOCKET_OPEN;
#ifdef DISPLAY
		  printf(">>> %d: OPEN\n", sockets[i].port);
#endif
		  (void) gettimeofday(&sockets[open_sock_nb].tictac, NULL);
		  open_sock_nb ++;
		  ports_states[port] = GRAB_PORT_OPEN;
		  unfiltered_ports_nb ++;
		  open_ports_nb ++;
		  open_ports_nb1 ++;
		  wait_sock_nb ++;
		  untested_ports_nb --;
		  scanner_add_port(desc, port, "tcp");
		}
	      if (imax >= 0)
		{
		  timeout.tv_sec = timeout.tv_usec = 0;
		  if (select(imax + 1, NULL, &wfs, NULL, &timeout) > 0)
		    {
#if DEBUG > 1
		      fprintf(stderr, "openvas_tcp_scanner(%s): select! Breaking loop (open_sock_nb=%d / %d)\n", inet_ntoa(*pia), open_sock_nb, open_sock_max);
#endif
		      break;
		    }
		}
	    }

	  if (open_sock_max2 <= 0)	/* file table is full */
	    return -1;

	  if (open_sock_nb == 0)
	    {
#if DEBUG > 0
	      fprintf(stderr, "openvas_tcp_scanner(%s): No more open socket\n", inet_ntoa(*pia));
#endif
		  goto end;
	    }

	  FD_ZERO(&rfs); FD_ZERO(&wfs); FD_ZERO(&efs); imax = -1;

	  for (i = 0; i < open_sock_nb; i ++)
	    {
	      if (sockets[i].fd >= 0)
		{
		  switch (sockets[i].state)
		    {
		    case GRAB_SOCKET_OPEN:
		      FD_SET(sockets[i].fd, &rfs);
		      break;
		    case GRAB_SOCKET_OPENING:
		      FD_SET(sockets[i].fd, &wfs);
		      break;
		    default:
#if 1
		      fprintf(stderr, "openvas_tcp_scanner(%s): Bad status %d - s=%d\n", inet_ntoa(*pia), sockets[i].state, sockets[i].fd);
#endif
		      break;
		    }
		  if (sockets[i].fd > imax)
		    imax = sockets[i].fd;
		}
	    }

	  if (imax < 0)
	    {
	      if (untested_ports_nb > 0)
		{
#if DEBUG > 0
		  fprintf(stderr, "openvas_tcp_scanner(%s): No socket! %d ports remaining\n", inet_ntoa(*pia), untested_ports_nb);
#endif
		  return -1;
		}
	      else
		{
#if DEBUG > 0
		  fprintf(stderr, "openvas_tcp_scanner(%s): No socket! No port remaining\n", inet_ntoa(*pia));
#endif
		  goto end;
		}
	    }

	  timeout_nb = 0; dropped_nb = 0; dropped_flag = 0;
#if defined COMPUTE_RTT
	  if (rtt_nb[0] > 1)
	    {
	      /* All values are in micro-seconds */
	      int	em, moy;

	      mean = rtt_sum[0] / (double)rtt_nb[0];
	      if ((double)rtt_max[0] > mean)
		{
		  sd = sqrt((rtt_sum2[0] / rtt_nb[0] - mean * mean) * (double)rtt_nb[0] / (rtt_nb[0] - 1));
		  emax = mean + 3 * sd;
		  em = floor(emax + 0.5);
		  moy = floor(rtt_sum[0] / rtt_nb[0] + 0.5);
		  if (em <= moy)
		    {
#if DEBUG > 0
		      fprintf(stderr, "openvas_tcp_scanner: arithmetic overflow: %g -> %d\n", emax, em);
#endif
		      em = moy;
		    }
		  if (rtt_max[0] > em) 
		    {
#if DEBUG > 0
		      fprintf(stderr, "openvas_tcp_scanner(%s): rtt_nb=%d rtt_max = %g > %g (M=%g, SD=%g)\n", inet_ntoa(*pia), rtt_nb[0], (double)rtt_max[0] / 1e6, emax / 1e6, mean / 1e6, sd / 1e6);
#endif
		      rtt_max[0] = em;
		    }
#if DEBUG > 1
		  else
		    fprintf(stderr, "openvas_tcp_scanner(%s): rtt_nb=%d rtt_max = %g < %g\n", inet_ntoa(*pia), rtt_nb[0], (double)rtt_max[0] / 1e6, emax / 1e6);
#endif
		}
	      if (rtt_max[0] < rtt_min[0])
		{
#if DEBUG > 0
		  fprintf(stderr, "openvas_tcp_scanner(%s): absurdly low rtt_max=%g < rtt_min = %g\n", inet_ntoa(*pia), (double)rtt_max[0] / 1e6, (double)rtt_min[0] / 1e6);
#endif
		  rtt_max[0] = rtt_min[0];
		}
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
		int	y;
		if (rtt_max[0] > 0)
		  y = x = rtt_max[0];
		else
		  y = x = ping_rtt;

		if (doublecheck_flag)
		  {
		    x = 3 * x + 20000;
		    if (x > MAX_SANE_RTT) x = MAX_SANE_RTT;
#if DEBUG > 1
		    fprintf(stderr, "openvas_tcp_scanner(%s): basic timeout increased from %g to %g because of \"double check\"\n", inet_ntoa(*pia), y/1e6, x/1e6);
#endif
		  }
		if (x > 1000000)	/* more that 1 s */
		  x += (unsigned)(lrand48() & 0x7FFFFFFF) % 100000;
		else if (x > 20000) /* between 20 ms and 1 s */
		  x += (unsigned)(lrand48() & 0x7FFFFFFF) % 50000;
		else		/* less than 20 ms */
		  x = 20000 + (unsigned)(lrand48() & 0x7FFFFFFF) % 20000;
		timeout.tv_sec = x / 1000000;
		timeout.tv_usec = x % 1000000;
#if DEBUG > 2
		fprintf(stderr, "openvas_tcp_scanner(%s): timeout=%g -> %g\n",
			inet_ntoa(*pia), y/1e6, x/1e6);
#endif
	      }
	    else
	      {
		/* Max RTT = 2 s ? */
		timeout.tv_sec = 2;
		timeout.tv_usec = (unsigned)(lrand48() & 0x7FFFFFFF) % 250000;
	      }
	  else
	    {
	      timeout.tv_sec = read_timeout; /* * 2 ? */
	      timeout.tv_usec = (unsigned)(lrand48() & 0x7FFFFFFF) % 500000;
	    }
#if DEBUG > 1
	  if (rtt_max[0] > 0)
	    fprintf(stderr, "openvas_tcp_scanner(%s): wait_sock_nb=%d - timeout=%u.%06u - RTT=%f/%f/%f/%f\n", inet_ntoa(*pia), wait_sock_nb, timeout.tv_sec, timeout.tv_usec, (double)rtt_min[0] / 1e6, rtt_sum[0] / 1e6 / (rtt_nb[0] > 0 ? rtt_nb[0] : 1), (double)rtt_max[0] / 1e6, (double)cnx_max[0] / 1e6);
	  else
	    fprintf(stderr, "openvas_tcp_scanner(%s): wait_sock_nb=%d - timeout=%d.%06d\n", inet_ntoa(*pia), wait_sock_nb, timeout.tv_sec, timeout.tv_usec);
#endif
#if DEBUG > 0
	  gettimeofday(&ti1, NULL);
#endif
	  i = 0;
	  do
	    {
	      x = select(imax + 1, &rfs, &wfs, NULL, &timeout);
#if DEBUG > 0
	      if (errno == EINTR)
		fprintf(stderr, "openvas_tcp_scanner(%s): select interrupted (i=%d)\n", inet_ntoa(*pia), i);
#endif
	    }
	  while (i ++ < 10 && x < 0 && errno == EINTR);

	  if (x < 0)
	    {
	      perror("select");
	      return -1;
	    }
	  else if (x == 0)		/* timeout */
	    {
#if DEBUG > 1
	      fprintf(stderr, "openvas_tcp_scanner(%s): select: timeout on all (%d) sockets!\n", inet_ntoa(*pia), imax - 1);
#endif
	      for (i = 0; i < open_sock_nb; i ++)
		{
		  if (sockets[i].fd > 0)
		    {
		      my_socket_close(sockets[i].fd);
		      sockets[i].fd = -1;
		      switch (sockets[i].state)
			{
			case  GRAB_SOCKET_OPENING:
#ifdef DISPLAY
			  printf(">> %d: TIMEOUT\n", sockets[i].port);
#endif
			  ports_states[sockets[i].port] = GRAB_PORT_SILENT;
			  filtered_ports_nb ++;
			  dropped_nb ++;
			  untested_ports_nb --;
			  break;
			case GRAB_SOCKET_OPEN:
#ifdef DISPLAY
			  printf(">> %d: NO BANNER\n", sockets[i].port);
#endif
			  wait_sock_nb --;
			  break;
			}
		    }
		  sockets[i].state = GRAB_SOCKET_UNUSED;
		}
	    }
	  else			/* something to do */
	    {
	      (void) gettimeofday(&ti, NULL);
#if DEBUG > 1
	      fprintf(stderr, "openvas_tcp_scanner(%s): select replied in %f s [time=%d.%06d]\n", inet_ntoa(*pia), DIFFTVu(ti, ti1) / 1e6, ti.tv_sec, ti.tv_usec);
#endif
	      for (i = 0; i < open_sock_nb; i ++)
		{
		  if (sockets[i].fd > 0)
		    if (FD_ISSET(sockets[i].fd, &wfs))
		      {
			opt = 0; optsz = sizeof(opt);
			if (getsockopt(sockets[i].fd, SOL_SOCKET, SO_ERROR, &opt, &optsz) < 0)
			  {
			    perror("getsockopt");
			    return -1;
			  }

			x = DIFFTVu(ti, sockets[i].tictac);
#if DEBUG > 2
			fprintf(stderr, "openvas_tcp_scanner: RTT to %s:%d: %g s\n", 
				inet_ntoa(*pia), sockets[i].port, x / 1e6);
#endif
			if (opt != 0)
			  {
			    errno = opt;
#if DEBUG > 2
			    perror("select->getsockopt");
#endif
			    if (x > cnx_max[2]) cnx_max[2] = x;
			    if (x < rtt_min[2]) rtt_min[2] = x;
			    if (x < MAX_SANE_RTT)
			      {
				if (x > rtt_max[2]) rtt_max[2] = x;
#if defined COMPUTE_RTT
				rtt_nb[2] ++;
				rtt_sum[2] += (double)x;
				rtt_sum2[2] += (double)x * (double)x;
#endif
			      }

			    my_socket_close(sockets[i].fd);
			    sockets[i].fd = -1;
			    sockets[i].state = GRAB_SOCKET_UNUSED;

			    untested_ports_nb --;
			    switch (opt)
			      {
			      case ENETUNREACH:
			      case EHOSTUNREACH:
				ports_states[sockets[i].port] = GRAB_PORT_REJECTED;
				filtered_ports_nb ++;
#ifdef DISPLAY
				printf(">> %d: FILTERED\n", sockets[i].port);
#endif
				break;

			      case ECONNREFUSED:
			      default:
				ports_states[sockets[i].port] = GRAB_PORT_CLOSED;
				unfiltered_ports_nb ++;
				closed_ports_nb ++;
				closed_ports_nb1 ++;
#ifdef DISPLAY
				printf(">> %d: CLOSED\n", sockets[i].port);
#endif
				break;
			      }
			  }
			else
			  {
			    sockets[i].state = GRAB_SOCKET_OPEN;
#ifdef DISPLAY
			    printf(">> %d: OPEN\n", sockets[i].port);
#endif
			    if (x > cnx_max[1]) cnx_max[1] = x;
			    if (x < rtt_min[1]) rtt_min[1] = x;
			    if (x < MAX_SANE_RTT)
			      {
				if (x > rtt_max[1]) rtt_max[1] = x;
#if defined COMPUTE_RTT
				rtt_nb[1] ++;
				rtt_sum[1] += (double)x;
				rtt_sum2[1] += (double)x * (double)x;
#endif
			      }

			    unfiltered_ports_nb ++;
			    open_ports_nb ++;
			    open_ports_nb1 ++;
			    untested_ports_nb --;
			    ports_states[sockets[i].port] = GRAB_PORT_OPEN;
			    scanner_add_port(desc, sockets[i].port, "tcp");
			    wait_sock_nb ++;
			    snprintf(kb, sizeof(kb), "TCPScanner/CnxTime1000/%d", sockets[i].port);
			    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER(x/1000));
			    snprintf(kb, sizeof(kb), "TCPScanner/CnxTime/%d", sockets[i].port);
			    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER((x + 500000) / 1000000));
			    sockets[i].tictac = ti;
			  }
			if (x > cnx_max[0]) cnx_max[0] = x;
			if (x < rtt_min[0]) rtt_min[0] = x;
			if (x < MAX_SANE_RTT)
			  {
			    if (x > rtt_max[0]) rtt_max[0] = x;
#if defined COMPUTE_RTT
			    rtt_nb[0] ++;
			    rtt_sum[0] += (double)x;
			    rtt_sum2[0] += (double)x * (double)x;
#endif
			  }
		      }
		    else if (FD_ISSET(sockets[i].fd, &rfs))
		      {
			x = read(sockets[i].fd, buf, sizeof(buf)-1);
			if (x > 0)
			  {
			    char	buf2[sizeof(buf)*2+1];
			    int y, flag = 0;

			    for (y = 0; y < x; y ++)
			      {
				sprintf(buf2 + 2*y, "%02x", (unsigned char) buf[y]);
				if (buf[y] == '\0') flag = 1;
			      }
			    buf2[2 * x - 1] = '\0';
			    if (flag)
			      {
				snprintf(kb, sizeof(kb),  "BannerHex/%d", sockets[i].port);
				plug_set_key(desc, kb, ARG_STRING, buf2);
			      }

			    buf[x] = '\0';
			    snprintf(kb, sizeof(kb), "Banner/%d", sockets[i].port);
			    plug_set_key(desc, kb, ARG_STRING, buf);
#ifdef DISPLAY
			    printf("Banner for port %d: %s\n", sockets[i].port, buf);
#endif
			    x = DIFFTVu(ti, sockets[i].tictac) / 1000;
			    snprintf(kb, sizeof(kb), "TCPScanner/RwTime1000/%d", sockets[i].port);
			    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER(x));
			    snprintf(kb, sizeof(kb), "TCPScanner/RwTime/%d", sockets[i].port);
			    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER((x + 500) / 1000));
			  }
#if DEBUG > 0
			else
			  perror("read");
#endif
			wait_sock_nb --;
			my_socket_close(sockets[i].fd);
			sockets[i].fd = -1;
			sockets[i].state = GRAB_SOCKET_UNUSED;
		      }
		}
	    }

	  (void) gettimeofday(&ti, NULL);
	  for (i = 0; i < open_sock_nb; i ++)
	    if (sockets[i].fd >= 0 && DIFFTV(ti, sockets[i].tictac) >= read_timeout)
	      {
#if DEBUG > 0
		fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d: timeout on port %d: %d\n", inet_ntoa(*pia), pass, sockets[i].port, DIFFTV(ti, sockets[i].tictac));
#endif
		switch(sockets[i].state)
		  {
		  case GRAB_SOCKET_OPEN:
#ifdef DISPLAY
		    printf(">> %d: NO BANNER\n", sockets[i].port);
#endif
		    timeout_nb ++;
		    wait_sock_nb --;
		    snprintf(kb, sizeof(kb), "/tmp/NoBanner/%d", sockets[i].port);
		    plug_set_key(desc, kb, ARG_INT, (void *) 1);
		    break;
		  case GRAB_SOCKET_OPENING:
#ifdef DISPLAY
		    printf(">> %d: TIMEOUT\n", sockets[i].port);
#endif
		    ports_states[sockets[i].port] = GRAB_PORT_SILENT;
		    filtered_ports_nb ++;
		    dropped_nb ++;
		    untested_ports_nb --;
		    break;
		  default:
		    fprintf(stderr, "nesssus_tcp_scanner: Unhandled case %d at %s:%d\n", sockets[i].state, __FILE__, __LINE__);
		    break;
		  }
		my_socket_close(sockets[i].fd); sockets[i].fd = -1;
		sockets[i].state = GRAB_SOCKET_UNUSED;
	      }

	  x = open_sock_max;
#if DEBUG > 1
	  fprintf(stderr, "openvas_tcp_scanner(%s): open_sock_max=%d timeout_nb=%d dropped_nb=%d\n", inet_ntoa(*pia), open_sock_max, timeout_nb, dropped_nb);
	  done_ports_nb = unfiltered_ports_nb + filtered_ports_nb;
	  if (done_ports_nb > 0 && total_ports_nb > 0)
	    {
	      int	dt = time(NULL) - start_time_1pass;
	      fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d: time spent so far = %d s - estimated total time = %d s - estimated time remaining = %d s\n", 
		      inet_ntoa(*pia),  pass,
		      dt,
		      dt * total_ports_nb / done_ports_nb,
		      dt * (total_ports_nb - done_ports_nb) / done_ports_nb);
	    }
#endif
	  if (dropped_nb > 0 &&
	      dropped_nb >= (open_sock_nb * 3) / 4 && 
	      (dropped_nb < filtered_ports_nb
	       || dropped_nb > unfiltered_ports_nb))
	    {
	      /* firewalled machine? */
#if DEBUG > 1
	      fprintf(stderr, "openvas_tcp_scanner(%s): %d connections dropped. Firewall?\n", inet_ntoa(*pia), dropped_nb);
#endif
	      open_sock_max += dropped_nb;
	      if (open_sock_max2 < max_cnx) open_sock_max2 ++;
#if 0
	      dropped_flag = 0;
#endif
	    }
	  else if (dropped_nb > 0)
	    {
	      dropped_flag = 1;
	      open_sock_max -= (dropped_nb + 2) / 3;
	      if (open_sock_max < min_cnx) open_sock_max = min_cnx;
	      open_sock_max2 = (open_sock_max  + 3 * open_sock_max2) / 4;
#if 0
	      if (open_sock_max2 <= min_cnx)
		if (open_sock_max2 > 0)
		  min_cnx = open_sock_max2;
		else
		  open_sock_max2 = min_cnx;
#endif
#if DEBUG > 0
	      if (min_cnx < open_sock_max)
		fprintf(stderr, "openvas_tcp_scanner(%s): %d connections dropped. Slowing down - min_cnx=%d - open_sock_nb=%d - open_sock_max=%d - open_sock_max2=%d\n", inet_ntoa(*pia), dropped_nb, min_cnx, open_sock_nb, open_sock_max, open_sock_max2);
#endif
	    }
	  else if (dropped_nb == 0 && dropped_flag)
	    {
	      /* re-increase number of open sockets */
	      open_sock_max ++;
#if 0
	      open_sock_max2 ++;
#endif
	    }
	  open_sock_max += timeout_nb;
	  if (open_sock_max > open_sock_max2)
	    {
#if  DEBUG > 2
	      fprintf(stderr, "openvas_tcp_scanner(%s): open_sock_max=%d > %d\n",
		      inet_ntoa(*pia), open_sock_max, open_sock_max2);
#endif
	      open_sock_max = open_sock_max2;
	    }
	  if (open_sock_max < min_cnx)
	    {
#if  DEBUG > 2
	      fprintf(stderr, "openvas_tcp_scanner(%s): open_sock_max=%d < %d\n",
		      inet_ntoa(*pia), open_sock_max, min_cnx);
#endif
	      open_sock_max = min_cnx;
	    }
#if DEBUG > 1
	  if (x != open_sock_max)
	    fprintf(stderr, "openvas_tcp_scanner(%s): open_sock_max=%d (old value %d)\n", inet_ntoa(*pia), open_sock_max, x);
#endif
	  for (i = 0; i < open_sock_nb; )
	    if (sockets[i].state == GRAB_SOCKET_UNUSED || sockets[i].fd < 0)
	      {
		for (j = i +1;  
		     j < open_sock_nb && (sockets[j].state == GRAB_SOCKET_UNUSED || sockets[j].fd < 0);
		     j ++)
		  ;
		if (j < open_sock_nb)
		  memmove(sockets+i, sockets+j, sizeof(*sockets) * (max_cnx - j));
		open_sock_nb -= j - i;
	      }
	    else
	      i ++;
	}

    end:
      end_time = time(NULL);
      diff_time1 = end_time - start_time_1pass;
      diff_time = end_time - start_time;
#if DEBUG > 0
      fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d ran in %d s - filtered_ports_nb=%d closed_ports_nb=%d open_ports_nb=%d\n", inet_ntoa(*pia), pass, diff_time1, filtered_ports_nb, closed_ports_nb, open_ports_nb);
#endif
      if (dropped_flag ||
	  pass == 1 && filtered_ports_nb > 10 && closed_ports_nb > 10 ||
	  pass > 1 && filtered_ports_nb > 0)
	{
	  if (doublecheck_flag && rst_rate_limit_flag && open_ports_nb == old_opened)
	    {
#if DEBUG > 0
	      fprintf(stderr, "openvas_tcp_scanner(%s): Same number of open ports! Stopping now\n", inet_ntoa(*pia));
#endif
	      break;
	    }
	  old_opened = open_ports_nb;

	  doublecheck_flag = 0;
#if DEBUG > 0
	  fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d: Suspicious number of filtered ports (%d) or closed ports (%d) - running another time\n", inet_ntoa(*pia), pass, filtered_ports_nb, closed_ports_nb);
#endif
	  if (filtered_ports_nb == old_filtered)
	    {
#if DEBUG > 0
	      fprintf(stderr, "openvas_tcp_scanner(%s): Same number of filtered ports! Stopping now\n", inet_ntoa(*pia));
#endif
	      break;
	    }

	  if (pass > 1 && open_ports_nb1 == 0 && 
	      closed_ports_nb1 >= min_cnx && 
	      /*
	       * Default value is 100 RST per second on OpenBSD, 
	       * 200 on FreeBSD and 40 on Solaris 
	       */
	      /* 1st check on this pass only */
	      closed_ports_nb1 >= (diff_time1 + 1) * 10 && 
	      closed_ports_nb1 < (diff_time1 + 1) * 201 && 
	      /* 2nd check on all passes */
	      closed_ports_nb >= (diff_time + 1) * 10 && 
	      closed_ports_nb < (diff_time + 1) * 201)
	    {
	      /* BSD-like system */
	      int	break_flag = (open_sock_max2 <= GRAB_MAX_SOCK_SAFE) || rst_rate_limit_flag;
	      int	tbd = break_flag && !doublecheck_flag ? double_check_std_ports(ports_states) : 0;
	      if (tbd > 0)
		{
		  doublecheck_flag = 1;
		  break_flag = 0;
		}
#if DEBUG > 0
	      fprintf(stderr, "openvas_tcp_scanner(%s): system seems to be limiting RST rate - %s - min_cnx=%d - closed_ports_nb1=%d - diff_time1=%d - closed_ports_nb=%d - diff_time=%d\n", inet_ntoa(*pia), break_flag ? "Stopping immediately" : doublecheck_flag ? "Double checking standard ports" : "Running one last pass", min_cnx, closed_ports_nb1, diff_time1, closed_ports_nb, diff_time);
#endif
	      rst_rate_limit_flag ++ ;
	      if (break_flag) break;
	    }
#if DEBUG > 1
	  fprintf(stderr, "openvas_tcp_scanner(%s): min_cnx=%d - open_ports_nb1=%d - closed_ports_nb1=%d - diff_time1=%d - closed_ports_nb=%d - diff_time=%d\n", inet_ntoa(*pia), min_cnx, open_ports_nb1, closed_ports_nb1, diff_time1, closed_ports_nb, diff_time);
#endif

	  /*
	   * With doublecheck_flag, the range of tested port is different, so
	   * we'd better count the number of filtered ports
	   */
	  old_filtered = 0;
	  for (port = 1; port <= 65535; port ++)
	    if (ports_states[port] == GRAB_PORT_SILENT)
	      {
		ports_states[port] = GRAB_PORT_UNKNOWN;
		old_filtered ++;
	      }
#if DEBUG > 1
	  if (old_filtered != filtered_ports_nb)
	    fprintf(stderr, "openvas_tcp_scanner(%s): old_filtered=%d filtered_ports_nb=%d\n", inet_ntoa(*pia), old_filtered, filtered_ports_nb);
#endif
	  untested_ports_nb = old_filtered;
	  filtered_ports_nb = 0;
	  open_sock_max = min_cnx / (pass + 1);
	  if (open_sock_max < 1)
	    open_sock_max = 1;
	  if (! dropped_flag)
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
	  else
	    if (open_sock_max2 <= open_sock_max)
	      open_sock_max2 = open_sock_max * 2;
	}
      else if (filtered_ports_nb > 0)
	{
	  int	tbd_nb = 0;
	  doublecheck_flag = 1;
	  /* Double check standard ports, just to avoid being ridiculous */

	  if ((tbd_nb = double_check_std_ports(ports_states)) == 0)
	    {
#if DEBUG > 0
	      fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d - No filtered standard ports - stopping\n", inet_ntoa(*pia), pass);
#endif
	      break;
	    }
#if DEBUG > 0
	  else
	    fprintf(stderr, "openvas_tcp_scanner(%s): pass #%d - Double checking %d standard ports\n", inet_ntoa(*pia), pass, tbd_nb);
#endif
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
      pass --;
      fprintf(stderr, "openvas_tcp_scanner(%s): gave up after %d pass\n",
	      inet_ntoa(*pia), pass);
      filtered_ports_nb = old_filtered;
    }

  plug_set_key(desc, "TCPScanner/NbPasses", ARG_INT, GSIZE_TO_POINTER(pass));

#if DEBUG > 0
  fprintf(stderr, "openvas_tcp_scanner(%s): ran in %d pass(es) in %d s - min_cnx=%d max_cnx=%d read_timeout=%d - open_ports_nb=%d closed_ports_nb=%d filtered_ports_nb=%d - rtt_min=%f rtt_max=%f cnx_max=%f\n", inet_ntoa(*pia), pass, diff_time, min_cnx, max_cnx, read_timeout, open_ports_nb, closed_ports_nb, filtered_ports_nb, rtt_min[0] / 1e6, rtt_max[0] / 1e6, cnx_max[0] / 1e6);
#endif

#if defined COMPUTE_RTT
  for (i = 0; i < 3; i ++)
    if (rtt_nb[i] > 0)
      {
	char	rep[64];
	double	mean, sd = -1.0, emax = -1.0;

	/* Convert from micro-seconds to seconds */
	rtt_sum[i] /= 1e6; rtt_sum2[i] /= 1e12;

	mean = rtt_sum[i] / rtt_nb[i];
#if 1
	snprintf(rep, sizeof(rep), "%6g", mean);
	snprintf(kb, sizeof(kb), "TCPScanner/%s/MeanRTT", rtt_type[i]);
	plug_set_key(desc, kb, ARG_STRING, rep);
	x = floor(mean * 1000 + 0.5);
	snprintf(kb, sizeof(kb), "TCPScanner/%s/MeanRTT1000", rtt_type[i]);
	plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER(x));
	/* rtt_max is integer (uS) */
	snprintf(kb, sizeof(kb), "TCPScanner/%s/MaxRTT1000", rtt_type[i]);
	plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER((rtt_max[i] + 500)/1000));
	snprintf(rep, sizeof(rep), "%6g", (rtt_max[i] + 500000.0) / 1000000.0);
	snprintf(kb, sizeof(kb), "TCPScanner/%s/MaxRTT", rtt_type[i]);
	plug_set_key(desc, kb, ARG_STRING, rep);
#endif
	if (rtt_nb[i] > 1)
	  {
	    sd = sqrt((rtt_sum2[i] / rtt_nb[i] - mean * mean) * rtt_nb[i] / (rtt_nb[i] - 1));
	    emax = mean + 3 * sd;
#if 1
	    snprintf(rep, sizeof(rep), "%6g", sd);
	    snprintf(kb, sizeof(kb), "TCPScanner/%s/SDRTT", rtt_type[i]);
	    plug_set_key(desc, kb, ARG_STRING, rep);
	    x = floor(sd * 1000 + 0.5);
	    snprintf(kb, sizeof(kb), "TCPScanner/%s/SDRTT1000", rtt_type[i]);
	    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER(x));
	    snprintf(rep, sizeof(rep), "%6g", emax);
	    snprintf(kb, sizeof(kb), "TCPScanner/%s/EstimatedMaxRTT", rtt_type[i]);
	    plug_set_key(desc, kb, ARG_STRING, rep);
	    x = floor(emax * 1000 + 0.5);
	    snprintf(kb, sizeof(kb), "TCPScanner/%s/EstimatedMaxRTT1000", rtt_type[i]);
	    plug_set_key(desc, kb, ARG_INT, GSIZE_TO_POINTER(x));
#endif
	  }
#if DEBUG > 0
	if (rtt_nb[i] > 0)
	  fprintf(stderr, "openvas_tcp_scanner: Mean RTT to %s = %g - [%g, %g] - SD = %g - +3SD = %g [%d %s ports]\n", 
		  inet_ntoa(*pia), mean, 
		  rtt_min[i] / 1e6, cnx_max[i] / 1e6,
		  sd, emax, rtt_nb[i], rtt_type[i]);
#endif
      }
#endif
  plug_set_key(desc, "TCPScanner/OpenPortsNb", ARG_INT, GSIZE_TO_POINTER(open_ports_nb));
  plug_set_key(desc, "TCPScanner/ClosedPortsNb", ARG_INT, GSIZE_TO_POINTER(closed_ports_nb));
  plug_set_key(desc, "TCPScanner/FilteredPortsNb", ARG_INT, GSIZE_TO_POINTER(filtered_ports_nb));
  plug_set_key(desc, "TCPScanner/RSTRateLimit", ARG_INT, GSIZE_TO_POINTER( rst_rate_limit_flag));
  if (untested_ports_nb <= 0)
    plug_set_key(desc, "Host/full_scan", ARG_INT, GSIZE_TO_POINTER(1));
  plug_set_key(desc, "Host/num_ports_scanned", ARG_INT,
	       GSIZE_TO_POINTER((total_ports_nb - untested_ports_nb)));
  return 0;
}

static int
read_sysctl_maxsysfd()
{
  int		cur_sys_fd = 0, max_sys_fd = 0;
  FILE		*fp;
  int		stderr_fd = -1, devnull_fd= -1;

  if (find_in_path("sysctl", 0) == NULL) return -1;

#ifndef DEBUG
      /* Avoid error messages from sysctl */
      stderr_fd = dup(2);
      if (stderr_fd < 0)
	perror("dup(2)");
      else
	{
	  devnull_fd = open("/dev/null", O_WRONLY);
	  if (devnull_fd < 0)
	    {
	      perror("/dev/null");
	      close(stderr_fd);
	      stderr_fd = -1;
	    }
	  else
	    if (dup2(devnull_fd, 2) < 0)
	      perror("dup2");
	}
#endif
	
  if ((fp = popen("sysctl fs.file-nr", "r")) != NULL)
    {
      if (fscanf(fp, "%*s = %d %*d %d", &cur_sys_fd, &max_sys_fd) == 2)
	max_sys_fd -= cur_sys_fd;
      else
	max_sys_fd = 0;	    
      pclose(fp);
    }
	  
  if (max_sys_fd <= 0 && (fp = popen("sysctl fs.file-max", "r")) != NULL)
    {
      if (fscanf(fp, "%*s = %d", &max_sys_fd) != 1)
	max_sys_fd = 0;
      pclose(fp);
    }

  if (max_sys_fd <= 0 && (fp = popen("sysctl kern.maxfiles", "r")) != NULL)
    {
      if (fscanf(fp, "%*s = %d", &max_sys_fd) != 1)
	max_sys_fd = 0;
      pclose(fp);
    }

  /* On BSD, net.inet.tcp.rexmit_min gives the initial TCP SYN 
   * retransmission interval. We could use it.
   * On Solaris, the situation looks more complex: 
   * http://www.sean.de/Solaris/rexmit.html
   */
  
  /* Restore stderr */
#ifndef DEBUG
      if (devnull_fd >= 0) close(devnull_fd);
      if (stderr_fd >= 0)
	{
	  dup2(stderr_fd, 2);
	  close(stderr_fd);
	}
#endif
  return max_sys_fd;
}

static void
compute_min_max_cnx(int max_hosts, int max_checks, int safe_checks,
		    int *pmin, int *pmax)
{
  int		max_sys_fd;
  int           min_cnx = *pmin, max_cnx = *pmax;
  struct rlimit	rlim;
  int		i, x;
  double	loadavg[3], maxloadavg = -1.0;

  if (max_hosts <= 0) max_hosts = 15;
  if (max_checks <= 0 || max_checks > 5)
      {
	max_checks = 5; /* bigger values do not make sense */
	// debug_printf(NULL, 1, "max_checks forced to %d\n", max_checks);
      }
  
  min_cnx = 4 * max_checks;
    if (safe_checks)
      max_cnx = 24 * max_checks;
    else
      max_cnx = 80 * max_checks;

    getloadavg(loadavg, 3);
    for (i = 0; i < 3; i ++)
      if (loadavg[i] > maxloadavg) maxloadavg = loadavg[i];

    if (maxloadavg >= 0.0)
      {
	int	x = max_cnx;
	max_cnx /= (1.0 + maxloadavg);
	// debug_printf(NULL, 1, "max_cnx reduced from %d to %d because of maxloadavg=%f\n", x, max_cnx, maxloadavg);
      }
  
    max_sys_fd = read_sysctl_maxsysfd();
    // debug_printf(NULL, 1, "max_sys_fd=%d\n", max_sys_fd);
    if (max_sys_fd <= 0) max_sys_fd = 16384; /* reasonable default */
    /* Let's leave at least 1024 FD for other processes */
    if (max_sys_fd < 1024)
      x = GRAB_MIN_SOCK;
    else
      {
	max_sys_fd -= 1024;
	x = max_sys_fd / max_hosts;
      }
    if (max_cnx > x) max_cnx = x;
#if 0
    fprintf(stderr, "min_cnx = %d ; max_cnx = %d\n", min_cnx, max_cnx);
#endif
    if (max_cnx > GRAB_MAX_SOCK) max_cnx = GRAB_MAX_SOCK;
    if (max_cnx < GRAB_MIN_SOCK) max_cnx = GRAB_MIN_SOCK;

    if (safe_checks && max_cnx > GRAB_MAX_SOCK_SAFE)
      max_cnx = GRAB_MAX_SOCK_SAFE;

    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
      perror("openvas_tcp_scanner->getrlimit(RLIMIT_NOFILE)");
    else
      {
	/* value = one greater than the maximum  file  descriptor number */
	if (rlim.rlim_cur != RLIM_INFINITY && max_cnx >= rlim.rlim_cur)
	  max_cnx = rlim.rlim_cur - 1;
      }
    x = max_cnx / 2;
    if (min_cnx > x) min_cnx = x > 0 ? x : 1;
  // debug_printf(NULL, 1, "min_cnx = %d ; max_cnx = %d\n", min_cnx, max_cnx);
  
  *pmin = min_cnx;
  *pmax = max_cnx;
}

#if !defined STANDALONE
int plugin_run(struct arglist * desc)
{
  struct arglist * globals = arg_get_value(desc, "globals");
  struct arglist * preferences = arg_get_value(desc, "preferences");
  struct arglist * hostinfos = arg_get_value(desc, "HOSTNAME");
  char * port_range = arg_get_value(preferences, "port_range");
  char * p;
  struct in_addr *p_addr;
  int	timeout = 0, max_cnx, min_cnx, safe_checks = 0, x;

  p = arg_get_value(preferences, "safe_checks");
  if (p != NULL && strcmp(p, "yes") == 0) safe_checks = 1;

  p =  arg_get_value(preferences, "checks_read_timeout");
  if (p != NULL) timeout = atoi(p);
  if (timeout <= 0)
    timeout = 5;
#if DEBUG > 0
  fprintf(stderr, "openvas_tcp_scanner: safe_checks=%d checks_read_timeout=%d\n", safe_checks, timeout);
#endif  

  {
    int		max_host = 0, max_checks = 0, cur_sys_fd = 0, max_sys_fd = 0;
    struct rlimit	rlim;
    FILE	*fp;
    int		i;
    double	loadavg[3], maxloadavg = -1.0;
#if DEBUG == 0
    int         stderr_fd = dup(2);
    int         devnull_fd = open("/dev/null", O_WRONLY);
    /* Avoid error messages from sysctl */
    dup2(devnull_fd, 2);
#endif

    p = arg_get_value(preferences, "max_hosts");
    if (p != NULL) max_host = atoi(p);
    if (max_host <= 0) max_host = 15;

    p = arg_get_value(preferences, "max_checks");
    if (p != NULL) max_checks = atoi(p);
    if (max_checks <= 0 || max_checks > 5)
      {
	max_checks = 5; /* bigger values do not make sense */
#if DEBUG > 0
	fprintf(stderr, "openvas_tcp_scanner: max_checks forced to %d\n", max_checks);
#endif
      }

    min_cnx = 8 * max_checks;
    if (safe_checks)
      max_cnx = 24 * max_checks;
    else
      max_cnx = 80 * max_checks;

    getloadavg(loadavg, 3);
    for (i = 0; i < 3; i ++)
      if (loadavg[i] > maxloadavg) maxloadavg = loadavg[i];

    if (max_sys_fd <= 0)
      {
	if ( find_in_path("sysctl", 0) != NULL )
	  fp = popen("sysctl fs.file-nr", "r");
  	else
	  fp = NULL;

	if (fp != NULL)
	  {
	    if (fscanf(fp, "%*s = %*d %d %d", &cur_sys_fd, &max_sys_fd) == 1)
	      max_sys_fd -= cur_sys_fd;
	    else
	      max_sys_fd = 0;	    
	    pclose(fp);
	  }
      }
    if (max_sys_fd <= 0)
      {
	if ( find_in_path("sysctl", 0) )
	  fp = popen("sysctl fs.file-max", "r");
	else
	  fp = NULL;

	if (fp != NULL)
	  {
	    fscanf(fp, "%*s = %d", &max_sys_fd);
	    pclose(fp);
	  }
      }

    if (max_sys_fd <= 0)
      {
	if ( find_in_path("sysctl", 0) )
	  fp = popen("sysctl kern.maxfiles", "r");
 	else
	  fp = NULL;

	if (fp != NULL)
	  {
	    fscanf(fp, "%*s = %d", &max_sys_fd);
	    pclose(fp);
	  }
      }

    /* Restore stderr */
#if DEBUG == 0
    close(devnull_fd);
    dup2(stderr_fd, 2);
    close(stderr_fd);
#endif

    if (maxloadavg >= 0.0)
      {
#if DEBUG > 0
	int	x = max_cnx;
#endif
	max_cnx /= (1.0 + maxloadavg);
#if DEBUG > 0
	/* Useless, as stderr is temporarily closed */
	fprintf(stderr, "openvas_tcp_scanner: max_cnx reduced from %d to %d because of maxloadavg=%f\n", x, max_cnx, maxloadavg);
#endif
      }
  


#if DEBUG > 0
    fprintf(stderr, "openvas_tcp_scanner: max_sys_fd=%d\n", max_sys_fd);
#endif
    if (max_sys_fd <= 0) max_sys_fd = 16384; /* reasonable default */
    /* Let's leave at least 1024 FD for other processes */
    if (max_sys_fd < 1024)
      x = GRAB_MIN_SOCK;
    else
      {
	max_sys_fd -= 1024;
	x = max_sys_fd / max_host;
      }
    if (max_cnx > x) max_cnx = x;
#if 0
    fprintf(stderr, "min_cnx = %d ; max_cnx = %d\n", min_cnx, max_cnx);
#endif
    if (max_cnx > GRAB_MAX_SOCK) max_cnx = GRAB_MAX_SOCK;
    if (max_cnx < GRAB_MIN_SOCK) max_cnx = GRAB_MIN_SOCK;

    if (safe_checks && max_cnx > GRAB_MAX_SOCK_SAFE)
      max_cnx = GRAB_MAX_SOCK_SAFE;

    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
      perror("getrlimit(RLIMIT_NOFILE)");
    else
      {
	/* value = one greater than the maximum  file  descriptor number */
	if (rlim.rlim_cur != RLIM_INFINITY && max_cnx >= rlim.rlim_cur)
	  max_cnx = rlim.rlim_cur - 1;
      }
    x = max_cnx / 2;
    if (min_cnx > x) min_cnx = x > 0 ? x : 1;
#if DEBUG > 0
    fprintf(stderr, "openvas_tcp_scanner: min_cnx = %d ; max_cnx = %d\n", min_cnx, max_cnx);
#endif
  }
  
  p_addr = arg_get_value(hostinfos, "IP");
  if( p_addr == NULL )
    return -1;
  if (banner_grab(p_addr, port_range, timeout, min_cnx, max_cnx, globals, desc, hostinfos) < 0)
    return -1;
  comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan", 65535, 65535);
  plug_set_key(desc, "Host/scanned", ARG_INT, (void*)1);
  plug_set_key(desc, "Host/scanners/openvas_tcp_scanner", ARG_INT, (void*)1);
  return 0;
}
#endif

/* Special code for standalone version
 * Compile with:
 * gcc -DSTANDALONE -I/opt/openvas/include/openvas openvas_tcp_scanner.c -o openvas_tcp_scanner -L/opt/openvas/lib -lopenvas -lssl -lpcap -lm
 */
#if defined STANDALONE
void
usage()
{
  fprintf(stderr, "Usage: openvas_tcp_scanner [options] IP port_range\n\
Options are:\n\
-C max_checks\n\
-H max_hosts\n\
-S\tSet safe_checks flag to TRUE\n\
-m min_cnx\tspecify the minimum number of connections\n\
-M max_cnx\tspecify the maximum number of connections\n\
Normally, min_cnx and max_cnx are computed from all other parameters\n\
-h\tPrint this help.\n\
");
  exit(1);
}

int
main(int argc, char *argv[])
{
  struct in_addr ia, *pia = NULL;
#ifdef IPV6_SUPPORT
  struct sockaddr_in6 ia6, *pia6 = NULL;
#endif
  int    timeout = 5, min_cnx, max_cnx, flags = ~0;
  int    safe_checks = 0, max_checks = 4, max_hosts = 4;
  int    min1 = 0, max1 = 0;
  int    i;
  
  while ((i = getopt(argc, argv, "m:M:C:H:ShrFRN")) != -1)
    switch(i)
    {
    case 'm':
      if (optarg == NULL) usage();
      else min1 = atoi(optarg);
      break;
    case 'M':
      if (optarg == NULL) usage();
      else max1 = atoi(optarg);
      break;
    case 'S':
      safe_checks = 1; break;
    case 'C':
      if (optarg == NULL) usage();
      else max_checks = atoi(optarg);
      break;
    case 'H':
      if (optarg == NULL) usage();
      else max_hosts = atoi(optarg);
      break;
      
    case 'h':
      usage();
      break;
  }
  if (argc != optind + 2) usage();
  if (inet_pton(AF_INET, argv[optind], &ia) > 0)
    pia = &ia;
#ifdef IPV6_SUPPORT
  else if (inet_pton(AF_INET6, argv[optind], &ia6) > 0)
    {
      pia6 = &ia6;
      ia6.sin6_family = AF_INET6;
    }
#endif
  else
    {
      fprintf(stderr, "Bad IP address %s\n", argv[optind]);
      return 1;
    }
  if (min1 <= 0 || max1 <= 0)
    compute_min_max_cnx(max_hosts, max_checks, safe_checks,
			&min_cnx, &max_cnx);
  if (min1 > 0) min_cnx = min1;
  if (max1 > 0) max_cnx = max1;
  
  if (banner_grab(pia, 
#ifdef IPV6_SUPPORT
		  pia6,
#endif
		  argv[optind+1], timeout, min_cnx, max_cnx, NULL, NULL, NULL) < 0)
    return -1;

  return 0;
}
#endif
/* STANDALONE */


