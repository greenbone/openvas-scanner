/* OpenVAS
 * $Id$
 * Description: IDS stressing functions.
 *
 * ids_send() sends data spliced into several packets, with bad packets
 * between them, thus making bad NIDSes reassemble the tcp stream awkwardly;
 *
 * ids_open_sock_tcp() opens a tcp socket and immediately sends a badly
 * formed RST packet to the remote host, thus making bad NIDSes think
 * the connection was immediately dropped on our end.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2002 Renaud Deraison
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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <gvm/base/logging.h>

#include "bpf_share.h"
#include "ids_send.h"
#include "network.h"
#include "pcap_openvas.h"
#include "plugutils.h"
#include "support.h"

/** @todo: It still needs to be taken care
 * BSD_BYTE_ORDERING gets here if defined (e.g. by config.h) */
#ifdef BSD_BYTE_ORDERING
# define FIX(n) (n)
# define UNFIX(n) (n)
#else
# define FIX(n) htons(n)
# define UNFIX(n) ntohs(n)
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/*
 * We define our own packet structs (they'll be defined in libnasl later
 * on, and I feel lazy today)
 */
struct ip_packet
{
#if !WORDS_BIGENDIAN
  u_char ip_hl:4,               /* header length */
    ip_v:4;                     /* version */
#else
  u_char ip_v:4,                /* version */
    ip_hl:4;                    /* header length */
#endif
  u_char ip_tos;                /* type of service */
  u_short ip_len;               /* total length */
  u_short ip_id;                /* identification */
  u_short ip_off;               /* fragment offset field */
  u_char ip_ttl;                /* time to live */
  u_char ip_p;                  /* protocol */
  u_short ip_sum;               /* checksum */
  struct in_addr ip_src, ip_dst;        /* source and dest address */
};

struct tcp_packet
{
  u_short th_sport;             /* source port */
  u_short th_dport;             /* destination port */
  u_long th_seq;                /* sequence number */
  u_long th_ack;                /* acknowledgement number */
#if !WORDS_BIGENDIAN
  u_int th_x2:4,                /* (unused) */
    th_off:4;                   /* data offset */
#endif
#if WORDS_BIGENDIAN
  u_int th_off:4,               /* data offset */
    th_x2:4;                    /* (unused) */
#endif
  u_char th_flags;

  u_short th_win;               /* window */
  u_short th_sum;               /* checksum */
  u_short th_urp;               /* urgent pointer */
};


struct ipv6_header
{
  union
  {
    struct ip6_hdrctl
    {
      uint32_t ip6_un1_flow;    /* 24 bits of flow-ID */
      uint16_t ip6_un1_plen;    /* payload length */
      uint8_t ip6_un1_nxt;      /* next header */
      uint8_t ip6_un1_hlim;     /* hop limit */
    } ip6_un1;
    uint8_t ip6_un2_vfc;        /* 4 bits version, 4 bits priority */
  } ip6_ctlun;
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
};


/*
 * our own definition of the tcp flags
 */
#define TCP_FLAG_RST  0x0004
#define TCP_FLAG_ACK  0x0010
#define TCP_FLAG_PUSH 0x0008


struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcp_packet tcpheader;
};

union sockaddr_u {
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
  struct sockaddr sockaddr;
};

/*
 * This function returns the TTL we should use when forging our own
 * IP packets. If <method & OPENVAS_CNX_IDS_EVASION_SHORT_TTL>, then
 * it returns an estimation of the number of hops between us and the
 * remote host (see comment), minus 1.
 *
 * By default, it returns the TTL our OS usually returns (to be improved)
 *
 */
static int
which_ttl (method, old_ttl)
     int method, old_ttl;
{
  int ttl;

  if (method & OPENVAS_CNX_IDS_EVASION_SHORT_TTL)
    {
      /*
       * XXXX
       * To find out the number of hops to the remote host,
       * we assume that the TTL set remotely is one of {32,64,128,255}.
       * (by default, I know of no OS which uses a different value)
       *
       * We could fine grain that by reading Host/OS or even by
       * computing the traceroute by ourselves (especially since we're
       * not sure that our packets will go through the same path as those
       * we receive) however this will do for now.
       */
      int num_hops = old_ttl;
      if (num_hops < 32)
        {
          ttl = 32 - num_hops;
        }
      else if (num_hops < 64)
        {
          ttl = 64 - num_hops;
        }
      else if (num_hops < 128)
        {
          ttl = 128 - num_hops;
        }
      else
        ttl = 255 - num_hops;
    }
  /*
   * We try to set up a 'normal' TTL
   */
  else                          /* if(method & OPENVAS_CNX_IDS_EVASION_INJECT) */
    {
#ifdef LINUX
      int f;
      f = open ("/proc/sys/net/ipv4/ip_default_ttl", O_RDONLY);
      if (f >= 0)
        {
          char rd[20];

          /* RATS issues the following warning for this line:
           * "Check buffer boundaries if calling this function in a loop and make sure
           * you are not in danger of writing past the allocated space."
           * This warning can IMHO be ignored as long as the buffer size of rd is
           * hardcoded since we will read at most sizeof(rd)-1 bytes into rd.
           *   -mwiegand, 20090205
           */
          read (f, rd, sizeof (rd) - 1);
          close (f);
          ttl = atoi (rd);
        }
      else
        {
          ttl = 64;
        }
#else
      /*
       * TODO :
       * XXX sysctl support (BSD)
       * XXX Solaris support...
       */
      ttl = 64;
#endif
    }

  return ttl;
}


static int
in_cksum (p, n)
     u_short *p;
     int n;
{
  register u_short answer;
  register long sum = 0;
  u_short odd_byte = 0;

  while (n > 1)
    {
      sum += *p++;
      n -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (n == 1)
    {
      *(u_char *) (&odd_byte) = *(u_char *) p;
      sum += odd_byte;
    }

  sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
  sum += (sum >> 16);           /* add carry */
  answer = (int) ~sum;          /* ones-complement, truncate */
  return (answer);
}


static int
tcp_cksum (packet, len)
     char *packet;
     int len;
{
  struct pseudohdr pseudoheader;
  char *tcpsumdata = g_malloc0 (sizeof (struct pseudohdr) + len + 1);
  struct in_addr source, dest;
  struct ip_packet *ip = (struct ip_packet *) packet;
  struct tcp_packet *tcp = (struct tcp_packet *) (packet + ip->ip_hl * 4);
  char *data = (char *) (packet + ip->ip_hl * 4 + tcp->th_off * 4);

  source.s_addr = ip->ip_src.s_addr;
  dest.s_addr = ip->ip_dst.s_addr;

  bzero (&pseudoheader, 12 + sizeof (struct tcp_packet));
  pseudoheader.saddr.s_addr = source.s_addr;
  pseudoheader.daddr.s_addr = dest.s_addr;

  pseudoheader.protocol = IPPROTO_TCP;
  pseudoheader.length = htons (sizeof (struct tcp_packet) + len);
  bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
         sizeof (struct tcp_packet));
  /* fill tcpsumdata with data to checksum */
  bcopy ((char *) &pseudoheader, tcpsumdata, sizeof (struct pseudohdr));
  bcopy ((char *) data, tcpsumdata + sizeof (struct pseudohdr), len);
  tcp->th_sum =
    in_cksum ((unsigned short *) tcpsumdata,
              12 + sizeof (struct tcp_packet) + len);
  g_free (tcpsumdata);
  return 0;
}


/*
 * This function injects a tcp packet in a stream. If
 * method & OPENVAS_CNX_IDS_EVASION_SHORT_TTL != 0, then
 * the injected tcp packet will be completely valid but will
 * have a short TTL (so that it does not reach the remote host).
 *
 * If method & OPENVAS_CNX_IDS_EVASION_INJECT != 0, then
 * the injected tcp packet will have a normal TTL but will
 * have a bad checksum.
 *
 * <orig_packet> is the capture of the last packet sent by the
 * remote host (hopefully a ACK). We use it to obtain the th_seq
 * and th_ack elements that are being waited for by the remote
 * host.
 *
 * <packet_len> is the size of the captured packet
 *
 *
 * We also use the ttl of the packet to determine the number
 * of hops between us and the remote host (see the function
 * which_ttl()).
 *
 * <flags> are the flags of the tcp packet we should send (RST, ...)
 *
 * <data> is the data we should append to our tcp packet. This can
 * be NULL
 * <data_len> is the length of the data.
 *
 *
 * Note that this function opens a raw socket each time it's called, which
 * is highly inefficient.
 */
static int
inject (orig_packet, packet_len, method, flags, data, data_len)
     char *orig_packet;
     unsigned int packet_len;
     int method;
     int flags;
     char *data;
     int data_len;
{
  int soc;
  char *packet;
  struct ip_packet *ip, *old_ip;
  struct tcp_packet *tcp, *old_tcp;
  int tot_len =
    sizeof (struct ip_packet) + sizeof (struct tcp_packet) + data_len;
  int i;
  int one = 1;
  struct sockaddr_in sockaddr;

  if (packet_len < sizeof (struct ip_packet) + sizeof (struct tcp_packet))
    return -1;



  old_ip = (struct ip_packet *) orig_packet;

  if ((old_ip->ip_hl * 4) + sizeof (struct tcp_packet) > packet_len)
    return -1;

  old_tcp = (struct tcp_packet *) (orig_packet + (old_ip->ip_hl * 4));


  soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return -1;

  setsockopt (soc, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one));
  packet = g_malloc0 (tot_len);

  /*
   * Copy data, if any
   */
  for (i = 0; i < data_len; i++)
    packet[i + sizeof (struct ip_packet)] = data[i];

  ip = (struct ip_packet *) packet;
  tcp = (struct tcp_packet *) (packet + sizeof (struct ip_packet));

  /*
   * for the sake of code shortness, we copy the header of the
   * received packet into the packet we forge, and we'll change
   * some stuff in it.
   */
  memcpy (ip, old_ip, sizeof (struct ip_packet));

  ip->ip_len = FIX (tot_len);
  ip->ip_hl = 5;
  ip->ip_off = 0;
  ip->ip_src.s_addr = old_ip->ip_dst.s_addr;
  ip->ip_dst.s_addr = old_ip->ip_src.s_addr;
  ip->ip_id = rand ();
  ip->ip_ttl = which_ttl (method, old_ip->ip_ttl);
  ip->ip_sum = in_cksum ((u_short *) packet, sizeof (struct ip_packet));

  memcpy (tcp, old_tcp, sizeof (struct tcp_packet));
  tcp->th_flags = flags;
  if ((flags & TCP_FLAG_RST) && (method & OPENVAS_CNX_IDS_EVASION_FAKE_RST))
    tcp->th_ack = htonl (ntohl (old_tcp->th_seq) + 1);
  else
    tcp->th_ack = old_tcp->th_seq;

  tcp->th_seq = old_tcp->th_ack;
  tcp->th_sport = old_tcp->th_dport;
  tcp->th_dport = old_tcp->th_sport;
  tcp->th_off = 5;
  tcp->th_sum = 0;
  if (method & OPENVAS_CNX_IDS_EVASION_SHORT_TTL)
    tcp_cksum (packet, data_len);
  else
    tcp->th_sum = rand ();      /* bad checksum - packet will be dropped */


  /*
   * Sending the packet now
   */
  bzero (&sockaddr, sizeof (sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = ip->ip_dst.s_addr;


  if (sendto
      (soc, packet, tot_len, 0, (struct sockaddr *) &sockaddr,
       sizeof (sockaddr)) < 0)
    {
      perror
        ("openvas-scanner : libopenvas : ids_send.c : inject() : sendto() ");
    }
  g_free (packet);
  close (soc);
  return 0;
}


static int
injectv6 (orig_packet, packet_len, method, flags, data, data_len)
     char *orig_packet;
     unsigned int packet_len;
     int method;
     int flags;
     char *data;
     int data_len;
{
  int soc;
  char *packet;
  struct ipv6_header *ip6, *old_ip6;
  struct tcp_packet *tcp, *old_tcp;
  int tot_len =
    sizeof (struct ipv6_header) + sizeof (struct tcp_packet) + data_len;
  int i;
  struct sockaddr_in6 sockaddr6;

  if (packet_len < sizeof (struct ipv6_header) + sizeof (struct tcp_packet))
    return -1;

  old_ip6 = (struct ipv6_header *) orig_packet;
  old_tcp = (struct tcp_packet *) (orig_packet + 40);

  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return -1;

  packet = g_malloc0 (tot_len);

  /*
   * Copy data, if any
   */
  for (i = 0; i < data_len; i++)
    {
      packet[i + sizeof (struct ipv6_header)] = data[i];
    }

  ip6 = (struct ipv6_header *) packet;
  tcp = (struct tcp_packet *) (packet + sizeof (struct ipv6_header));

  /*
   * for the sake of code shortness, we copy the header of the
   * received packet into the packet we forge, and we'll change
   * some stuff in it.
   */
  memcpy (ip6, old_ip6, sizeof (struct ipv6_header));

  ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = old_ip6->ip6_ctlun.ip6_un1.ip6_un1_flow;
  ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = data_len;
  ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = old_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim =
    which_ttl (method, old_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
  memcpy (&ip6->ip6_src, &old_ip6->ip6_dst, sizeof (struct in6_addr));
  memcpy (&ip6->ip6_dst, &old_ip6->ip6_src, sizeof (struct in6_addr));

  memcpy (tcp, old_tcp, sizeof (struct tcp_packet));
  tcp->th_flags = flags;
  if ((flags & TCP_FLAG_RST) && (method & OPENVAS_CNX_IDS_EVASION_FAKE_RST))
    tcp->th_ack = htonl (ntohl (old_tcp->th_seq) + 1);
  else
    tcp->th_ack = old_tcp->th_seq;

  tcp->th_seq = old_tcp->th_ack;
  tcp->th_sport = old_tcp->th_dport;
  tcp->th_dport = old_tcp->th_sport;
  tcp->th_off = 5;
  tcp->th_sum = 0;
  if (method & OPENVAS_CNX_IDS_EVASION_SHORT_TTL)
    tcp_cksum (packet, data_len);
  else
    tcp->th_sum = rand ();      /* bad checksum - packet will be dropped */


  /*
   * Sending the packet now
   */
  bzero (&sockaddr6, sizeof (sockaddr6));
  sockaddr6.sin6_family = AF_INET6;
  sockaddr6.sin6_addr = ip6->ip6_dst;

  if (sendto
      (soc, packet, tot_len, 0, (struct sockaddr *) &sockaddr6,
       sizeof (sockaddr6)) < 0)
    {
      perror
        ("openvas-scanner : libopenvas : ids_send.c : inject() : sendto() ");
    }
  g_free (packet);
  close (soc);
  return 0;
}


int
ids_send (fd, buf0, n, method)
     int fd;
     void *buf0;
     int n;
     int method;
{
  struct in_addr dst, src;
  struct in6_addr dst6, src6;
  struct sockaddr_in6 sockaddr6;
  struct sockaddr_in *saddr;
  struct sockaddr *sa;
  union sockaddr_u *su = NULL;
  char *iface;
  char filter[255];
  char *src_host, *dst_host;
  int port;
  int ret = 0;
  int len;
  char *buf = (char *) buf0;
  unsigned int sz = sizeof (sockaddr6);
  int e;
  unsigned char *packet;
  int bpf;
  char hostname[INET6_ADDRSTRLEN];
  int family;

  if (getpeername (fd, &(su->sockaddr), &sz) < 0)
    {
      perror ("getpeername() ");
      return -1;
    }
  sa = &(su->sockaddr);
  if (sa->sa_family == AF_INET)
    {
      family = AF_INET;
      saddr = &(su->in);
      port = ntohs (saddr->sin_port);
      dst.s_addr = saddr->sin_addr.s_addr;
      src.s_addr = 0;
      iface = routethrough (&dst, &src);

      src_host = g_strdup (inet_ntoa (src));
      dst_host = g_strdup (inet_ntoa (dst));

      snprintf (filter, sizeof (filter),
                "tcp and (src host %s and dst host %s and src port %d)",
                dst_host, src_host, port);
      g_free (src_host);
      g_free (dst_host);
    }
  else
    {
      sockaddr6 = su->in6;
      family = AF_INET6;
      port = ntohs (sockaddr6.sin6_port);
      memcpy (&dst6, &sockaddr6.sin6_addr, sizeof (struct in6_addr));
      bzero (&src6, sizeof (src6));
      iface = v6_routethrough (&dst6, &src6);

      src_host =
        g_strdup (inet_ntop (AF_INET6, &src6, hostname, sizeof (hostname)));
      dst_host =
        g_strdup (inet_ntop (AF_INET6, &dst6, hostname, sizeof (hostname)));
      snprintf (filter, sizeof (filter),
                "tcp and (src host %s and dst host %s and src port %d)",
                dst_host, src_host, port);
      g_free (src_host);
      g_free (dst_host);
    }

  bpf = bpf_open_live (iface, filter);
  if (bpf >= 0)
    {
      e = send (fd, buf + ret, 1, 0);
      packet = bpf_next (bpf, &len);
      if (e < 0)
        return -1;
      else
        ret += e;
      /*
       * We can start to send stuff now
       */
      while (ret < n)
        {
          if (packet)
            {
              char *pkt_ip;
              int num_before = (rand () / 1000) % 3;
              int num_after = (rand () / 1000) % 3;
              int i;

              if (!num_before && !num_after)
                {
                  if (rand () % 2)
                    num_before = 1;
                  else
                    num_after = 1;
                }
              pkt_ip =
                (char *) (packet + get_datalink_size (bpf_datalink (bpf)));

              /*
               * send bogus data before
               */
              for (i = 0; i < num_before; i++)
                {
                  int j;
                  char data[10];
                  for (j = 0; j < 10; j++)
                    data[j] = rand ();
                  if (family == AF_INET)
                    inject (pkt_ip,
                            len - get_datalink_size (bpf_datalink (bpf)),
                            method, TCP_FLAG_ACK | TCP_FLAG_PUSH, data,
                            (rand () % 9) + 1);
                  else
                    injectv6 (pkt_ip,
                              len - get_datalink_size (bpf_datalink (bpf)),
                              method, TCP_FLAG_ACK | TCP_FLAG_PUSH, data,
                              (rand () % 9) + 1);

                }
              e = send (fd, buf + ret, 1, 0);
              packet = bpf_next (bpf, &len);
              /*
               * send bogus data after
               */
              for (i = 0; i < num_after; i++)
                {
                  int j;
                  char data[10];
                  for (j = 0; j < 10; j++)
                    data[j] = rand ();
                  if (family == AF_INET)
                    inject (pkt_ip,
                            len - get_datalink_size (bpf_datalink (bpf)),
                            method, TCP_FLAG_ACK | TCP_FLAG_PUSH, data,
                            (rand () % 9) + 1);
                  else
                    injectv6 (pkt_ip,
                              len - get_datalink_size (bpf_datalink (bpf)),
                              method, TCP_FLAG_ACK | TCP_FLAG_PUSH, data,
                              (rand () % 9) + 1);
                }
            }
          else
            {
              e = send (fd, buf + ret, 1, 0);
              packet = bpf_next (bpf, &len);
            }
          if (e < 0)
            return -1;
          else
            ret += e;
        }
      bpf_close (bpf);
      return ret;
    }
  else
    return send (fd, buf, n, 0);
}


int
ids_open_sock_tcp (struct script_infos *args, int port, int method, int timeout)
{
  int bpf;
  struct in_addr dst, src;
  struct in6_addr *dst6 = NULL, src6;
  char *iface;
  char filter[255];
  char *src_host, *dst_host;
  int ret = 0;
  int len;
  char hostname[INET6_ADDRSTRLEN];
  int family;

  dst6 = plug_get_host_ip (args);
  if (!dst6)
    {
      g_message ("Error - no address associated with name");
      return -1;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6))
    {
      family = AF_INET;
      dst.s_addr = dst6->s6_addr32[3];
      src.s_addr = 0;
      iface = routethrough (&dst, &src);
      src_host = g_strdup (inet_ntoa (src));
      dst_host = g_strdup (inet_ntoa (dst));
    }
  else
    {
      family = AF_INET6;
      iface = v6_routethrough (dst6, &src6);
      src_host =
        g_strdup (inet_ntop (AF_INET6, &src6, hostname, sizeof (hostname)));
      dst_host =
        g_strdup (inet_ntop (AF_INET6, dst6, hostname, sizeof (hostname)));
    }

  snprintf (filter, sizeof (filter),
            "tcp and (src host %s and dst host %s and src port %d)", dst_host,
            src_host, port);

  g_free (src_host);
  g_free (dst_host);


  bpf = bpf_open_live (iface, filter);
  if (bpf >= 0)
    {
      ret = open_sock_tcp (args, port, timeout);
      if (ret >= 0)
        {
          unsigned char *packet = bpf_next (bpf, &len);
          if (packet)
            {
              char *pkt_ip;
              pkt_ip =
                (char *) (packet + get_datalink_size (bpf_datalink (bpf)));

              if (family == AF_INET)
                inject (pkt_ip, len - get_datalink_size (bpf_datalink (bpf)),
                        method, TCP_FLAG_RST, NULL, 0);
              else
                injectv6 (pkt_ip, len - get_datalink_size (bpf_datalink (bpf)),
                          method, TCP_FLAG_RST, NULL, 0);
            }
        }
      bpf_close (bpf);
      return ret;
    }
  else
    return open_sock_tcp (args, port, timeout);
}
