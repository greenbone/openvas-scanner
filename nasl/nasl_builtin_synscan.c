/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_builtin_synscan.c
 * @brief Port scanner Synscan
 */

/* legacy feature macro */
#define _BSD_SOURCE 1
/* new feature macros that provides the same plus more */
#define _DEFAULT_SOURCE 1
#undef _SVID_SOURCE

#include "../misc/bpf_share.h"    /* for bpf_open_live */
#include "../misc/network.h"      /* for getpts */
#include "../misc/pcap_openvas.h" /* for get_datalink_size */
#include "../misc/plugutils.h"    /* for scanner_add_port */
#include "nasl_builtin_plugins.h"
#include "nasl_lex_ctxt.h"

#include <arpa/inet.h> /* for AF_INET */
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <netinet/ip.h>
#include <netinet/tcp.h> /* for TH_SYN */
#include <stdlib.h>      /* for rand() */
#include <string.h>      /* for memcpy() */
#include <unistd.h>      /* for close() */

#undef SHOW_RETRIES
#undef SHOW_RTT_REMOVAL

#define NUM_RETRIES 2

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"
/*----------------------------------------------------------------------------*/
struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcphdr tcpheader;
};

static int
in_cksum (u_short *p, int n)
{
  register u_short answer;
  register unsigned long sum = 0;
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
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = (int) ~sum;                /* ones-complement, truncate */
  return (answer);
}

static unsigned long
maketime ()
{
  struct timeval tv;
  unsigned long ret;

  gettimeofday (&tv, NULL);

  ret = ((tv.tv_sec & 0x0000000F) << 28) | (((tv.tv_usec) & 0xFFFFFFF0) >> 4);

  return htonl (ret);
}

static struct timeval
timeval (unsigned long val)
{
  struct timeval ret;
  unsigned int h, l;

  val = ntohl (val);

  h = (val & 0xF0000000) >> 28;
  l = (val & 0x0FFFFFFF) << 4;

  ret.tv_sec = h;
  ret.tv_usec = l;
  while (ret.tv_usec >= 1000000)
    {
      ret.tv_usec -= 1000000;
      ret.tv_sec++;
    }

  if (ret.tv_sec > 2)
    {
      ret.tv_sec = 2;
      ret.tv_usec = 0;
    }
  return ret;
}

static unsigned long
compute_rtt (unsigned long then)
{
  unsigned long now = maketime ();
  unsigned long res;
  unsigned long a, b;

  a = (unsigned long) ntohl (now);
  b = (unsigned long) ntohl (then);

  if (b > a)
    {
      return 0;
    }
  res = a - b;
  if (res >= (1 << 28))
    res = 1 << 28;

  return htonl (res);
}

static int
packetdead (unsigned long then)
{
  unsigned long now = maketime ();

  then = ntohl (then);
  now = ntohl (now);

  if ((now - then) >= 2 << 28)
    {
      return 1;
    }

  return 0;
}

/**
 * @brief Opens and returns a raw socket.
 */
static int
rawsocket (int family)
{
  int soc;
  int opt = 1;
  int offset = 8;

  if (family == AF_INET)
    {
      soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
      if (soc < 0)
        {
          perror ("socket ");
          printf ("error opeinig socket\n");
          return -1;
        }
      if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, /*(char *) */ &opt,
                      sizeof (opt))
          < 0)
        {
          perror ("setsockopt ");
          printf ("error setting socket opt\n");
          close (soc);
          return -1;
        }
    }
  else
    {
      soc = socket (AF_INET6, SOCK_RAW, IPPROTO_TCP);
      if (soc < 0
          || setsockopt (soc, IPPROTO_IPV6, IPV6_CHECKSUM, &offset,
                         sizeof (offset))
               < 0)
        {
          perror ("socket ");
          printf ("error opening socket\n");
          if (soc >= 0)
            close (soc);
          return -1;
        }
    }

  return soc;
}

/**
 * @brief Opens a packet filter, grabs packets from \p dst to port \p magic
 *
 * @param[out] src   in_addr of source.
 * @param[in]  dst   Destination.
 * @param[in]  magic Destination port on src to listen to.
 *
 * @return A bpf that listens to tcp packets coming from \p dst to port
 *         \p magic.
 */
static int
openbpf (struct in_addr dst, struct in_addr *src, int magic)
{
  char *iface;
  char filter[255];
  int bpf;

  iface = routethrough (&dst, src);
  snprintf (filter, sizeof (filter), "tcp and src host %s and dst port %d",
            inet_ntoa (dst), magic);
  bpf = bpf_open_live (iface, filter);
  return bpf;
}

static int
v6_openbpf (struct in6_addr *dst, struct in6_addr *src, int magic)
{
  char *iface;
  char filter[255];
  char hostname[INET6_ADDRSTRLEN];
  int bpf;

  iface = v6_routethrough (dst, src);

  snprintf (filter, sizeof (filter), "tcp and src host %s and dst port %d",
            inet_ntop (AF_INET6, dst, hostname, sizeof (hostname)), magic);
  bpf = bpf_open_live (iface, filter);
  if (bpf < 0)
    printf ("bpf_open_live returned error\n");
  return bpf;
}
/*----------------------------------------------------------------------------*/

struct list
{
  unsigned short dport;
  unsigned long when;
  int retries;
  struct list *prev;
  struct list *next;
};

/**
 * @return First pointer to list in l with the given \p dport , NULL if no
 *         such list item could be found.
 */
static struct list *
get_packet (struct list *l, unsigned short dport)
{
  while (l != NULL)
    {
      if (l->dport == dport)
        return l;
      else
        l = l->next;
    }
  return NULL;
}

/**
 * @brief If no packet with \p dport is in list, prepends a "packet" to the
 * @brief list \p l.
 */
static struct list *
add_packet (struct list *l, unsigned short dport, unsigned long ack)
{
  struct list *ret;

  ret = get_packet (l, dport);
  if (ret != NULL)
    {
#ifdef SHOW_RETRIES
      printf ("RETRIES FOR %d = %d\n", dport, ret->retries);
#endif
      ret->retries++;
      ret->when = ack;
      return l;
    }
  ret = g_malloc0 (sizeof (struct list));

  ret->next = l;
  ret->prev = NULL;
  if (ret->next != NULL)
    ret->next->prev = ret;

  ret->dport = dport;
  ret->when = ack;
  ret->retries = 0;
  return ret;
}

static struct list *
rm_packet (struct list *l, unsigned short dport)
{
  struct list *ret = l;
  struct list *p = get_packet (l, dport);

  if (p == NULL)
    return l;
  if (p->next != NULL)
    p->next->prev = p->prev;

  if (p->prev != NULL)
    p->prev->next = p->next;
  else
    ret = p->next;

  g_free (p);
  return ret;
}

static struct list *
rm_dead_packets (struct list *l, int *retry)
{
  struct list *ret = l;
  struct list *p = l;

  *retry = 0;
  while (p != NULL)
    {
      struct list *next = p->next;
      if (packetdead (p->when))
        {
          if (p->retries < NUM_RETRIES)
            {
#ifdef SHOW_RETRIES
              printf ("Will retry port %d\n", p->dport);
#endif
              *retry = p->dport;
            }
          else
            {
#ifdef SHOW_RTT_REMOVAL
              printf ("Removing port %d (RTT elapsed)\n", p->dport);
#endif
              if (p->next != NULL)
                p->next->prev = p->prev;

              if (p->prev != NULL)
                p->prev->next = p->next;
              else
                {
                  if (p->next == NULL)
                    {
                      g_free (p);
                      return NULL;
                    }
                  ret = p->next;
                  g_free (p);
                }
            }
        }
      p = next;
    }
  return ret;
}

/*-----------------------------------------------------------------------------*/

static struct tcphdr *
extracttcp (char *pkt, unsigned int len)
{
  struct ip *ip;
  struct tcphdr *tcp;

  ip = (struct ip *) pkt;
  if (ip->ip_hl * 4 + sizeof (struct tcphdr) > len)
    return NULL;

  tcp = (struct tcphdr *) (pkt + ip->ip_hl * 4);
  return tcp;
}

static struct tcphdr *
v6_extracttcp (char *pkt)
{
  struct tcphdr *tcp;
  tcp = (struct tcphdr *) (pkt + 40);
  return tcp;
}

static unsigned long
extractack (char *pkt, int len, int family)
{
  unsigned long ret;
  struct tcphdr *tcp;
  if (family == AF_INET)
    tcp = extracttcp (pkt, len);
  else
    tcp = v6_extracttcp (pkt);

  if (tcp == NULL)
    return -1;

  ret = htonl (ntohl (tcp->th_ack) - 1);
  return ret;
}

static unsigned short
extractsport (char *pkt, int len, int family)
{
  struct tcphdr *tcp;

  if (family == AF_INET)
    tcp = extracttcp (pkt, len);
  else
    tcp = v6_extracttcp (pkt);

  if (tcp == NULL)
    return 0;

  return ntohs (tcp->th_sport);
}

static int
issynack (char *pkt, int len, int family)
{
  struct tcphdr *tcp;

  if (family == AF_INET)
    tcp = extracttcp (pkt, len);
  else
    tcp = v6_extracttcp (pkt);

  if (tcp == NULL)
    return 0;

  return tcp->th_flags == (TH_SYN | TH_ACK);
}

static char *
mktcp (struct in_addr src, int sport, struct in_addr dst, int dport,
       unsigned long th_ack, unsigned char flag)
{
  static char pkt[sizeof (struct ip) + sizeof (struct tcphdr)];
  struct ip *ip;
  struct tcphdr *tcp;
  struct pseudohdr pseudohdr;
  char tcpsumdata[sizeof (pseudohdr)];

  ip = (struct ip *) (&pkt);
  ip->ip_hl = 5;
  ip->ip_v = 4;
  ip->ip_tos = 0;
  ip->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
  ip->ip_id = rand ();
  ip->ip_off = 0;
  ip->ip_ttl = 64;
  ip->ip_p = IPPROTO_TCP;
  ip->ip_sum = 0;
  ip->ip_src.s_addr = src.s_addr;
  ip->ip_dst.s_addr = dst.s_addr;
  ip->ip_sum = in_cksum ((u_short *) pkt, sizeof (struct ip));

  tcp = (struct tcphdr *) (&(pkt[sizeof (struct ip)]));
  tcp->th_sport = htons (sport);
  tcp->th_dport = htons (dport);
  tcp->th_seq = th_ack;
  tcp->th_ack = 0;
  tcp->th_x2 = 0;
  tcp->th_off = 5;
  tcp->th_flags = flag;
  tcp->th_win = 4096;
  tcp->th_sum = 0;
  tcp->th_urp = 0;

  bzero (&pseudohdr, sizeof (pseudohdr));
  pseudohdr.saddr.s_addr = src.s_addr;
  pseudohdr.daddr.s_addr = dst.s_addr;
  pseudohdr.protocol = IPPROTO_TCP;
  pseudohdr.length = htons (sizeof (struct tcphdr));
  bcopy ((char *) tcp, (char *) &pseudohdr.tcpheader, sizeof (struct tcphdr));
  bcopy (&pseudohdr, tcpsumdata, sizeof (struct pseudohdr));
  tcp->th_sum =
    in_cksum ((unsigned short *) tcpsumdata, 12 + sizeof (struct tcphdr));

  return pkt;
}

static char *
mktcpv6 (int sport, int dport, unsigned long th_ack, unsigned char flag)
{
  static char pkt[sizeof (struct tcphdr)];
  struct tcphdr *tcp;

  tcp = (struct tcphdr *) (&(pkt[0]));
  tcp->th_sport = htons (sport);
  tcp->th_dport = htons (dport);
  tcp->th_ack = htonl (rand ());
  tcp->th_seq = th_ack;
  tcp->th_off = 5;
  tcp->th_flags = flag;
  tcp->th_win = htons (5760);
  tcp->th_urp = 0;
  tcp->th_sum = 2;

  return pkt;
}
/*--------------------------------------------------------------------*/

/**
 * @param sniff If != 0, "sniff" (listen to incoming packages), else just
 *              add packet.
 */
static struct list *
sendpacket (int soc, int bpf, int skip, struct in_addr dst, struct in_addr src,
            int dport, int magic, struct list *packets, unsigned long *rtt,
            int sniff, struct script_infos *env)
{
  unsigned long ack = maketime ();
  char *pkt = mktcp (src, magic, dst, dport, ack, TH_SYN);
  int len;
  char *res;
  struct sockaddr_in soca;
  struct timeval rtt_tv = timeval (*rtt);
  int family = AF_INET;

  bzero (&soca, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = dst;

  rtt_tv.tv_sec *= 1000;
  rtt_tv.tv_sec /= 8;

  rtt_tv.tv_usec += (rtt_tv.tv_sec % 1000) * 1000;
  rtt_tv.tv_sec /= 1000;
  if (rtt_tv.tv_sec >= 1)
    {
      rtt_tv.tv_sec = 1;
      rtt_tv.tv_usec = 0;
    }

  if (dport != 0)
    {
      int e;
      packets = add_packet (packets, dport, ack);
      e = sendto (soc, pkt, sizeof (struct ip) + sizeof (struct tcphdr), 0,
                  (struct sockaddr *) &soca, sizeof (soca));
      if (e < 0)
        {
          perror ("sendto ");
          close (soc);
          bpf_close (bpf);
          return NULL;
        }
    }
  if (sniff != 0)
    {
    again:
      res = (char *) bpf_next_tv (bpf, &len, &rtt_tv);
      if (res != NULL)
        {
          unsigned short sport = extractsport (res + skip, len, family);
          int synack = issynack (res + skip, len, family);
          unsigned int rack = extractack (res + skip, len, family);
          if (synack)
            {
              char *rst;
              scanner_add_port (env, sport, "tcp");
              /* Send a RST to make sure the connection is closed on the remote
               * side */
              rst = mktcp (src, magic, dst, sport, ack + 1, TH_RST);
              if (sendto (soc, rst, sizeof (struct ip) + sizeof (struct tcphdr),
                          0, (struct sockaddr *) &soca, sizeof (soca))
                  < 0)
                {
                  perror ("sendto ");
                  close (soc);
                  bpf_close (bpf);
                  return NULL;
                }

              /* Adjust the rtt */
              *rtt = compute_rtt (rack);
              if (ntohl (*rtt) >= (1 << 28))
                *rtt = 1 << 28;
            }
          packets = rm_packet (packets, sport);
          rtt_tv.tv_sec = 0;
          rtt_tv.tv_usec = 0;
          goto again;
        }
    }
  return packets;
}

static struct list *
v6_sendpacket (int soc, int bpf, int skip, struct in6_addr *dst, int dport,
               int magic, struct list *packets, unsigned long *rtt, int sniff,
               struct script_infos *env)
{
  unsigned long ack = maketime ();
  char *pkt = mktcpv6 (magic, dport, ack, TH_SYN);
  int len;
  char *res;
  struct sockaddr_in6 soca;
  struct timeval rtt_tv = timeval (*rtt);

  bzero (&soca, sizeof (soca));
  soca.sin6_family = AF_INET6;
  memcpy (&soca.sin6_addr, dst, sizeof (struct in6_addr));
  rtt_tv.tv_sec *= 1000;
  rtt_tv.tv_sec /= 8;

  rtt_tv.tv_usec += (rtt_tv.tv_sec % 1000) * 1000;
  rtt_tv.tv_sec /= 1000;
  if (rtt_tv.tv_sec >= 1)
    {
      rtt_tv.tv_sec = 1;
      rtt_tv.tv_usec = 0;
    }

  if (dport != 0)
    {
      int e;
      packets = add_packet (packets, dport, ack);
      e = sendto (soc, pkt, sizeof (struct tcphdr), 0,
                  (struct sockaddr *) &soca, sizeof (soca));
      if (e < 0)
        {
          g_message ("sendto error in v6_sendpacket");
          perror ("sendto ");
          close (soc);
          bpf_close (bpf);
          return NULL;
        }
    }
  if (sniff != 0)
    {
      res = (char *) bpf_next (bpf, &len);
      if (res != NULL)
        {
          unsigned short sport = extractsport (res + skip, len, AF_INET6);
          int synack = issynack (res + skip, len, AF_INET6);
          if (synack)
            {
              char *rst;
              scanner_add_port (env, sport, "tcp");
              /* Send a RST to make sure the connection is closed on the remote
               * side */
              rst = mktcpv6 (magic, sport, ack + 1, TH_RST);
              if (sendto (soc, rst, sizeof (struct tcphdr), 0,
                          (struct sockaddr *) &soca, sizeof (soca))
                  < 0)
                {
                  perror ("sendto ");
                  close (soc);
                  bpf_close (bpf);
                  return NULL;
                }
            }
          packets = rm_packet (packets, sport);
        }
    }
  return packets;
}

/**
 * @return -1 if the socket could not be opened (error), 0 otherwise.
 */
static int
scan (struct script_infos *env, char *portrange, struct in6_addr *dst6,
      unsigned long rtt)
{
  int num;
  int soc;
  int bpf;
  struct in_addr src;
  struct in_addr dst;
  struct in6_addr src6;
  int magic = 4441 + (rand () % 1200);
  int skip;
  int i;
  struct list *packets = NULL;
  int retry;
  unsigned short *ports;
  int family;

  dst.s_addr = 0;

  if (IN6_IS_ADDR_V4MAPPED (dst6))
    {
      family = AF_INET;
      dst.s_addr = dst6->s6_addr32[3];
      soc = rawsocket (AF_INET);
    }
  else
    {
      family = AF_INET6;
      soc = rawsocket (AF_INET6);
    }

  ports = (unsigned short *) getpts (portrange, &num);

  if (soc < 0)
    {
      printf ("error opening raw socket\n");
      return -1;
    }

  if (family == AF_INET)
    bpf = openbpf (dst, &src, magic);
  else
    bpf = v6_openbpf (dst6, &src6, magic);
  if (bpf < 0)
    {
      close (soc);
      return -1;
    }
  skip = get_datalink_size (bpf_datalink (bpf));

  /** This will send packets to ports not in ports list, will it? */
  for (i = 0; i < num; i += 2)
    {
      if (family == AF_INET)
        packets = sendpacket (soc, bpf, skip, dst, src, ports[i], magic,
                              packets, &rtt, 0, env);
      else
        packets = v6_sendpacket (soc, bpf, skip, dst6, ports[i], magic, packets,
                                 &rtt, 0, env);
      if (i + 1 < num)
        {
          g_debug ("=====>> Sniffing %u\n", ports[i + 1]);
          if (family == AF_INET)
            packets = sendpacket (soc, bpf, skip, dst, src, ports[i + 1], magic,
                                  packets, &rtt, 1, env);
          else
            packets = v6_sendpacket (soc, bpf, skip, dst6, ports[i + 1], magic,
                                     packets, &rtt, 1, env);
        }
    }

  /** @TODO How to do this for ipv6? This causes much scan delay for IPv6. */
  if (family == AF_INET)
    {
      while (packets != NULL)
        {
          i = 0;
          retry = 0;
          packets = rm_dead_packets (packets, &retry);
          while (retry != 0 && i < 2)
            {
              packets = sendpacket (soc, bpf, skip, dst, src, retry, magic,
                                    packets, &rtt, 0, env);
              packets = rm_dead_packets (packets, &retry);
              i++;
            }
          packets = sendpacket (soc, bpf, skip, dst, src, retry, magic, packets,
                                &rtt, 1, env);
        }
    }

  close (soc);
  bpf_close (bpf);
  if (ports != NULL)
    g_free (ports);
  if (num >= 65535)
    plug_set_key (env, "Host/full_scan", ARG_INT, (void *) 1);

  return 0;
}

tree_cell *
plugin_run_synscan (lex_ctxt *lexic)
{
  struct script_infos *env = lexic->script_infos;
  unsigned long rtt;
  struct in6_addr *dst6 = plug_get_host_ip (env);
  struct in_addr *dst;
  struct in_addr inaddr;

  inaddr.s_addr = dst6->s6_addr32[3];
  dst = &inaddr;

  if (islocalhost (dst))
    return NULL;

  rtt = htonl (1 << 28);

  const char *range = prefs_get ("port_range");
  scan (env, (char *) range, dst6, rtt);
  plug_set_key (env, "Host/scanned", ARG_INT, (void *) 1);
  plug_set_key (env, "Host/scanners/synscan", ARG_INT, (void *) 1);
  return NULL;
}
