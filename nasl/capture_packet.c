/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
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

#include <arpa/inet.h>          /* for inet_ntoa */
#include <string.h>             /* for bcopy */
#include <glib.h>               /* for gfree */
#include "../misc/bpf_share.h"          /* for bpf_datalink */
#include "../misc/pcap_openvas.h"       /* for get_datalink_size */

#include <pcap.h>

#include "capture_packet.h"
#include <netinet/ip.h>

#include <sys/param.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif

extern int islocalhost (struct in_addr *);


/**
 * @brief Set up the pcap filter, and select the correct interface.
 *
 * The filter will be changed only if this is necessary
 *
 */
int
init_capture_device (struct in_addr src, struct in_addr dst, char *filter)
{
  int ret = -1;
  char *interface = NULL;
  char *a_dst, *a_src;
  char errbuf[PCAP_ERRBUF_SIZE];
  int free_filter = 0;

  a_src = g_strdup (inet_ntoa (src));
  a_dst = g_strdup (inet_ntoa (dst));

  if ((filter == NULL) || (filter[0] == '\0') || (filter[0] == '0'))
    {
      filter = g_malloc0 (256);
      free_filter = 1;
      if (islocalhost (&src) == 0)
        snprintf (filter, 256, "ip and (src host %s and dst host %s)",
                  a_src, a_dst);

    }
  else
    {
      if (islocalhost (&src) == 0)
        filter = g_strdup (filter);
      else
        filter = g_malloc0 (1);
      free_filter = 1;
    }

  g_free (a_dst);
  g_free (a_src);

  if ((interface = routethrough (&src, &dst))
      || (interface = pcap_lookupdev (errbuf)))
    ret = bpf_open_live (interface, filter);


  if (free_filter != 0)
    g_free (filter);

  return ret;
}

struct ip *
capture_next_packet (int bpf, int timeout, int *sz)
{
  int len;
  int dl_len;
  char *packet = NULL;
  char *ret = NULL;
  struct timeval past, now, then;
  struct timezone tz;

  if (bpf < 0)
    return NULL;

  dl_len = get_datalink_size (bpf_datalink (bpf));
  bzero (&past, sizeof (past));
  bzero (&now, sizeof (now));
  gettimeofday (&then, &tz);
  for (;;)
    {
      bcopy (&then, &past, sizeof (then));
      packet = (char *) bpf_next (bpf, &len);
      if (packet != NULL)
        break;
      gettimeofday (&now, &tz);

      if (now.tv_usec < past.tv_usec)
        {
          past.tv_sec++;
          now.tv_usec += 1000000;
        }

      if (timeout > 0)
        {
          if ((now.tv_sec - past.tv_sec) >= timeout)
            break;
        }
      else
        break;
    }


  if (packet != NULL)
    {
      struct ip *ip;
      ip = (struct ip *) (packet + dl_len);
#ifdef BSD_BYTE_ORDERING
      ip->ip_len = ntohs (ip->ip_len);
      ip->ip_off = ntohs (ip->ip_off);
#endif
      ip->ip_id = ntohs (ip->ip_id);
      ret = g_malloc0 (len - dl_len);
      bcopy (ip, ret, len - dl_len);
      if (sz != NULL)
        *sz = len - dl_len;
    }
  return ((struct ip *) ret);
}


int
init_v6_capture_device (struct in6_addr src, struct in6_addr dst, char *filter)
{
  int ret = -1;
  char *interface = NULL;
  char *a_dst, *a_src;
  int free_filter = 0;
  char name[INET6_ADDRSTRLEN];
  char errbuf[PCAP_ERRBUF_SIZE];

  a_src = g_strdup (inet_ntop (AF_INET6, &src, name, INET6_ADDRSTRLEN));
  a_dst = g_strdup (inet_ntop (AF_INET6, &dst, name, INET6_ADDRSTRLEN));

  if ((filter == NULL) || (filter[0] == '\0') || (filter[0] == '0'))
    {
      filter = g_malloc0 (256);
      free_filter = 1;
      if (v6_islocalhost (&src) == 0)
        snprintf (filter, 256, "ip and (src host %s and dst host %s", a_src,
                  a_dst);
    }
  else
    {
      if (v6_islocalhost (&src) == 0)
        filter = g_strdup (filter);
      else
        filter = g_malloc0 (1);
      free_filter = 1;
    }

  g_free (a_dst);
  g_free (a_src);

  if ((interface = v6_routethrough (&src, &dst))
      || (interface = pcap_lookupdev (errbuf)))
    ret = bpf_open_live (interface, filter);

  if (free_filter != 0)
    g_free (filter);

  return ret;
}


struct ip6_hdr *
capture_next_v6_packet (int bpf, int timeout, int *sz)
{
  int len;
  int dl_len;
  char *packet = NULL;
  char *ret = NULL;
  struct timeval past, now, then;
  struct timezone tz;

  if (bpf < 0)
    return NULL;

  dl_len = get_datalink_size (bpf_datalink (bpf));
  bzero (&past, sizeof (past));
  bzero (&now, sizeof (now));
  gettimeofday (&then, &tz);

  for (;;)
    {
      bcopy (&then, &past, sizeof (then));
      packet = (char *) bpf_next (bpf, &len);

      if (packet != NULL)
        break;

      gettimeofday (&now, &tz);
      if (now.tv_usec < past.tv_usec)
        {
          past.tv_sec++;
          now.tv_usec += 1000000;
        }

      if (timeout > 0)
        {
          if ((now.tv_sec - past.tv_sec) >= timeout)
            break;
        }
      else
        break;
    }

  if (packet != NULL)
    {
      struct ip6_hdr *ip6;
      ip6 = (struct ip6_hdr *) (packet + dl_len);
#ifdef BSD_BYTE_ORDERING
      ip6->ip6_plen = ntohs (ip6->ip6_plen);
#endif
      ret = g_malloc0 (len - dl_len);
      bcopy (ip6, ret, len - dl_len);
      if (sz != NULL)
        *sz = len - dl_len;
    }

  return ((struct ip6_hdr *) ret);
}
