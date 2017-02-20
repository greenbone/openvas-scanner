/* Copyright (C) 2003 Renaud Deraison
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

/** @todo There once was a BPF sharing feature with the same API
 * as the methods below, but trying to share BPF among the daemon
 * processes. What remains is a thin abstraction of the pcap API.
 * Eventually it needs to be analysed whether this makes sense
 * or can further be simplified. */

#include <pcap.h>

#include <gvm/base/logging.h>

#undef DEBUG
#undef DEBUG_HIGH
#define NUM_CLIENTS 128

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/** Shared pcap_t's. */
static pcap_t *pcaps[NUM_CLIENTS];

/**
 * @return -1 in case of error, index of the opened pcap_t in pcaps
 *         otherwise.
 */
int
bpf_open_live (char *iface, char *filter)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ret;
  bpf_u_int32 netmask, network;
  struct bpf_program filter_prog;
  int i;

  for (i = 0; (i < (NUM_CLIENTS - 1)) && (pcaps[i]); i++)
    ;

  if (pcaps[i])
    {
      g_message ("no free pcap");
      return -1;
    }


  if (iface == NULL)
    iface = pcap_lookupdev (errbuf);

  ret = pcap_open_live (iface, 1500, 0, 1, errbuf);
  if (ret == NULL)
    {
      g_message ("%s", errbuf);
      return -1;
    }

  if (pcap_lookupnet (iface, &network, &netmask, 0) < 0)
    {
      g_message ("pcap_lookupnet failed");
      pcap_close (ret);
      return -1;
    }

  if (pcap_compile (ret, &filter_prog, filter, 1, netmask) < 0)
    {
      pcap_perror (ret, "pcap_compile");
      pcap_close (ret);
      return -1;
    }

  if (pcap_setnonblock (ret, 1, NULL) == -1)
    {
      pcap_perror (ret, "pcap_setnonblock");
      g_message
        ("call to pcap_setnonblock failed, some plugins/scripts will"
         " hang/freeze. Upgrade your version of libcap!");
    }

  if (pcap_setfilter (ret, &filter_prog) < 0)
    {
      pcap_perror (ret, "pcap_setfilter\n");
      pcap_close (ret);
      return -1;
    }
  pcaps[i] = ret;
  pcap_freecode (&filter_prog);
  return i;
}



u_char *
bpf_next_tv (int bpf, int *caplen, struct timeval * tv)
{
  u_char *p = NULL;
  struct pcap_pkthdr head;
  struct timeval timeout, now;

  gettimeofday (&timeout, NULL);
  timeout.tv_sec += tv->tv_sec;
  timeout.tv_usec += tv->tv_usec;
  while (timeout.tv_usec >= 1000000)
    {
      timeout.tv_sec++;
      timeout.tv_usec -= 1000000;
    }

  do
    {
      p = (u_char *) pcap_next (pcaps[bpf], &head);
      *caplen = head.caplen;
      if (p != NULL)
        break;
      gettimeofday (&now, NULL);
    }
  while (!
         ((now.tv_sec > timeout.tv_sec)
          || (now.tv_sec == timeout.tv_sec && now.tv_usec >= timeout.tv_usec)));


  return p;
}


u_char *
bpf_next (int bpf, int *caplen)
{
  struct timeval tv = { 0, 100000 };

  return bpf_next_tv (bpf, caplen, &tv);
}


int
bpf_datalink (int bpf)
{
  return pcap_datalink (pcaps[bpf]);
}


void
bpf_close (int bpf)
{
  pcap_close (pcaps[bpf]);
  pcaps[bpf] = NULL;
}
