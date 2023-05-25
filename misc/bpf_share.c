/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "bpf_share.h"

#include "../nasl/nasl_debug.h" /* for nasl_*_filename */

#include <gvm/base/logging.h>
#include <pcap.h>

#define NUM_CLIENTS 128

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/** Shared pcap_t's. */
static pcap_t *pcaps[NUM_CLIENTS];

static void
print_pcap_error (pcap_t *p, char *prefix)
{
  char *msg = pcap_geterr (p);
  g_message ("[%s] %s : %s",
             nasl_get_plugin_filename () ? nasl_get_plugin_filename () : "",
             prefix, msg);
}

/**
 * @return -1 in case of error, index of the opened pcap_t in pcaps
 *         otherwise.
 */
int
bpf_open_live (char *iface, char *filter)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ret;
  pcap_if_t *alldevsp = NULL; /* list of capture devices */
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
    {
      if (pcap_findalldevs (&alldevsp, errbuf) < 0)
        g_message ("Error for pcap_findalldevs(): %s", errbuf);
      if (alldevsp != NULL)
        iface = alldevsp->name;
    }

  ret = pcap_open_live (iface, 1500, 0, 1, errbuf);
  if (ret == NULL)
    {
      g_message ("%s", errbuf);
      if (alldevsp != NULL)
        pcap_freealldevs (alldevsp);
      return -1;
    }

  if (pcap_lookupnet (iface, &network, &netmask, errbuf) < 0)
    {
      g_message ("pcap_lookupnet failed: %s", errbuf);
      if (alldevsp != NULL)
        pcap_freealldevs (alldevsp);
      pcap_close (ret);
      return -1;
    }

  if (pcap_compile (ret, &filter_prog, filter, 1, netmask) < 0)
    {
      char buffer[2048];
      snprintf (buffer, sizeof (buffer), "pcap_compile: Filter \"%s\"", filter);
      print_pcap_error (ret, buffer);
      if (alldevsp != NULL)
        pcap_freealldevs (alldevsp);
      pcap_close (ret);
      return -1;
    }

  if (pcap_setnonblock (ret, 1, NULL) == -1)
    {
      print_pcap_error (ret, "pcap_setnonblock");
      g_message ("call to pcap_setnonblock failed, some plugins/scripts will"
                 " hang/freeze. Upgrade your version of libcap!");
    }

  if (pcap_setfilter (ret, &filter_prog) < 0)
    {
      print_pcap_error (ret, "pcap_setfilter\n");
      if (alldevsp != NULL)
        pcap_freealldevs (alldevsp);
      pcap_freecode (&filter_prog);
      pcap_close (ret);
      return -1;
    }
  pcaps[i] = ret;
  pcap_freecode (&filter_prog);
  if (alldevsp != NULL)
    pcap_freealldevs (alldevsp);

  return i;
}

u_char *
bpf_next_tv (int bpf, int *caplen, struct timeval *tv)
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
  while (
    !((now.tv_sec > timeout.tv_sec)
      || (now.tv_sec == timeout.tv_sec && now.tv_usec >= timeout.tv_usec)));

  return p;
}

u_char *
bpf_next (int bpf, int *caplen)
{
  struct timeval tv = {0, 100000};

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
