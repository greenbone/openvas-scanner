/* Copyright (C) 2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file nasl_frame_forgery.c
 * @brief Functions to forge and manipulate datalink layer frames.
 */

#include "nasl_frame_forgery.h"

#include "../misc/bpf_share.h" /* for bpf_open_live */
#include "../misc/plugutils.h"
#include "capture_packet.h"

#include <gvm/base/networking.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/**
 * @brief Send an arp request to an IP host.
 *
 * @naslnparam
 *
 * - @a host    Target's IPv4 address
 *
 * @naslret The MAC address of the host. NULL otherwise
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 *
 * @return A tree cell or NULL.
 */
tree_cell *
nasl_send_arp_request (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct in6_addr *dst = plug_get_host_ip (lexic->script_infos);
  struct in_addr inaddr;
  char ip_str[INET6_ADDRSTRLEN];
  libnet_t *l; /* the libnet context */
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_int32_t target_ip_addr, src_ip_addr;
  u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
  struct libnet_ether_addr *src_mac_addr;
  int bytes_written, bpf = -1;
  char filter[255];
  struct ether_header *answer;
  int answer_sz;
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);

  l = libnet_init (LIBNET_LINK, NULL, errbuf);
  if (l == NULL)
    {
      g_message ("%s: libnet_init() failed: %s\n", __func__, errbuf);
      return retc;
    }

  /* Getting our own MAC and IP addresses */

  src_ip_addr = libnet_get_ipaddr4 (l);
  if (src_ip_addr == (u_int32_t) -1)
    {
      g_message ("%s: Couldn't get own IP address: %s\n", __func__,
                 libnet_geterror (l));
      libnet_destroy (l);
      return NULL;
    }

  src_mac_addr = libnet_get_hwaddr (l);
  if (src_mac_addr == NULL)
    {
      g_message ("%s: Couldn't get own IP address: %s\n", __func__,
                 libnet_geterror (l));
      libnet_destroy (l);
      return NULL;
    }

  /* Getting target IP address */
  if (dst == NULL || (IN6_IS_ADDR_V4MAPPED (dst) != 1))
    return retc;
  inaddr.s_addr = dst->s6_addr32[3];
  addr6_to_str (dst, ip_str);
  target_ip_addr = libnet_name2addr4 (l, ip_str, LIBNET_DONT_RESOLVE);

  if (target_ip_addr == (u_int32_t) -1)
    {
      g_message ("%s: Error converting IP address.\n", __func__);
      libnet_destroy (l);
      return retc;
    }

  /* Building ARP header */

  if (libnet_autobuild_arp (ARPOP_REQUEST, src_mac_addr->ether_addr_octet,
                            (u_int8_t *) (&src_ip_addr), mac_zero_addr,
                            (u_int8_t *) (&target_ip_addr), l)
      == -1)
    {
      g_message ("%s: Error building ARP header: %s\n", __func__,
                 libnet_geterror (l));
      libnet_destroy (l);
      return retc;
    }

  /* Building Ethernet header */

  if (libnet_autobuild_ethernet (mac_broadcast_addr, ETHERTYPE_ARP, l) == -1)
    {
      g_message ("%s: Error building Ethernet header: %s\n", __func__,
                 libnet_geterror (l));
      libnet_destroy (l);
      return retc;
    }

  /* Prepare filter and init capture */
  snprintf (filter, sizeof (filter), "arp and src host %s", inet_ntoa (inaddr));
  bpf = init_capture_device (inaddr, inaddr, filter);

  /* Writing packet */
  bytes_written = libnet_write (l);
  if (bytes_written != -1)
    {
      if (bpf >= 0)
        answer = capture_next_frame (bpf, to, &answer_sz);

      if (answer)
        {
          char *daddr;
          daddr = g_strdup_printf ("%02x:%02x:%02x:%02x:%02x:%02x",
                                   (unsigned int) answer->ether_shost[0],
                                   (unsigned int) answer->ether_shost[1],
                                   (unsigned int) answer->ether_shost[2],
                                   (unsigned int) answer->ether_shost[3],
                                   (unsigned int) answer->ether_shost[4],
                                   (unsigned int) answer->ether_shost[5]);
          retc = alloc_typed_cell (CONST_DATA);
          retc = alloc_typed_cell (CONST_DATA);
          retc->x.str_val = daddr;
          retc->size = strlen (daddr);
        }
    }
  else
    g_message ("%s: Error writing packet: %s\n", __func__, libnet_geterror (l));

  libnet_destroy (l);
  if (bpf >= 0)
    bpf_close (bpf);

  return retc;
}
