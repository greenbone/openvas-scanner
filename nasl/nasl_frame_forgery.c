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
#include "../misc/pcap_openvas.h"
#include "../misc/pcap_openvas.h" /* for get_iface_from_ip */
#include "../misc/plugutils.h"
#include "capture_packet.h"
#include "nasl_debug.h"

#include <gvm/base/networking.h>
#include <libnet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

struct pseudo_frame
{
  struct ethhdr framehdr;
  u_char *payload;
  int payload_sz;
} __attribute__ ((packed));

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
  int dl_layer_only = 0;

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
        answer = (struct ether_header *) capture_next_frame (
          bpf, to, &answer_sz, dl_layer_only);

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

/*----------------------------------------------------------------------------*/

/** @brief Prepare message header to be sent with sendmsg().
 *
 * @param[out] soc_addr_ll The sockaddr_ll structure to be prepared
 * @param[in] ifindex The interface index to be use for capturing.
 * @param[in] ether_dst_addr The dst MAC address.
 */
static void
prepare_sockaddr_ll (struct sockaddr_ll *soc_addr_ll, int ifindex,
                     const unsigned char *ether_dst_addr)
{
  //  const unsigned char ether_dst_addr[]=
  //    {0x54,0xe1,0xad,0xd4,0xed,0x74};

  soc_addr_ll->sll_family = AF_PACKET;
  soc_addr_ll->sll_ifindex = ifindex;
  soc_addr_ll->sll_halen = ETHER_ADDR_LEN;
  soc_addr_ll->sll_protocol = htons (ETH_P_ALL);
  memcpy (soc_addr_ll->sll_addr, ether_dst_addr, ETHER_ADDR_LEN);
}

/** @brief Prepare message header to be sent with sendmsg().
 *
 * @param[out] message The packaged messages to be sent
 * @param[in] soc_addr_ll The sockaddr_ll structure for capturing
 * @param[in] payload The payload, a datalink layer frame with payload
 * @param[in] payload_sz The payload size.
 */
static void
prepare_message (struct msghdr *message, struct sockaddr_ll *soc_addr_ll,
                 u_char *payload, int payload_sz)
{
  struct iovec iov[1];
  iov[0].iov_base = payload;
  iov[0].iov_len = payload_sz;

  message->msg_name = soc_addr_ll;
  message->msg_namelen = sizeof (struct sockaddr_ll);
  message->msg_iov = iov;
  message->msg_iovlen = 1;
  message->msg_control = 0;
  message->msg_controllen = 0;
}

/** @brief Forge a datalink layer frame
 *
 * @naslparams
 *
 * - @n src_haddr     Source MAC address to use.
 * - @n dst_haddr     Destination MAC address to use.
 * - @n ether_proto   Ethernet type integer in hex format. Default 0x0800
 * (ETHER_P_IP)
 * - @n payload       Payload to be attached to the frame. E.g a forged tcp
 * datagram.
 *
 * - @naslreturn the forged frame.
 *
 * @param lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell element or null.
 */
tree_cell *
nasl_forge_frame (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct pseudo_frame *frame;
  u_char *payload = (u_char *) get_str_var_by_name (lexic, "payload");
  int payload_sz = get_var_size_by_name (lexic, "payload");
  int frame_sz;
  char *ether_src_addr = get_str_var_by_name (lexic, "src_haddr");
  char *ether_dst_addr = get_str_var_by_name (lexic, "dst_haddr");
  int ether_proto = get_int_var_by_name (lexic, "ether_proto", 0x0800);

  frame = (struct pseudo_frame *) g_malloc0 (sizeof (struct pseudo_frame)
                                             + payload_sz);
  memcpy (frame->framehdr.h_dest, ether_dst_addr, ETHER_ADDR_LEN);
  memcpy (frame->framehdr.h_source, ether_src_addr, ETHER_ADDR_LEN);
  frame->framehdr.h_proto = htons (ether_proto);
  frame->payload = payload;

  frame_sz = ETH_HLEN + payload_sz;
  memcpy ((char *) frame + ETH_HLEN, payload, payload_sz);

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = (char *) frame;
  retc->size = frame_sz;
  return retc;
}

/** @brief Send a frame and listen to the answer
 *
 * @naslparams
 *
 * - @n frame The frame to be sent.
 * - @n pcap_active     TRUE by default. Otherwise, NASL does not listen
 * for the answers.
 * - @n pcap_filter     BPF filter.
 * - @n pcap_timeout    Capture timeout. 5 by default.
 *
 * - @naslreturn Sniffed answer.
 *
 * @param lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell element or null.
 */
tree_cell *
nasl_send_frame (lex_ctxt *lexic)
{
  int soc;
  tree_cell *retc = FAKE_CELL;
  struct msghdr message;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *ipaddr = plug_get_host_ip (script_infos);
  u_char *frame = (u_char *) get_str_var_by_name (lexic, "frame");
  int frame_sz = get_var_size_by_name (lexic, "frame");
  int use_pcap = get_int_var_by_name (lexic, "pcap_active", 1);
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  int ifindex;
  u_char *answer = NULL;
  int answer_sz = 0;
  int bpf = -1;
  int frame_and_payload = 0;

  // Create the raw socket
  soc = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (soc == -1)
    {
      nasl_perror (lexic, "%s: %s", __func__, strerror (errno));
      return NULL;
    }

  // We will need the eth index. We get it depending on the target's IP..
  if (get_iface_index (ipaddr, &ifindex) < 0)
    {
      nasl_perror (lexic, "%s: Missing interface index\n", __func__);
      return NULL;
    }

  // Preapre sockaddr_ll. This is necessary for further captures
  unsigned char dst_haddr[ETHER_ADDR_LEN];
  memcpy (&dst_haddr, (struct pseudo_frame *) frame, ETHER_ADDR_LEN);

  struct sockaddr_ll soc_addr;
  memset (&soc_addr, '\0', sizeof (struct sockaddr_ll));
  prepare_sockaddr_ll (&soc_addr, ifindex, dst_haddr);

  /* Init capture */
  if (use_pcap != 0 && bpf < 0)
    {
      struct in_addr sin, this_host;
      memset (&sin, '\0', sizeof (struct in_addr));
      memset (&this_host, '\0', sizeof (struct in_addr));
      if (IN6_IS_ADDR_V4MAPPED (ipaddr))
        {
          sin.s_addr = ipaddr->s6_addr32[3];
          bpf = init_capture_device (sin, this_host, filter);
        }
      else
        nasl_perror (
          lexic, "%s: Error. Only IPv4 is supported for starting a capture.",
          __func__);
    }

  // Prepare the message and send it
  memset (&message, '\0', sizeof (struct msghdr));
  prepare_message (&message, &soc_addr, (u_char *) frame, frame_sz);

  int b = sendmsg (soc, &message, 0);
  if (b == -1)
    nasl_perror (lexic, "%s: Error sending message: %s", __func__,
                 strerror (errno));

  if (bpf >= 0)
    answer =
      (u_char *) capture_next_frame (bpf, to, &answer_sz, frame_and_payload);

  if (answer)
    {
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) answer;
      retc->size = answer_sz;
    }

  if (bpf >= 0)
    bpf_close (bpf);
  close (soc);

  return retc;
}

/** @brief Dump a datalink layer frame
 *
 * @naslparam
 *
 * - @n frame The frame to be dumped.
 *
 * @param lexic Lexical context of NASL interpreter.
 *
 * @return Null
 */
tree_cell *
nasl_dump_frame (lex_ctxt *lexic)
{
  u_char *frame = (u_char *) get_str_var_by_name (lexic, "frame");
  int frame_sz = get_var_size_by_name (lexic, "frame");
  int f = 0;

  if (frame_sz == 0)
    return NULL;

  printf ("\nThe Frame:\n");
  while (f < frame_sz)
    {
      printf ("%02x%02x ", ((u_char *) frame)[f], ((u_char *) frame)[f + 1]);
      f += 2;
      if (f % 16 == 0)
        printf ("\n");
    }
  printf ("\n\n");

  return NULL;
}
