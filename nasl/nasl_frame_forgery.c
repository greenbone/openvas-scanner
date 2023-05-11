/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <errno.h>
#include <gvm/base/networking.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

struct pseudo_eth_arp
{
  struct arphdr arp_header;
  u_char __ar_sha[ETH_ALEN]; /* Sender hardware address.  */
  u_char __ar_sip[4];        /* Sender IP address.  */
  u_char __ar_tha[ETH_ALEN]; /* Target hardware address.  */
  u_char __ar_tip[4];        /* Target IP address.  */
  u_char __zero_padding[18];
} __attribute__ ((packed));

struct pseudo_frame
{
  struct ethhdr framehdr;
  u_char *payload;
} __attribute__ ((packed));

/** @brief Dump a datalink layer frame
 *
 * @param frame    The frame to be dumped.
 * @param frame_sz The frame's size.
 *
 */
static void
dump_frame (const u_char *frame, int frame_sz)
{
  int f = 0;

  printf ("\nThe Frame:\n");
  while (f < frame_sz)
    {
      printf ("%02x%02x ", ((u_char *) frame)[f], ((u_char *) frame)[f + 1]);
      f += 2;
      if (f % 16 == 0)
        printf ("\n");
    }
  printf ("\n\n");
}

/** @brief Prepare message header to be sent with sendmsg().
 *
 * @param[out] soc_addr_ll The sockaddr_ll structure to be prepared
 * @param[in] ifindex The interface index to be use for capturing.
 * @param[in] ether_dst_addr The dst MAC address.
 */
static void
prepare_sockaddr_ll (struct sockaddr_ll *soc_addr_ll, int ifindex,
                     const u_char *ether_dst_addr)
{
  soc_addr_ll->sll_family = AF_PACKET;
  soc_addr_ll->sll_ifindex = ifindex;
  soc_addr_ll->sll_halen = ETHER_ADDR_LEN;
  soc_addr_ll->sll_protocol = htons (ETH_P_ALL);
  memcpy (soc_addr_ll->sll_addr, ether_dst_addr, ETHER_ADDR_LEN);
}

/** @brief Prepare message header to be sent with sendmsg().
 *
 * @param[out] msg The packaged messages to be sent
 * @param[in] soc_addr_ll The sockaddr_ll structure for capturing
 * @param[in] payload The payload, a datalink layer frame with payload
 * @param[in] payload_sz The payload size.
 */
static void
prepare_message (u_char *msg, struct sockaddr_ll *soc_addr_ll, u_char *payload,
                 int payload_sz)
{
  struct iovec iov;
  struct msghdr *message;

  iov.iov_base = payload;
  iov.iov_len = payload_sz;

  message = g_malloc0 (sizeof (struct msghdr) + payload_sz);

  message->msg_name = soc_addr_ll;
  message->msg_namelen = sizeof (struct sockaddr_ll);
  message->msg_iov = &iov;
  message->msg_iovlen = 1;
  message->msg_control = 0;
  message->msg_controllen = 0;

  memcpy (msg, (u_char *) message, sizeof (struct msghdr) + payload_sz);
  g_free (message);
}

/** @brief Send a frame and listen to the answer
 *
 * @param[in]frame         The frame to be sent.
 * @param[in]frame_sz      The frame's size.
 * @param[in]pcap_active   TRUE by default. Otherwise, NASL does not listen
 *                         for the answers.
 * @param[in]pcap_filter   BPF filter.
 * @param[in]pcap_timeout  Capture timeout. 5 by default.
 * @param[in]ipaddr        Destination address, used for calculating the
 *                         ethernet index
 * @param[out]answer       Sniffed answer.
 *
 * @return Bits received in the answer or 0 on success, -1 if no answer, -2
 * error sending the message.
 */
static int
send_frame (const u_char *frame, int frame_sz, int use_pcap, int timeout,
            char *filter, struct in6_addr *ipaddr, u_char **answer)
{
  int soc;
  u_char *message;
  int ifindex;
  int bpf = -1;
  int frame_and_payload = 0;
  int answer_sz = -1;

  // Create the raw socket
  soc = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (soc == -1)
    {
      g_debug ("%s: %s", __func__, strerror (errno));
      return -1;
    }

  // We will need the eth index. We get it depending on the target's IP..
  if (get_iface_index (ipaddr, &ifindex) < 0)
    {
      g_message ("%s: Missing interface index\n", __func__);
      return -1;
    }

  // Prepare sockaddr_ll. This is necessary for further captures
  u_char dst_haddr[ETHER_ADDR_LEN];
  memcpy (&dst_haddr, (struct pseudo_frame *) frame, ETHER_ADDR_LEN);

  struct sockaddr_ll soc_addr;
  memset (&soc_addr, '\0', sizeof (struct sockaddr_ll));
  prepare_sockaddr_ll (&soc_addr, ifindex, dst_haddr);

  /* Init capture */
  if (use_pcap != 0 && bpf < 0)
    {
      if (IN6_IS_ADDR_V4MAPPED (ipaddr))
        {
          struct in_addr sin, this_host;
          memset (&sin, '\0', sizeof (struct in_addr));
          memset (&this_host, '\0', sizeof (struct in_addr));
          sin.s_addr = ipaddr->s6_addr32[3];
          bpf = init_capture_device (sin, this_host, filter);
        }
      else
        {
          struct in6_addr this_host;
          memset (&this_host, '\0', sizeof (struct in6_addr));
          bpf = init_v6_capture_device (*ipaddr, this_host, filter);
        }
    }

  // Prepare the message and send it
  message = g_malloc0 (sizeof (struct msghdr) + frame_sz);
  prepare_message (message, &soc_addr, (u_char *) frame, frame_sz);

  int b = sendmsg (soc, (struct msghdr *) message, 0);
  g_free (message);
  if (b == -1)
    {
      g_message ("%s: Error sending message: %s", __func__, strerror (errno));
      return -2;
    }
  if (bpf >= 0)
    {
      *answer = (u_char *) capture_next_frame (bpf, timeout, &answer_sz,
                                               frame_and_payload);
      bpf_close (bpf);
      close (soc);
      return answer_sz;
    }

  close (soc);
  return 0;
}

/** @brief Forge a datalink layer frame
 *
 * @param[in] src_haddr     Source MAC address to use.
 * @param[in] dst_haddr     Destination MAC address to use.
 * @param[in] ether_proto   Ethernet type integer in hex format. Default 0x0800
 * (ETHER_P_IP)
 * @param[in] payload       Payload to be attached to the frame. E.g a forged
 * tcp datagram, or arp header
 * @param[out] frame the forge frame
 *
 * @return the forged frame size.
 */
static int
forge_frame (const u_char *ether_src_addr, const u_char *ether_dst_addr,
             int ether_proto, u_char *payload, int payload_sz,
             struct pseudo_frame **frame)
{
  int frame_sz;

  *frame = (struct pseudo_frame *) g_malloc0 (sizeof (struct pseudo_frame)
                                              + payload_sz);

  memcpy ((*frame)->framehdr.h_dest, ether_dst_addr, ETHER_ADDR_LEN);
  memcpy ((*frame)->framehdr.h_source, ether_src_addr, ETHER_ADDR_LEN);
  (*frame)->framehdr.h_proto = htons (ether_proto);
  (*frame)->payload = payload;

  frame_sz = ETH_HLEN + payload_sz;
  memcpy ((char *) *frame + ETH_HLEN, payload, payload_sz);

  return frame_sz;
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
  int frame_sz;
  u_char *payload = (u_char *) get_str_var_by_name (lexic, "payload");
  int payload_sz = get_var_size_by_name (lexic, "payload");
  char *ether_src_addr = get_str_var_by_name (lexic, "src_haddr");
  char *ether_dst_addr = get_str_var_by_name (lexic, "dst_haddr");
  int ether_proto = get_int_var_by_name (lexic, "ether_proto", 0x0800);

  if (ether_src_addr == NULL || ether_dst_addr == NULL || payload == NULL)
    {
      nasl_perror (lexic,
                   "%s usage: payload, src_haddr and dst_haddr are mandatory "
                   "parameters.\n",
                   __func__);
      return NULL;
    }

  frame_sz = forge_frame ((u_char *) ether_src_addr, (u_char *) ether_dst_addr,
                          ether_proto, payload, payload_sz, &frame);

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
  tree_cell *retc = NULL;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *ipaddr = plug_get_host_ip (script_infos);
  u_char *frame = (u_char *) get_str_var_by_name (lexic, "frame");
  int frame_sz = get_var_size_by_name (lexic, "frame");
  int use_pcap = get_int_var_by_name (lexic, "pcap_active", 1);
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  u_char *answer = NULL;
  int answer_sz;

  if (frame == NULL || frame_sz <= 0)
    {
      nasl_perror (lexic, "%s usage: frame is a mandatory parameters.\n",
                   __func__);
      return NULL;
    }

  answer_sz =
    send_frame (frame, frame_sz, use_pcap, to, filter, ipaddr, &answer);
  if (answer_sz == -2)
    {
      g_message ("%s: Not possible to send the frame", __func__);
      return NULL;
    }

  if (answer && answer_sz > -1)
    {
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) answer;
      retc->size = answer_sz;
    }

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

  if (frame == NULL || frame_sz <= 0)
    {
      nasl_perror (lexic, "%s usage: frame is a mandatory parameters.\n",
                   __func__);
      return NULL;
    }

  dump_frame (frame, frame_sz);
  return NULL;
}

/**
 * @brief Get the MAC address of host
 *
 * @param[in] ip_address    Local IP address
 * @param[out] mac          The MAC address
 *
 * @return 0 on success. MAC address is put into buffer. -1 on error.

 */
static int
get_local_mac_address_from_ip (char *ip_address, u_char *mac)
{
  struct ifreq ifr;
  int sock;
  char *if_name = NULL;

  if_name = get_iface_from_ip (ip_address);
  if (!if_name)
    {
      g_debug ("%s: Missing interface name", __func__);
      return -1;
    }

  strncpy (ifr.ifr_name, if_name, sizeof (ifr.ifr_name) - 1);
  g_free (if_name);
  ifr.ifr_name[sizeof (ifr.ifr_name) - 1] = '\0';

  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (-1 == sock)
    {
      perror ("socket() ");
      return -1;
    }

  if (-1 == ioctl (sock, SIOCGIFHWADDR, &ifr))
    {
      g_debug ("%s: ioctl(SIOCGIFHWADDR)", __func__);
      return -1;
    }

  memcpy (mac, (u_char *) ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  close (sock);

  return 0;
}

/**
 * @brief Get the MAC address of host
 *
 * @naslparam
 *
 * - @a ip_address    Local IP address
 *
 *  @naslreturn The MAC address of the host. NULL otherwise
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 *
 **/
tree_cell *
nasl_get_local_mac_address_from_ip (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  char *buffer = NULL;
  u_char *mac;

  char *ip_address = get_str_var_by_num (lexic, 0);

  mac = g_malloc0 (sizeof (u_char) * ETHER_ADDR_LEN);
  get_local_mac_address_from_ip (ip_address, mac);
  if (mac != NULL)
    {
      buffer = g_strdup_printf ("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
                                mac[2], mac[3], mac[4], mac[5]);
      g_free (mac);
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = buffer;
      retc->size = 17;
    }

  return retc;
}

/**
 * @brief Send an arp request to an IP host.
 *
 * @naslret The MAC address of the target. NULL otherwise
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 *
 * @return A tree cell or NULL.
 */
tree_cell *
nasl_send_arp_request (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct in6_addr src, *dst = plug_get_host_ip (lexic->script_infos);
  struct in_addr dst_inaddr, src_inaddr;
  struct pseudo_eth_arp eth_arp;
  struct pseudo_frame *frame;
  int frame_sz;
  char ip_src_str[INET6_ADDRSTRLEN];
  u_char mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_char mac[6], *mac_aux;
  char filter[255];
  u_char *answer = NULL;
  int answer_sz;
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);

  /* Get source IP address via routethrough. We need it to find our mac address.
   */
  if (dst == NULL || (IN6_IS_ADDR_V4MAPPED (dst) != 1))
    return retc;

  memset (&dst_inaddr, '\0', sizeof (struct in_addr));
  dst_inaddr.s_addr = dst->s6_addr32[3];
  routethrough (&dst_inaddr, &src_inaddr);
  ipv4_as_ipv6 (&src_inaddr, &src);

  /* Getting target IP address  as string, to get the mac address */
  addr6_to_str (&src, ip_src_str);

  mac_aux = (u_char *) g_malloc0 (sizeof (u_char) * 6);
  get_local_mac_address_from_ip (ip_src_str, mac_aux);
  mac[0] = mac_aux[0];
  mac[1] = mac_aux[1];
  mac[2] = mac_aux[2];
  mac[3] = mac_aux[3];
  mac[4] = mac_aux[4];
  mac[5] = mac_aux[5];
  g_free (mac_aux);

  /* Building ARP header */
  memset (&eth_arp, '\0', sizeof (struct pseudo_eth_arp));
  eth_arp.arp_header.ar_hrd = htons (ARPHRD_ETHER);
  eth_arp.arp_header.ar_pro = htons (ETHERTYPE_IP);
  eth_arp.arp_header.ar_hln = ETH_ALEN;
  eth_arp.arp_header.ar_pln = 4;
  eth_arp.arp_header.ar_op = htons (ARPOP_REQUEST);

  memcpy (&(eth_arp.__ar_sha), mac, ETH_ALEN);
  memcpy (&(eth_arp.__ar_sip), &src_inaddr, 4);
  memcpy (&(eth_arp.__ar_tha), mac_broadcast_addr, ETH_ALEN);
  memcpy (&(eth_arp.__ar_tip), &dst_inaddr, 4);

  frame_sz =
    forge_frame (mac, mac_broadcast_addr, ETH_P_ARP, (u_char *) &eth_arp,
                 sizeof (struct pseudo_eth_arp), &frame);

  /* Prepare filter */
  snprintf (filter, sizeof (filter), "arp and src host %s",
            inet_ntoa (dst_inaddr));

  answer_sz =
    send_frame ((const u_char *) frame, frame_sz, 1, to, filter, dst, &answer);
  g_free (frame);
  if (answer_sz == -2)
    {
      g_message ("%s: Not possible to send the frame", __func__);
      return NULL;
    }

  if (answer && answer_sz > -1)
    {
      char *daddr;
      struct ether_header *answer_aux;

      answer_aux = (struct ether_header *) answer;
      daddr = g_strdup_printf (
        "%02x:%02x:%02x:%02x:%02x:%02x", (u_int) answer_aux->ether_shost[0],
        (u_int) answer_aux->ether_shost[1], (u_int) answer_aux->ether_shost[2],
        (u_int) answer_aux->ether_shost[3], (u_int) answer_aux->ether_shost[4],
        (u_int) answer_aux->ether_shost[5]);

      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = daddr;
      retc->size = strlen (daddr);
    }
  else
    g_debug ("%s: No answer received.", __func__);

  return retc;
}
