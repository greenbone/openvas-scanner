/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_packet_forgery_v6.c
 *
 * @brief NASL IPv6 Packet Forgery functions
 *
 * Provides IPv6 Packet Forgery functionalities
 * The API set offers forgery for,
 * 1. TCP
 * 2. IPv6
 */

/*
 * Modified for IPv6 packet forgery - 04/02/2010
 * Preeti Subramanian <spreeti@secpod.com>
 * Srinivas NL <nl.srinivas@gmail.com>
 *
 * Modified for ICMPv6, IPv6 packet forgery support for IGMP and UDP -
 * 09/02/2010 Preeti Subramanian <spreeti@secpod.com>
 */

#include <arpa/inet.h> /* for inet_aton */
#include <ctype.h>     /* for isprint */
#include <pcap.h>      /* for PCAP_ERRBUF_SIZE */
#include <stdlib.h>    /* for rand */
#include <string.h>    /* for bcopy */
#include <sys/param.h>
#include <sys/time.h> /* for gettimeofday */
#include <unistd.h>   /* for close */
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "../misc/bpf_share.h"    /* for bpf_open_live */
#include "../misc/pcap_openvas.h" /* for routethrough */
#include "../misc/plugutils.h"    /* plug_get_host_ip */
#include "capture_packet.h"
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_packet_forgery_v6.h"
#include "nasl_raw.h"
#include "nasl_socket.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <netinet/icmp6.h> /* ICMPv6 */

/** @todo: It still needs to be taken care
 * BSD_BYTE_ORDERING gets here if defined (e.g. by config.h) */
#ifdef BSD_BYTE_ORDERING
#define FIX(n) (n)
#define UNFIX(n) (n)
#else
#define FIX(n) htons (n)
#define UNFIX(n) ntohs (n)
#endif

/*--------------[ cksum ]-----------------------------------------*/

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 * From ping examples in W.Richard Stevens "UNIX NETWORK PROGRAMMING" book.
 */
static int
np_in_cksum (p, n)
u_short *p;
int n;
{
  register u_short answer = 0;
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

  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = (int) ~sum;                /* ones-complement, truncate */
  return (answer);
}

/*--------------[ IP ]--------------------------------------------*/

/**
 * @brief Forge an IPv6 packet.
 *
 * @param[in] lexic     Lexical context of NASL interpreter.
 * @param[in] data      Data payload
 * @param[in] ip6_v     Version. 6 by default.
 * @param[in] ip6_tc    Traffic class. 0 by default.
 * @param[in] ip6_fl    Flow label. 0 by default.
 * @param[in] ip6_p     IP protocol. 0 by default.
 * @param[in] ip6_hlim  Hop limit. Max. 255. 64 by default.
 * @param[in] ip6_src   Source address.
 * @param[in] ip6_dst   Destination address.
 *
 * @return Forged IP packet.
 */
tree_cell *
forge_ip_v6_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct ip6_hdr *pkt;
  char *s;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dst_addr;
  char *data;
  int data_len;
  int version;
  int tc;
  int fl;

  dst_addr = plug_get_host_ip (script_infos);

  if (dst_addr == NULL || (IN6_IS_ADDR_V4MAPPED (dst_addr) == 1))
    return NULL;

  data = get_str_var_by_name (lexic, "data");
  data_len = get_var_size_by_name (lexic, "data");

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = sizeof (struct ip6_hdr) + data_len;

  pkt = (struct ip6_hdr *) g_malloc0 (sizeof (struct ip6_hdr) + data_len);
  retc->x.str_val = (char *) pkt;

  version = get_int_var_by_name (lexic, "ip6_v", 6);
  tc = get_int_var_by_name (lexic, "ip6_tc", 0);
  fl = get_int_var_by_name (lexic, "ip6_fl", 0);

  pkt->ip6_flow = htonl (version << 28 | tc << 20 | fl);

  pkt->ip6_plen = FIX (data_len); /* No extension headers ? */
  pkt->ip6_nxt = get_int_var_by_name (lexic, "ip6_p", 0);
  pkt->ip6_hlim = get_int_var_by_name (lexic, "ip6_hlim", 64);

  /* source */
  s = get_str_var_by_name (lexic, "ip6_src");
  if (s != NULL)
    inet_pton (AF_INET6, s, &pkt->ip6_src);
  /* else this host address? */

  s = get_str_var_by_name (lexic, "ip6_dst");
  if (s != NULL)
    inet_pton (AF_INET6, s, &pkt->ip6_dst);
  else
    pkt->ip6_dst = *dst_addr;

  if (data != NULL)
    {
      bcopy (data, retc->x.str_val + sizeof (struct ip6_hdr), data_len);
    }

  /*
     There is no checksum for ipv6. Only upper layer
     calculates a checksum using pseudoheader
   */
  return retc;
}

/**
 * @brief Obtain IPv6 header element.
 *
 * @param[in] lexic      Lexical context of NASL interpreter.
 * @param[in] ipv6       IPv6 header. TODO: Once versions older than 20.08 are
 * no longer in use the parameter name can be changed to 'ip6'.
 * @param[in] element    Element to extract from the header.
 *
 * @return tree_cell with the IP header element.
 */
tree_cell *
get_ip_v6_element (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *element = get_str_var_by_name (lexic, "element");
  char ret_ascii[INET6_ADDRSTRLEN];
  int ret_int = 0;
  int flag = 0;
  struct ip6_hdr *ip6;

  /* Parameter name 'ipv6' was renamed to 'ip6' for consistency.
   * For backwards compatibility reasons we still need to consider the 'ipv6'
   * argument.
   */
  ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ipv6");
  if (ip6 == NULL)
    {
      ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");
      if (ip6 == NULL)
        {
          nasl_perror (lexic, "%s: no valid 'ip6' argument\n", __func__);
          return NULL;
        }
    }

  if (element == NULL)
    {
      nasl_perror (lexic, "%s: no valid 'element' argument\n", __func__);
      return NULL;
    }

  if (!strcmp (element, "ip6_v"))
    {
      ret_int = ntohl (ip6->ip6_flow) >> 28;
      flag++;
    }
  else if (!strcmp (element, "ip6_tc"))
    {
      ret_int = (ntohl (ip6->ip6_flow) >> 20) & 0xff;
      flag++;
    }
  else if (!strcmp (element, "ip6_fl"))
    {
      ret_int = ntohl (ip6->ip6_flow) & 0x3ffff;
      flag++;
    }
  else if (!strcmp (element, "ip6_plen"))
    {
      ret_int = UNFIX (ip6->ip6_plen);
      flag++;
    }
  else if (!strcmp (element, "ip6_nxt"))
    {
      ret_int = (ip6->ip6_nxt);
      flag++;
    }
  else if (!strcmp (element, "ip6_hlim"))
    {
      ret_int = (ip6->ip6_hlim);
      flag++;
    }

  if (flag != 0)
    {
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = ret_int;
      return retc;
    }

  if (!strcmp (element, "ip6_src"))
    {
      inet_ntop (AF_INET6, &ip6->ip6_src, ret_ascii, sizeof (ret_ascii));
      flag++;
    }
  else if (!strcmp (element, "ip6_dst"))
    {
      inet_ntop (AF_INET6, &ip6->ip6_dst, ret_ascii, sizeof (ret_ascii));
      flag++;
    }

  if (flag == 0)
    {
      nasl_perror (lexic, "%s : unknown element '%s'\n", __func__, element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (ret_ascii);
  retc->x.str_val = g_strdup (ret_ascii);

  return retc;
}

/**
 * @brief Set IPv6 header element.
 *
 * @param[in] lexic     Lexical context of NASL interpreter.
 * @param[in] ip6       IP v6 header.
 * @param[in] ip6_plen  Payload length.
 * @param[in] ip6_hlim  Hop limit. Max. 255
 * @param[in] ip6_nxt   Next packet.
 * @param[in] ip6_src   Source address
 *
 * @return tree_cell with the forged IP packet.
 */
tree_cell *
set_ip_v6_elements (lex_ctxt *lexic)
{
  struct ip6_hdr *o_pkt = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");
  int size = get_var_size_by_name (lexic, "ip6");
  tree_cell *retc;
  struct ip6_hdr *pkt;
  char *s;

  if (o_pkt == NULL)
    {
      nasl_perror (lexic, "%s: missing <ip6> field\n", __func__);
      return NULL;
    }

  pkt = (struct ip6_hdr *) g_malloc0 (size);
  bcopy (o_pkt, pkt, size);

  pkt->ip6_plen = get_int_var_by_name (lexic, "ip6_plen", pkt->ip6_plen);
  pkt->ip6_nxt = get_int_var_by_name (lexic, "ip6_nxt", pkt->ip6_nxt);
  pkt->ip6_hlim = get_int_var_by_name (lexic, "ip6_hlim", pkt->ip6_hlim);

  s = get_str_var_by_name (lexic, "ip6_src");
  if (s != NULL)
    inet_pton (AF_INET6, s, &pkt->ip6_src);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = size;
  retc->x.str_val = (char *) pkt;

  return retc;
}

/**
 * @brief Print IPv6 Header.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IPv6 datagrams to dump.
 *
 * @return Print and returns FAKE_CELL.
 */
tree_cell *
dump_ip_v6_packet (lex_ctxt *lexic)
{
  int i;
  char addr[INET6_ADDRSTRLEN];

  for (i = 0;; i++)
    {
      struct ip6_hdr *ip6 = (struct ip6_hdr *) get_str_var_by_num (lexic, i);

      if (ip6 == NULL)
        break;
      else
        {
          printf ("------\n");
          printf ("\tip6_v    : %d\n", ntohl (ip6->ip6_flow) >> 28);
          printf ("\tip6_tc   : %d\n", (ntohl (ip6->ip6_flow) >> 20) & 0xff);
          printf ("\tip6_fl   : %d\n", ntohl (ip6->ip6_flow) & 0x3ffff);
          printf ("\tip6_plen : %d\n", UNFIX (ip6->ip6_plen));
          printf ("\tip6_hlim : %d\n", ip6->ip6_hlim);
          switch (ip6->ip6_nxt)
            {
            case IPPROTO_TCP:
              printf ("\tip6_nxt  : IPPROTO_TCP (%d)\n", ip6->ip6_nxt);
              break;
            case IPPROTO_UDP:
              printf ("\tip6_nxt  : IPPROTO_UDP (%d)\n", ip6->ip6_nxt);
              break;
            case IPPROTO_ICMPV6:
              printf ("\tip6_nxt  : IPPROTO_ICMPV6 (%d)\n", ip6->ip6_nxt);
              break;
            default:
              printf ("\tip6_nxt  : %d\n", ip6->ip6_nxt);
              break;
            }
          printf ("\tip6_src  : %s\n",
                  inet_ntop (AF_INET6, &ip6->ip6_src, addr, sizeof (addr)));
          printf ("\tip6_dst  : %s\n",
                  inet_ntop (AF_INET6, &ip6->ip6_dst, addr, sizeof (addr)));
          printf ("\n");
        }
    }

  return FAKE_CELL;
}

/**
 * @brief Adds an IPv6 option to the datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ip6     IPv6 packet.
 * @param[in] data    Data payload.
 * @param[in] code    Code of option.
 * @param[in] length  Length of value.
 * @param[in] value   Value of the option.
 *
 * @return the modified datagram.
 */
tree_cell *
insert_ip_v6_options (lex_ctxt *lexic)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");
  int code = get_int_var_by_name (lexic, "code", 0);
  int len = get_int_var_by_name (lexic, "length", 0);
  char *value = get_str_var_by_name (lexic, "value");
  int value_size = get_var_size_by_name (lexic, "value");
  tree_cell *retc;
  struct ip6_hdr *new_packet;
  char *p;
  int size = get_var_size_by_name (lexic, "ip6");
  u_char uc_code, uc_len;
  int pad_len;
  char zero = '0';
  int i;
  int pl;

  if (ip6 == NULL)
    {
      nasl_perror (lexic,
                   "Usage : %s(ip6:<ip6>, code:<code>, "
                   "length:<len>, value:<value>\n",
                   __func__);
      return NULL;
    }

  pad_len = 4 - ((sizeof (uc_code) + sizeof (uc_len) + value_size) % 4);
  if (pad_len == 4)
    pad_len = 0;

  pl = 40 < UNFIX (ip6->ip6_plen) ? 40 : UNFIX (ip6->ip6_plen);
  new_packet = g_malloc0 (size + 4 + value_size + pad_len);
  bcopy (ip6, new_packet, pl);

  uc_code = (u_char) code;
  uc_len = (u_char) len;

  p = (char *) new_packet;
  bcopy (&uc_code, p + pl, sizeof (uc_code));
  bcopy (&uc_len, p + pl + sizeof (uc_code), sizeof (uc_len));
  bcopy (value, p + pl + sizeof (uc_code) + sizeof (uc_len), value_size);

  zero = 0;
  for (i = 0; i < pad_len; i++)
    {
      bcopy (&zero,
             p + pl + sizeof (uc_code) + sizeof (uc_len) + value_size + i, 1);
    }

  p = (char *) ip6;
  bcopy (p + pl,
         new_packet
           + (sizeof (uc_code) + sizeof (uc_len) + value_size + pad_len) + pl,
         size - pl);

  new_packet->ip6_plen =
    FIX (size + sizeof (uc_code) + sizeof (uc_len) + value_size + pad_len);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = size + value_size + sizeof (uc_code) + sizeof (uc_len) + pad_len;
  retc->x.str_val = (char *) new_packet;

  return retc;
}

/*--------------[   TCP   ]--------------------------------------------*/

struct v6pseudohdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  u_short length;
  u_char zero1;
  u_char zero2;
  u_char zero3;
  u_char protocol;
  struct tcphdr tcpheader;
} __attribute__ ((packed));

// TCP options
struct tcp_opt_mss
{
  uint8_t kind; // 2
  uint8_t len;  // 4
  uint16_t mss;
} __attribute__ ((packed));

struct tcp_opt_wscale
{
  uint8_t kind; // 3
  uint8_t len;  // 3
  uint8_t wscale;
} __attribute__ ((packed));

struct tcp_opt_sack_perm
{
  uint8_t kind; // 4
  uint8_t len;  // 2
} __attribute__ ((packed));

struct tcp_opt_tstamp
{
  uint8_t kind; // 8
  uint8_t len;  // 10
  uint32_t tstamp;
  uint32_t e_tstamp;
} __attribute__ ((packed));

struct tcp_options
{
  struct tcp_opt_mss mss;
  struct tcp_opt_wscale wscale;
  struct tcp_opt_sack_perm sack_perm;
  struct tcp_opt_tstamp tstamp;
} __attribute__ ((packed));

/**
 * @brief Forge TCP packet.
 *
 * @param[in] lexic     Lexical context of NASL interpreter.
 * @param[in] ip6       IPv6 packet.
 * @param[in] data      Data.
 * @param[in] th_sport  Source port. 0 by default.
 * @param[in] th_dport  Destination port. 0 by default.
 * @param[in] th_seq    Sequence number. Random by default.
 * @param[in] th_ack    Acknowledgement number. 0 by default.
 * @param[in] th_x2     0 by default.
 * @param[in] th_off    Data offset. 5 by default.
 * @param[in] th_flags  Flags. 0 by default.
 * @param[in] th_win    Window. 0 by default.
 * @param[in] th_sum    Checksum. Is filled in automatically by default
 * @param[in] th_urp    Urgent pointer. 0 by default.
 *
 * @return tree_cell with the forged TCP packet containing IPv6 header.
 */
tree_cell *
forge_tcp_v6_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *data;
  int len;
  struct ip6_hdr *ip6, *tcp_packet;
  struct tcphdr *tcp;
  int ipsz;

  ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");
  if (ip6 == NULL)
    {
      nasl_perror (lexic,
                   "forge_tcp_v6_packet: You must supply the 'ip6' argument\n");
      return NULL;
    }

  ipsz = get_var_size_by_name (lexic, "ip6");

  // Not considering IP Options.
  if (ipsz != 40)
    ipsz = 40;

  data = get_str_var_by_name (lexic, "data");
  len = data == NULL ? 0 : get_var_size_by_name (lexic, "data");

  retc = alloc_typed_cell (CONST_DATA);
  tcp_packet =
    (struct ip6_hdr *) g_malloc0 (ipsz + sizeof (struct tcphdr) + len);
  retc->x.str_val = (char *) tcp_packet;

  bcopy (ip6, tcp_packet, ipsz);
  /* Adjust length in ipv6 header */
  tcp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen =
    FIX (sizeof (struct tcphdr) + len);
  tcp = (struct tcphdr *) ((char *) tcp_packet + 40);

  tcp->th_sport = ntohs (get_int_var_by_name (lexic, "th_sport", 0));
  tcp->th_dport = ntohs (get_int_var_by_name (lexic, "th_dport", 0));
  tcp->th_seq = htonl (get_int_var_by_name (lexic, "th_seq", rand ()));
  tcp->th_ack = htonl (get_int_var_by_name (lexic, "th_ack", 0));
  tcp->th_x2 = get_int_var_by_name (lexic, "th_x2", 0);
  tcp->th_off = get_int_var_by_name (lexic, "th_off", 5);
  tcp->th_flags = get_int_var_by_name (lexic, "th_flags", 0);
  tcp->th_win = htons (get_int_var_by_name (lexic, "th_win", 0));
  tcp->th_sum = get_int_var_by_name (lexic, "th_sum", 0);
  tcp->th_urp = get_int_var_by_name (lexic, "th_urp", 0);

  if (data != NULL)
    bcopy (data, (char *) tcp + sizeof (struct tcphdr), len);

  if (!tcp->th_sum)
    {
      struct v6pseudohdr pseudoheader;
      char *tcpsumdata = g_malloc0 (sizeof (struct v6pseudohdr) + len + 1);

      bzero (&pseudoheader, 38 + sizeof (struct tcphdr));
      memcpy (&pseudoheader.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
      memcpy (&pseudoheader.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

      pseudoheader.protocol = IPPROTO_TCP;
      pseudoheader.length = htons (sizeof (struct tcphdr) + len);
      bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
             sizeof (struct tcphdr));
      /* fill tcpsumdata with data to checksum */
      bcopy ((char *) &pseudoheader, tcpsumdata, sizeof (struct v6pseudohdr));
      if (data != NULL)
        bcopy ((char *) data, tcpsumdata + sizeof (struct v6pseudohdr), len);
      tcp->th_sum = np_in_cksum ((unsigned short *) tcpsumdata,
                                 38 + sizeof (struct tcphdr) + len);
      g_free (tcpsumdata);
    }

  retc->size = ipsz + sizeof (struct tcphdr) + len;
  return retc;
}

/**
 * @brief Get TCP Header element.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] tcp     IPv6 packet
 * @param[in] element Element to extract from the header (see
 * forge_tcp_v6_packet()).
 *
 * @return tree_cell with the forged IP packet.
 */
tree_cell *
get_tcp_v6_element (lex_ctxt *lexic)
{
  u_char *packet = (u_char *) get_str_var_by_name (lexic, "tcp");
  struct ip6_hdr *ip6;
  int ipsz;
  struct tcphdr *tcp;
  char *element;
  int ret;
  tree_cell *retc;

  ipsz = get_var_size_by_name (lexic, "tcp");

  if (packet == NULL)
    {
      nasl_perror (lexic, "get_tcp_v6_element: No valid 'tcp' argument\n");
      return NULL;
    }

  ip6 = (struct ip6_hdr *) packet;

  /* valid ipv6 header check */
  if (UNFIX (ip6->ip6_plen) > ipsz)
    return NULL; /* Invalid packet */

  tcp = (struct tcphdr *) (packet + 40);

  element = get_str_var_by_name (lexic, "element");
  if (!element)
    {
      nasl_perror (lexic, "get_tcp_v6_element: No valid 'element' argument\n");
      return NULL;
    }

  if (!strcmp (element, "th_sport"))
    ret = ntohs (tcp->th_sport);
  else if (!strcmp (element, "th_dsport"))
    ret = ntohs (tcp->th_dport);
  else if (!strcmp (element, "th_seq"))
    ret = ntohl (tcp->th_seq);
  else if (!strcmp (element, "th_ack"))
    ret = ntohl (tcp->th_ack);
  else if (!strcmp (element, "th_x2"))
    ret = tcp->th_x2;
  else if (!strcmp (element, "th_off"))
    ret = tcp->th_off;
  else if (!strcmp (element, "th_flags"))
    ret = tcp->th_flags;
  else if (!strcmp (element, "th_win"))
    ret = ntohs (tcp->th_win);
  else if (!strcmp (element, "th_sum"))
    ret = tcp->th_sum;
  else if (!strcmp (element, "th_urp"))
    ret = tcp->th_urp;
  else if (!strcmp (element, "data"))
    {
      retc = alloc_typed_cell (CONST_DATA);
      retc->size = UNFIX (ip6->ip6_plen) - tcp->th_off * 4;
      if (retc->size < 0 || retc->size > ipsz - 40 - tcp->th_off * 4)
        {
          nasl_perror (lexic,
                       "get_tcp_v6_element: Erroneous tcp header offset %d\n",
                       retc->size);
          deref_cell (retc);
          return NULL;
        }
      retc->x.str_val = g_malloc0 (retc->size);
      bcopy ((char *) tcp + tcp->th_off * 4, retc->x.str_val, retc->size);
      return retc;
    }
  else
    {
      nasl_perror (lexic, "get_tcp_v6_element: Unknown tcp field %s\n",
                   element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/**
 * @brief Extract all TCP option from an IP datagram.
 *
 * @param[in] options All options present in the TCP segment.
 * @param[out] tcp_all_options Container for the options to return.
 */
static void
get_tcp_options (char *options, struct tcp_options *tcp_all_options)
{
  uint8_t *opt_kind;
  if (options == NULL)
    return;

  opt_kind = (uint8_t *) options;

  while (*opt_kind != 0)
    {
      switch (*opt_kind)
        {
        case TCPOPT_MAXSEG:
          tcp_all_options->mss.kind = *opt_kind;
          tcp_all_options->mss.len = *(opt_kind + 1);
          tcp_all_options->mss.mss = *((uint16_t *) (opt_kind + 2));
          opt_kind = opt_kind + *(opt_kind + 1);
          break;
        case TCPOPT_WINDOW:
          tcp_all_options->wscale.kind = *opt_kind;
          tcp_all_options->wscale.len = *(opt_kind + 1);
          tcp_all_options->wscale.wscale = (uint8_t) * (opt_kind + 2);
          opt_kind = opt_kind + *(opt_kind + 1);
          break;
        case TCPOPT_SACK_PERMITTED:
          tcp_all_options->sack_perm.kind = *opt_kind;
          tcp_all_options->sack_perm.len = *(opt_kind + 1);
          opt_kind = opt_kind + *(opt_kind + 1);
          break;
        case TCPOPT_TIMESTAMP:
          tcp_all_options->tstamp.kind = *opt_kind;
          tcp_all_options->tstamp.len = *(opt_kind + 1);
          tcp_all_options->tstamp.tstamp = *((uint32_t *) (opt_kind + 2));
          tcp_all_options->tstamp.e_tstamp = *((uint32_t *) (opt_kind + 6));
          opt_kind = opt_kind + *(opt_kind + 1);
          break;
        case TCPOPT_EOL:
        case TCPOPT_NOP:
          opt_kind++;
          break;
        case TCPOPT_SACK: // Not supported
          opt_kind = opt_kind + *(opt_kind + 1);
          break;
        default:
          g_debug ("%s: Unsupported %u TCP option. "
                   "Not all options are returned.",
                   __func__, *opt_kind);
          *opt_kind = 0;
          break;
        }
    }
}

/**
 * @brief Get a TCP option from an IP datagram if present.
 * Possible options are:
 *   TCPOPT_MAXSEG (2), values between 536 and 65535
 *   TCPOPT_WINDOW (3), with values between 0 and 14
 *   TCPOPT_SACK_PERMITTED (4), no value required.
 *   TCPOPT_TIMESTAMP (8), 8 bytes value for timestamp
 *   and echo timestamp, 4 bytes each one.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] tcp     The full IP datagram (IP + TCP).
 * @param[in] option  Option to get.
 *
 * @return  Integer or array given the case.
 */
tree_cell *
get_tcp_v6_option (lex_ctxt *lexic)
{
  u_char *packet = (u_char *) get_str_var_by_name (lexic, "tcp");
  struct ip6_hdr *ip6;
  int ipsz;
  struct tcphdr *tcp;
  char *options;
  int opt;
  tree_cell *retc;
  nasl_array *arr;
  anon_nasl_var v;

  struct tcp_options *tcp_all_options = NULL;

  if (packet == NULL)
    {
      nasl_perror (lexic, "%s: No valid 'tcp' argument passed.\n", __func__);
      return NULL;
    }

  opt = get_int_var_by_name (lexic, "option", -1);
  if (opt < 0)
    {
      nasl_perror (lexic,
                   "%s: No 'option' argument passed but required.\n."
                   "Usage: %s(tcp:<tcp>, option:<TCPOPT>)",
                   __func__, __func__);
      return NULL;
    }

  ip6 = (struct ip6_hdr *) packet;

  /* valid ipv6 header check */
  ipsz = get_var_size_by_name (lexic, "tcp");
  if (UNFIX (ip6->ip6_plen) > ipsz)
    return NULL; /* Invalid packet */

  tcp = (struct tcphdr *) (packet + 40);

  if (tcp->th_off <= 5)
    return NULL;

  // Get options from the segment
  options = (char *) g_malloc0 (sizeof (uint8_t) * 4 * (tcp->th_off - 5));
  memcpy (options, (char *) tcp + 20, (tcp->th_off - 5) * 4);

  tcp_all_options = g_malloc0 (sizeof (struct tcp_options));
  get_tcp_options (options, tcp_all_options);
  if (tcp_all_options == NULL)
    {
      nasl_perror (lexic, "%s: No TCP options found in passed TCP packet.\n",
                   __func__);

      g_free (options);
      return NULL;
    }

  opt = get_int_var_by_name (lexic, "option", -1);
  retc = NULL;
  switch (opt)
    {
    case TCPOPT_MAXSEG:
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = ntohs ((uint16_t) tcp_all_options->mss.mss);
      break;
    case TCPOPT_WINDOW:
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = tcp_all_options->wscale.wscale;
      break;
    case TCPOPT_SACK_PERMITTED:
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = tcp_all_options->sack_perm.kind ? 1 : 0;
      break;
    case TCPOPT_TIMESTAMP:
      retc = alloc_typed_cell (DYN_ARRAY);
      retc->x.ref_val = arr = g_malloc0 (sizeof (nasl_array));

      memset (&v, 0, sizeof (v));
      v.var_type = VAR2_INT;
      v.v.v_int = ntohl ((uint32_t) tcp_all_options->tstamp.tstamp);
      add_var_to_array (arr, "timestamp", &v);

      memset (&v, 0, sizeof (v));
      v.var_type = VAR2_INT;
      v.v.v_int = ntohl ((uint32_t) tcp_all_options->tstamp.e_tstamp);
      add_var_to_array (arr, "echo_timestamp", &v);
      break;
    default:
      nasl_perror (lexic, "%s: Invalid TCP option passed.\n", __func__);
      break;
    }

  g_free (tcp_all_options);
  g_free (options);
  return retc;
}

/**
 * @brief Set TCP Header element.
 *
 * @param[in] lexic     Lexical context of NASL interpreter.
 * @param[in] tcp       IPv6 packet to modify.
 * @param[in] data      Data.
 * @param[in] th_sport  Source port.
 * @param[in] th_dport  Destination port.
 * @param[in] th_seq    Sequence number.
 * @param[in] th_ack    Acknowledgement number.
 * @param[in] th_x2
 * @param[in] th_off    Data offset.
 * @param[in] th_flags  Flags.
 * @param[in] th_win    Window.
 * @param[in] th_sum    Checksum.
 * @param[in] th_urp    Urgent pointer.
 * @param[in] update_ip_len  Flag (TRUE by default). If set, NASL will recompute
 * the size field of the IP datagram.
 *
 * @return tree_cell with the modified IPv6 datagram.
 */
tree_cell *
set_tcp_v6_elements (lex_ctxt *lexic)
{
  char *pkt = get_str_var_by_name (lexic, "tcp");
  struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
  int pktsz = get_var_size_by_name (lexic, "tcp");
  struct tcphdr *tcp;
  tree_cell *retc;
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = get_var_size_by_name (lexic, "data");
  char *npkt;

  if (pkt == NULL)
    {
      nasl_perror (
        lexic, "set_tcp_v6_elements: Invalid value for the argument 'tcp'\n");
      return NULL;
    }

  tcp = (struct tcphdr *) (pkt + 40);

  if (pktsz < UNFIX (ip6->ip6_plen))
    return NULL;

  if (data_len == 0)
    {
      data_len = UNFIX (ip6->ip6_plen) - (tcp->th_off * 4);
      data = (char *) ((char *) tcp + tcp->th_off * 4);
    }

  npkt = g_malloc0 (40 + tcp->th_off * 4 + data_len);
  bcopy (pkt, npkt, UNFIX (ip6->ip6_plen) + 40);

  ip6 = (struct ip6_hdr *) (npkt);
  tcp = (struct tcphdr *) (npkt + 40);

  tcp->th_sport =
    htons (get_int_var_by_name (lexic, "th_sport", ntohs (tcp->th_sport)));
  tcp->th_dport =
    htons (get_int_var_by_name (lexic, "th_dport", ntohs (tcp->th_dport)));
  tcp->th_seq =
    htonl (get_int_var_by_name (lexic, "th_seq", ntohl (tcp->th_seq)));
  tcp->th_ack =
    htonl (get_int_var_by_name (lexic, "th_ack", ntohl (tcp->th_ack)));
  tcp->th_x2 = get_int_var_by_name (lexic, "th_x2", tcp->th_x2);
  tcp->th_off = get_int_var_by_name (lexic, "th_off", tcp->th_off);
  tcp->th_flags = get_int_var_by_name (lexic, "th_flags", tcp->th_flags);
  tcp->th_win =
    htons (get_int_var_by_name (lexic, "th_win", ntohs (tcp->th_win)));
  tcp->th_sum = get_int_var_by_name (lexic, "th_sum", 0);
  tcp->th_urp = get_int_var_by_name (lexic, "th_urp", tcp->th_urp);

  bcopy (data, (char *) tcp + tcp->th_off * 4, data_len);

  if (get_int_var_by_name (lexic, "update_ip_len", 1) != 0)
    {
      ip6->ip6_plen = FIX (tcp->th_off * 4 + data_len);
    }

  if (tcp->th_sum == 0)
    {
      struct v6pseudohdr pseudoheader;
      char *tcpsumdata = g_malloc0 (sizeof (struct v6pseudohdr) + data_len + 1);

      bzero (&pseudoheader, 38 + sizeof (struct tcphdr));
      memcpy (&pseudoheader.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
      memcpy (&pseudoheader.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

      pseudoheader.protocol = IPPROTO_TCP;
      pseudoheader.length = htons (sizeof (struct tcphdr) + data_len);
      bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
             sizeof (struct tcphdr));
      /* fill tcpsumdata with data to checksum */
      bcopy ((char *) &pseudoheader, tcpsumdata, sizeof (struct v6pseudohdr));
      if (data != NULL)
        bcopy ((char *) data, tcpsumdata + sizeof (struct v6pseudohdr),
               data_len);
      tcp->th_sum = np_in_cksum ((unsigned short *) tcpsumdata,
                                 38 + sizeof (struct tcphdr) + data_len);
      g_free (tcpsumdata);
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 40 + (tcp->th_off * 4) + data_len;
  retc->x.str_val = npkt;
  return retc;
}

/**
 * @brief Add options to a TCP segment header.
 * Possible options are:
 *   TCPOPT_MAXSEG (2), values between 536 and 65535
 *   TCPOPT_WINDOW (3), with values between 0 and 14
 *   TCPOPT_SACK_PERMITTED (4), no value required.
 *   TCPOPT_TIMESTAMP (8), 8 bytes value for timestamp
 *   and echo timestamp, 4 bytes each one.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] tcp       IP datagram.
 * @param[in] data      (optional) TCP data payload.
 * @param[in]           unnamed option.
 * @param[in]           Value for unnamed option if required.
 *
 * @return The modified IP datagram.
 */
tree_cell *
insert_tcp_v6_options (lex_ctxt *lexic)
{
  char *pkt = get_str_var_by_name (lexic, "tcp");
  struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
  int pktsz = get_var_size_by_name (lexic, "tcp");
  struct tcphdr *tcp;
  tree_cell *retc;
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = get_var_size_by_name (lexic, "data");
  char *npkt;
  int tcp_opt, tcp_opt_val, tcp_opt_val2;
  int current_opt_len, total_opt_len, opt_size_allocated;
  char *opts, *ptr_opts_pos;
  uint8_t eol, nop;
  int i;

  struct tcp_opt_mss *opt_mss;
  struct tcp_opt_wscale *opt_wscale;
  struct tcp_opt_sack_perm *opt_sack_perm;
  struct tcp_opt_tstamp *opt_tstamp;

  if (pkt == NULL)
    {
      nasl_perror (
        lexic, "set_tcp_v6_elements: Invalid value for the argument 'tcp'\n");
      return NULL;
    }
  opts = g_malloc0 (sizeof (char) * 4);
  ptr_opts_pos = opts;
  opt_size_allocated = 4; // 4 bytes
  total_opt_len = 0;
  for (i = 0;; i++)
    {
      tcp_opt = get_int_var_by_num (lexic, i, -1);
      current_opt_len = total_opt_len;

      if (tcp_opt == -1)
        break;

      switch (tcp_opt)
        {
        case TCPOPT_MAXSEG:
          tcp_opt_val = get_int_var_by_num (lexic, i + 1, -1);
          i++;
          if (tcp_opt_val < (int) TCP_MSS_DESIRED || tcp_opt_val > 65535)
            {
              nasl_perror (lexic, "%s: Invalid value for TCP option MSS\n",
                           __func__);
              break;
            }
          opt_mss = g_malloc0 (sizeof (struct tcp_opt_mss));
          total_opt_len += TCPOLEN_MAXSEG;
          opt_mss->kind = TCPOPT_MAXSEG;
          opt_mss->len = TCPOLEN_MAXSEG;
          opt_mss->mss = FIX (tcp_opt_val);

          // Need reallocated memory because options requires it.
          if (total_opt_len > opt_size_allocated)
            {
              opt_size_allocated = ((total_opt_len / 4) + 1) * 4;
              opts = g_realloc (opts, sizeof (char) * opt_size_allocated);
              ptr_opts_pos = opts + current_opt_len;
            }

          memcpy (ptr_opts_pos, (u_char *) opt_mss,
                  sizeof (struct tcp_opt_mss));
          ptr_opts_pos = ptr_opts_pos + sizeof (struct tcp_opt_mss);
          g_free (opt_mss);
          break;
        case TCPOPT_WINDOW:
          tcp_opt_val = get_int_var_by_num (lexic, i + 1, -1);
          i++;
          if (tcp_opt_val < 0 || tcp_opt_val > 14)
            {
              nasl_perror (lexic, "%s: Invalid value for TCP option WScale\n",
                           __func__);
              break;
            }
          opt_wscale = g_malloc0 (sizeof (struct tcp_opt_wscale));
          total_opt_len += TCPOLEN_WINDOW;
          opt_wscale->kind = TCPOPT_WINDOW;
          opt_wscale->len = TCPOLEN_WINDOW;
          opt_wscale->wscale = tcp_opt_val;

          // Need reallocated memory because options requires it.
          if (total_opt_len > opt_size_allocated)
            {
              opt_size_allocated = ((total_opt_len / 4) + 1) * 4;
              opts = g_realloc (opts, sizeof (char) * opt_size_allocated);
              ptr_opts_pos = opts + current_opt_len;
            }

          memcpy (ptr_opts_pos, (u_char *) opt_wscale,
                  sizeof (struct tcp_opt_wscale));
          ptr_opts_pos = ptr_opts_pos + sizeof (struct tcp_opt_wscale);
          g_free (opt_wscale);
          break;
        case TCPOPT_SACK_PERMITTED:
          opt_sack_perm = g_malloc0 (sizeof (struct tcp_opt_sack_perm));
          total_opt_len += TCPOLEN_SACK_PERMITTED;
          opt_sack_perm->kind = TCPOPT_SACK_PERMITTED;
          opt_sack_perm->len = TCPOLEN_SACK_PERMITTED;

          // Need reallocated memory because options requires it.
          if (total_opt_len > opt_size_allocated)
            {
              opt_size_allocated = ((total_opt_len / 4) + 1) * 4;
              opts = g_realloc (opts, sizeof (char) * opt_size_allocated);
              ptr_opts_pos = opts + current_opt_len;
            }

          memcpy (ptr_opts_pos, (u_char *) opt_sack_perm,
                  sizeof (struct tcp_opt_sack_perm));
          ptr_opts_pos = ptr_opts_pos + sizeof (struct tcp_opt_sack_perm);
          g_free (opt_sack_perm);
          break;
        case TCPOPT_TIMESTAMP:
          tcp_opt_val = get_int_var_by_num (lexic, i + 1, -1);
          tcp_opt_val2 = get_int_var_by_num (lexic, i + 2, -1);
          i = i + 2;
          if (tcp_opt_val < 0)
            nasl_perror (lexic, "%s: Invalid value for TCP option Timestamp\n",
                         __func__);
          opt_tstamp = g_malloc0 (sizeof (struct tcp_opt_tstamp));
          total_opt_len += TCPOLEN_TIMESTAMP;
          opt_tstamp->kind = TCPOPT_TIMESTAMP;
          opt_tstamp->len = TCPOLEN_TIMESTAMP;
          opt_tstamp->tstamp = htonl (tcp_opt_val);
          opt_tstamp->e_tstamp = htonl (tcp_opt_val2);

          // Need reallocated memory because options requires it.
          if (total_opt_len > opt_size_allocated)
            {
              opt_size_allocated = ((total_opt_len / 4) + 1) * 4;
              opts = g_realloc (opts, sizeof (char) * opt_size_allocated);
              ptr_opts_pos = opts + current_opt_len;
            }

          memcpy (ptr_opts_pos, (u_char *) opt_tstamp,
                  sizeof (struct tcp_opt_tstamp));
          ptr_opts_pos = ptr_opts_pos + sizeof (struct tcp_opt_tstamp);
          g_free (opt_tstamp);
          break;
        case TCPOPT_NOP:
        case TCPOPT_EOL:
        case TCPOPT_SACK: /* Experimental, not supported */
        default:
          nasl_perror (lexic, "%s: TCP option %d not supported\n", __func__,
                       tcp_opt);
          break;
        }
    }

  // Add NOP padding and End Of Option list kinds.
  current_opt_len = total_opt_len;
  eol = TCPOPT_EOL;
  nop = TCPOPT_NOP;
  if (total_opt_len % 4 == 0)
    {
      opt_size_allocated = opt_size_allocated + 4;
      opts = g_realloc (opts, sizeof (char) * opt_size_allocated);
      ptr_opts_pos = opts + total_opt_len;
    }
  if (current_opt_len < opt_size_allocated - 1)
    {
      // Add NOPs
      for (i = current_opt_len; i < opt_size_allocated - 1; i++)
        {
          memcpy (ptr_opts_pos, &nop, 1);
          total_opt_len++;
          ptr_opts_pos++;
        }
    }
  // Add EOL
  memcpy (ptr_opts_pos, &eol, 1);

  tcp = (struct tcphdr *) (pkt + 40);

  if (pktsz < UNFIX (ip6->ip6_plen))
    {
      g_free (opts);
      return NULL;
    }

  if (data_len == 0)
    {
      data_len = UNFIX (ip6->ip6_plen) - (tcp->th_off * 4);
      data = (char *) ((char *) tcp + tcp->th_off * 4);
    }

  // Alloc enough memory to hold the options
  npkt = g_malloc0 (40 + tcp->th_off * 4 + opt_size_allocated + data_len);
  memcpy (npkt, pkt, UNFIX (ip6->ip6_plen) + 40);
  ip6 = (struct ip6_hdr *) (npkt);
  tcp = (struct tcphdr *) (npkt + 40);

  // copy options
  memcpy ((char *) tcp + tcp->th_off * 4, opts, opt_size_allocated);
  tcp->th_off = tcp->th_off + (opt_size_allocated / 4);

  memcpy ((char *) tcp + tcp->th_off * 4, data, data_len);

  ip6->ip6_plen = FIX (tcp->th_off * 4 + data_len);

  struct v6pseudohdr pseudoheader;
  char *tcpsumdata =
    g_malloc0 (sizeof (struct v6pseudohdr) + opt_size_allocated + data_len + 1);

  memset (&pseudoheader, 0, 38 + sizeof (struct tcphdr));
  memcpy (&pseudoheader.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
  memcpy (&pseudoheader.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

  pseudoheader.protocol = IPPROTO_TCP;
  pseudoheader.length =
    htons (sizeof (struct tcphdr) + opt_size_allocated + data_len);

  // Set th_sum to Zero, necessary for the new checksum calculation
  tcp->th_sum = 0;

  memcpy ((char *) &pseudoheader.tcpheader, (char *) tcp,
          sizeof (struct tcphdr));

  /* fill tcpsumdata with data to checksum */
  memcpy (tcpsumdata, (char *) &pseudoheader, sizeof (struct v6pseudohdr));
  memcpy (tcpsumdata + sizeof (struct v6pseudohdr), (char *) opts,
          opt_size_allocated);
  if (data != NULL)
    memcpy (tcpsumdata + sizeof (struct v6pseudohdr) + opt_size_allocated,
            (char *) data, data_len);
  tcp->th_sum =
    np_in_cksum ((unsigned short *) tcpsumdata,
                 38 + sizeof (struct tcphdr) + opt_size_allocated + data_len);
  g_free (opts);
  g_free (tcpsumdata);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 40 + (tcp->th_off * 4) + data_len;
  retc->x.str_val = npkt;
  return retc;
}

/**
 * @brief Dump TCP part of an IPv6 Datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IPv6 datagrams to dump.
 *
 * @return Print and return FAKE_CELL.
 */
tree_cell *
dump_tcp_v6_packet (lex_ctxt *lexic)
{
  int i = 0;
  u_char *pkt;
  int options_len = 0;

  while ((pkt = (u_char *) get_str_var_by_num (lexic, i++)) != NULL)
    {
      int a = 0;
      struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
      struct tcphdr *tcp = (struct tcphdr *) (pkt + 40);
      unsigned int j;
      unsigned int limit;
      char *c;

      limit = get_var_size_by_num (lexic, i - 1);

      printf ("------\n");
      printf ("\tth_sport : %d\n", ntohs (tcp->th_sport));
      printf ("\tth_dport : %d\n", ntohs (tcp->th_dport));
      printf ("\tth_seq   : %u\n", (unsigned int) ntohl (tcp->th_seq));
      printf ("\tth_ack   : %u\n", (unsigned int) ntohl (tcp->th_ack));
      printf ("\tth_x2    : %d\n", tcp->th_x2);
      printf ("\tth_off   : %d\n", tcp->th_off);
      printf ("\tth_flags : ");
      if (tcp->th_flags & TH_FIN)
        {
          printf ("TH_FIN");
          a++;
        }
      if (tcp->th_flags & TH_SYN)
        {
          if (a)
            printf ("|");
          printf ("TH_SYN");
          a++;
        }
      if (tcp->th_flags & TH_RST)
        {
          if (a)
            printf ("|");
          printf ("TH_RST");
          a++;
        }
      if (tcp->th_flags & TH_PUSH)
        {
          if (a)
            printf ("|");
          printf ("TH_PUSH");
          a++;
        }
      if (tcp->th_flags & TH_ACK)
        {
          if (a)
            printf ("|");
          printf ("TH_ACK");
          a++;
        }
      if (tcp->th_flags & TH_URG)
        {
          if (a)
            printf ("|");
          printf ("TH_URG");
          a++;
        }
      if (!a)
        printf ("0");
      else
        printf (" (%d)", tcp->th_flags);
      printf ("\n");
      printf ("\tth_win   : %d\n", ntohs (tcp->th_win));
      printf ("\tth_sum   : 0x%x\n", tcp->th_sum);
      printf ("\tth_urp   : %d\n", tcp->th_urp);

      options_len = sizeof (uint8_t) * 4 * (tcp->th_off - 5);

      if (options_len > 5) // Options present
        {
          char *options;
          struct tcp_options *tcp_all_options;

          options = (char *) g_malloc0 (options_len);
          memcpy (options, (char *) tcp + 20, options_len);

          tcp_all_options = g_malloc0 (sizeof (struct tcp_options));
          get_tcp_options (options, tcp_all_options);
          if (tcp_all_options != NULL)
            {
              printf ("\tTCP Options:\n");
              printf ("\t\tTCPOPT_MAXSEG: %u\n",
                      ntohs ((uint16_t) tcp_all_options->mss.mss));
              printf ("\t\tTCPOPT_WINDOW: %u\n",
                      tcp_all_options->wscale.wscale);
              printf ("\t\tTCPOPT_SACK_PERMITTED: %u\n",
                      tcp_all_options->sack_perm.kind ? 1 : 0);
              printf ("\t\tTCPOPT_TIMESTAMP TSval: %u\n",
                      ntohl ((uint32_t) tcp_all_options->tstamp.tstamp));
              printf ("\t\tTCPOPT_TIMESTAMP TSecr: %u\n",
                      ntohl ((uint32_t) tcp_all_options->tstamp.e_tstamp));
            }
          g_free (options);
          g_free (tcp_all_options);
        }
      printf ("\n\tData     : ");
      c = (char *) ((char *) tcp + sizeof (struct tcphdr) + options_len);
      if (UNFIX (ip6->ip6_plen) > (sizeof (struct tcphdr) + options_len))
        for (j = 0;
             j < UNFIX (ip6->ip6_plen) - sizeof (struct tcphdr) - options_len
             && j < limit;
             j++)
          printf ("%c", isprint (c[j]) ? c[j] : '.');
      printf ("\n");
      printf ("\n");
    }
  return NULL;
}

/*--------------[       UDP     ]--------------------------------------------*/
/*
 * @brief UDP header.
 */

struct v6pseudo_udp_hdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  char proto;
  unsigned short len;
  struct udphdr udpheader;
};

/*
 * @brief Fills an IPv6 datagram with UDP data.
 *
 * @param[in] lexic           Lexical context of NASL interpreter.
 * @param[in] ip6             IPv6 packet.
 * @param[in] data            Data.
 * @param[in] uh_sport        Source port. 0 by default.
 * @param[in] uh_dport        Destination port. 0 by default.
 * @param[in] uh_ulen         Udp length.
 * @param[in] update_ip6_len  Flag (TRUE by default). If set, NASL will
 * recompute the size field of the IP datagram.
 *
 * @return tree_cell with the forged UDP packet containing IPv6 header.
 */
tree_cell *
forge_udp_v6_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct ip6_hdr *ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");

  if (ip6 != NULL)
    {
      char *data = get_str_var_by_name (lexic, "data");
      int data_len = get_var_size_by_name (lexic, "data");
      u_char *pkt;
      struct ip6_hdr *udp_packet;
      struct udphdr *udp;

      pkt = g_malloc0 (sizeof (struct udphdr) + 40 + data_len);
      udp_packet = (struct ip6_hdr *) pkt;
      udp = (struct udphdr *) (pkt + 40);

      udp->uh_sum = get_int_var_by_name (lexic, "uh_sum", 0);
      bcopy ((char *) ip6, pkt, 40);

      udp->uh_sport = htons (get_int_var_by_name (lexic, "uh_sport", 0));
      udp->uh_dport = htons (get_int_var_by_name (lexic, "uh_dport", 0));
      udp->uh_ulen = htons (get_int_var_by_name (
        lexic, "uh_ulen", data_len + sizeof (struct udphdr)));

      if (data_len != 0 && data != NULL)
        bcopy (data, (pkt + 40 + sizeof (struct udphdr)), data_len);

      if (!udp->uh_sum)
        {
          struct v6pseudo_udp_hdr pseudohdr;
          char *udpsumdata =
            g_malloc0 (sizeof (struct v6pseudo_udp_hdr) + data_len + 1);

          bzero (&pseudohdr, sizeof (struct v6pseudo_udp_hdr));
          memcpy (&pseudohdr.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
          memcpy (&pseudohdr.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

          pseudohdr.proto = IPPROTO_UDP;
          pseudohdr.len = htons (sizeof (struct udphdr) + data_len);
          bcopy ((char *) udp, (char *) &pseudohdr.udpheader,
                 sizeof (struct udphdr));
          bcopy ((char *) &pseudohdr, udpsumdata, sizeof (pseudohdr));
          if (data != NULL)
            {
              bcopy ((char *) data, udpsumdata + sizeof (pseudohdr), data_len);
            }
          udp->uh_sum = np_in_cksum ((unsigned short *) udpsumdata,
                                     38 + sizeof (struct udphdr) + data_len);
          g_free (udpsumdata);
        }

      if (UNFIX (udp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen) <= 40)
        {
          int v = get_int_var_by_name (lexic, "update_ip6_len", 1);
          if (v != 0)
            {
              udp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen =
                FIX (ntohs (udp->uh_ulen));
            }
        }

      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) pkt;
      retc->size = 8 + 40 + data_len;

      return retc;
    }
  else
    nasl_perror (lexic, "forge_udp_v6_packet:'ip6' argument missing. \n");

  return NULL;
}

/*
 * @brief Get an UDP Header element.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] udp     IPv6 datagram.
 * @param[in] element One of 'uh_sport', 'uh_dport', 'uh_ulen', 'uh_sum', 'data'
 *
 * @return tree_cell with the forged UDP packet.
 */
tree_cell *
get_udp_v6_element (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *udp;
  char *element;
  unsigned int ipsz;
  struct udphdr *udphdr;
  int ret;

  udp = get_str_var_by_name (lexic, "udp");
  ipsz = get_var_size_by_name (lexic, "udp");

  element = get_str_var_by_name (lexic, "element");
  if (udp == NULL || element == NULL)
    {
      nasl_perror (
        lexic, "get_udp_v6_element() usage :\n"
               "element = get_udp_v6_element(udp:<udp>,element:<element>\n");
      return NULL;
    }

  if (40 + sizeof (struct udphdr) > ipsz)
    return NULL;

  udphdr = (struct udphdr *) (udp + 40);
  if (!strcmp (element, "uh_sport"))
    ret = ntohs (udphdr->uh_sport);
  else if (!strcmp (element, "uh_dport"))
    ret = ntohs (udphdr->uh_dport);
  else if (!strcmp (element, "uh_ulen"))
    ret = ntohs (udphdr->uh_ulen);
  else if (!strcmp (element, "uh_sum"))
    ret = ntohs (udphdr->uh_sum);
  else if (!strcmp (element, "data"))
    {
      int sz;
      retc = alloc_typed_cell (CONST_DATA);
      sz = ntohs (udphdr->uh_ulen) - sizeof (struct udphdr);

      if (ntohs (udphdr->uh_ulen) - 40 - sizeof (struct udphdr) > ipsz)
        sz = ipsz - 40 - sizeof (struct udphdr);

      retc->x.str_val = g_malloc0 (sz);
      retc->size = sz;
      bcopy (udp + 40 + sizeof (struct udphdr), retc->x.str_val, sz);
      return retc;
    }
  else
    {
      nasl_perror (lexic, "%s is not a value of a udp packet\n", element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/*
 * @brief Set UDP Header element.
 *
 * @param[in] lexic     Lexical context of NASL interpreter
 * @param[in] udp       IPv6 packet.
 * @param[in] data      Data.
 * @param[in] uh_sport  Source port.
 * @param[in] uh_dport  Destination port.
 * @param[in] uh_ulen   Udp length.
 * @param[in] uh_sum    Checksum.
 *
 * @return tree_cell with the forged UDP packet and IPv6.
 */
tree_cell *
set_udp_v6_elements (lex_ctxt *lexic)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "udp");
  unsigned int sz = get_var_size_by_name (lexic, "udp");
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = get_var_size_by_name (lexic, "data");

  if (ip6 != NULL)
    {
      char *pkt;
      struct udphdr *udp;
      tree_cell *retc;
      int old_len;

      if (40 + sizeof (struct udphdr) > sz)
        {
          return NULL;
        }
      if (data != NULL)
        {
          sz = 40 + sizeof (struct udphdr) + data_len;
          pkt = g_malloc0 (sz);
          bcopy (ip6, pkt, 40 + sizeof (struct udphdr));
        }
      else
        {
          pkt = g_malloc0 (sz);
          bcopy (ip6, pkt, sz);
        }

      ip6 = (struct ip6_hdr *) pkt;
      if (data != NULL)
        {
          ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX (sz - 40);
        }
      udp = (struct udphdr *) (pkt + 40);

      udp->uh_sport =
        htons (get_int_var_by_name (lexic, "uh_sport", ntohs (udp->uh_sport)));
      udp->uh_dport =
        htons (get_int_var_by_name (lexic, "uh_dport", ntohs (udp->uh_dport)));

      old_len = ntohs (udp->uh_ulen);
      udp->uh_ulen =
        htons (get_int_var_by_name (lexic, "uh_ulen", ntohs (udp->uh_ulen)));
      udp->uh_sum = get_int_var_by_name (lexic, "uh_sum", 0);

      if (data != NULL)
        {
          bcopy (data, pkt + 40 + sizeof (struct udphdr), data_len);
          udp->uh_ulen = htons (sizeof (struct udphdr) + data_len);
        }

      if (!udp->uh_sum)
        {
          struct v6pseudo_udp_hdr pseudohdr;
          int len = old_len - sizeof (struct udphdr);
          char *udpsumdata;
          char *ptr = NULL;

          if (data != NULL)
            {
              len = data_len;
            }

          if (len > 0)
            {
              ptr = (char *) udp + sizeof (struct udphdr);
            }

          udpsumdata = g_malloc0 (sizeof (struct v6pseudo_udp_hdr) + len + 1);
          bzero (&pseudohdr, sizeof (struct v6pseudo_udp_hdr));

          pseudohdr.proto = IPPROTO_UDP;
          pseudohdr.len = htons (sizeof (struct udphdr) + data_len);
          bcopy ((char *) udp, (char *) &pseudohdr.udpheader,
                 sizeof (struct udphdr));
          memcpy (&pseudohdr.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
          memcpy (&pseudohdr.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));
          bcopy ((char *) &pseudohdr, udpsumdata, sizeof (pseudohdr));
          if (ptr != NULL)
            {
              bcopy ((char *) ptr, udpsumdata + sizeof (pseudohdr), data_len);
            }
          udp->uh_sum = np_in_cksum ((unsigned short *) udpsumdata,
                                     38 + sizeof (struct udphdr)
                                       + ((len % 2) ? len + 1 : len));
          g_free (udpsumdata);
        }
      retc = alloc_typed_cell (CONST_DATA);
      retc->size = sz;
      retc->x.str_val = pkt;
      return retc;
    }
  else
    nasl_perror (lexic,
                 "set_udp_v6_elements: You must supply the 'udp' argument !\n");

  return NULL;
}

/*
 * @brief Print UDP part of IPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 * @param[in] ...   IPv6 datagrams to dump.
 *
 * @return Print and return FAKE_CELL.
 */
tree_cell *
dump_udp_v6_packet (lex_ctxt *lexic)
{
  int i = 0;
  u_char *pkt;
  while ((pkt = (u_char *) get_str_var_by_num (lexic, i++)) != NULL)
    {
      struct udphdr *udp = (struct udphdr *) (pkt + sizeof (struct ip6_hdr));
      unsigned int j;
      char *c;
      unsigned int limit = get_var_size_by_num (lexic, i - 1);
      printf ("------\n");
      printf ("\tuh_sport : %d\n", ntohs (udp->uh_sport));
      printf ("\tuh_dport : %d\n", ntohs (udp->uh_dport));
      printf ("\tuh_sum   : 0x%x\n", udp->uh_sum);
      printf ("\tuh_ulen  : %d\n", ntohs (udp->uh_ulen));
      printf ("\tdata     : ");
      c = (char *) udp;
      if (udp->uh_ulen > sizeof (struct udphdr))
        for (j = sizeof (struct udphdr); j < ntohs (udp->uh_ulen) && j < limit;
             j++)
          printf ("%c", isprint (c[j]) ? c[j] : '.');

      printf ("\n");
    }
  return NULL;
}

/*--------------[  ICMP  ]--------------------------------------------*/
/*
 * @brief ICMPv6 header.
 */

struct v6pseudo_icmp_hdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  unsigned short len;
  unsigned char zero1;
  unsigned char zero2;
  unsigned char zero3;
  char proto;
  struct icmp6_hdr icmpheader;
};

/*
 * @brief Forge ICMPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 * @param[in] ip6               IPv6 datagram to add ICMP header to.
 * @param[in] data              Payload.
 * @param[in] icmp_type         0 by default.
 * @param[in] icmp_code         0 by default.
 * @param[in] icmp_id           0 by default.
 * @param[in] icmp_seq
 * @param[in] reachable_time
 * @param[in] retransmit_timer
 * @param[in] flags
 * @param[in] target
 * @param[in] update_ip_len
 * @param[in] icmp_cksum
 *
 * @return tree_cell with the forged ICMPv6 packet containing IPv6 header.
 */
tree_cell *
forge_icmp_v6_packet (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct ip6_hdr *ip6;
  struct ip6_hdr *ip6_icmp;
  int ip6_sz, size = 0, sz = 0;
  struct icmp6_hdr *icmp;
  struct nd_router_solicit *routersolicit = NULL;
  struct nd_router_advert *routeradvert = NULL;
  struct nd_neighbor_solicit *neighborsolicit = NULL;
  struct nd_neighbor_advert *neighboradvert = NULL;

  char *data, *p;
  int len;
  u_char *pkt;
  int t;
  ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");
  ip6_sz = get_var_size_by_name (lexic, "ip6");

  if (ip6 != NULL)
    {
      retc = alloc_typed_cell (CONST_DATA);
      data = get_str_var_by_name (lexic, "data");
      len = data == NULL ? 0 : get_var_size_by_name (lexic, "data");
      t = get_int_var_by_name (lexic, "icmp_type", 0);
      if (40 > ip6_sz)
        return NULL;

      /* ICMP header size is 8 */
      pkt = g_malloc0 (ip6_sz + 8 + len);
      ip6_icmp = (struct ip6_hdr *) pkt;

      bcopy (ip6, ip6_icmp, ip6_sz);
      p = (char *) (pkt + ip6_sz);
      icmp = (struct icmp6_hdr *) p;

      icmp->icmp6_code = get_int_var_by_name (lexic, "icmp_code", 0);
      icmp->icmp6_type = t;

      switch (t)
        {
        case ICMP6_ECHO_REQUEST:
          {
            if (data != NULL)
              bcopy (data, &(p[8]), len);
            icmp->icmp6_id = get_int_var_by_name (lexic, "icmp_id", 0);
            icmp->icmp6_seq = get_int_var_by_name (lexic, "icmp_seq", 0);
            size = ip6_sz + 8 + len;
            sz = 8;
          }
          break;
        case ND_ROUTER_SOLICIT:
          {
            pkt =
              g_realloc (pkt, ip6_sz + sizeof (struct nd_router_solicit) + len);
            p = (char *) (pkt + ip6_sz);
            // Update ip6_icmp because it gets used again below
            ip6_icmp = (struct ip6_hdr *) pkt;
            routersolicit = (struct nd_router_solicit *) p;
            ((struct icmp6_hdr *) routersolicit)->icmp6_type = icmp->icmp6_type;
            ((struct icmp6_hdr *) routersolicit)->icmp6_code = icmp->icmp6_code;
            ((struct icmp6_hdr *) routersolicit)->icmp6_cksum =
              icmp->icmp6_cksum;
            size = ip6_sz + sizeof (struct nd_router_solicit) + len;
            sz = 4; /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        case ND_ROUTER_ADVERT:
          {
            pkt =
              g_realloc (pkt, ip6_sz + sizeof (struct nd_router_advert) + len);
            p = (char *) (pkt + ip6_sz);
            // Update ip6_icmp because it gets used again below
            ip6_icmp = (struct ip6_hdr *) pkt;
            // Let routeradvert point to routeradvert location in pkt
            routeradvert = (struct nd_router_advert *) p;
            // Set icmp6 header members
            ((struct icmp6_hdr *) routeradvert)->icmp6_type = icmp->icmp6_type;
            ((struct icmp6_hdr *) routeradvert)->icmp6_code = icmp->icmp6_code;
            ((struct icmp6_hdr *) routeradvert)->icmp6_cksum =
              icmp->icmp6_cksum;
            routeradvert->nd_ra_reachable =
              get_int_var_by_name (lexic, "reachable_time", 0);
            routeradvert->nd_ra_retransmit =
              get_int_var_by_name (lexic, "retransmit_timer", 0);
            routeradvert->nd_ra_curhoplimit = ip6_icmp->ip6_hlim;
            routeradvert->nd_ra_flags_reserved =
              get_int_var_by_name (lexic, "flags", 0);
            size = ip6_sz + sizeof (struct nd_router_advert) + len;
            sz = 5; /*type-1 byte, code-1byte, cksum-2bytes, current
                       hoplimit-1byte */
          }
          break;
        case ND_NEIGHBOR_SOLICIT:
          {
            // Make room for nd_neighbor_solicit.nd_ns_target in packet
            pkt = g_realloc (pkt, ip6_sz + sizeof (struct nd_neighbor_solicit)
                                    + len);
            // Let p point to the start of nd_neighbor_solicit
            p = (char *) (pkt + ip6_sz);
            // Update ip6_icmp because it gets used again below
            ip6_icmp = (struct ip6_hdr *) pkt;
            // Fill in user date if provided
            if (data != NULL)
              memmove (&(p[8 + 16]), data, len);
            // Let neighborsolicit point to nd_neighbor_solicit location in pkt
            neighborsolicit = (struct nd_neighbor_solicit *) p;
            // Set icmp6 header members
            ((struct icmp6_hdr *) neighborsolicit)->icmp6_type =
              icmp->icmp6_type;
            ((struct icmp6_hdr *) neighborsolicit)->icmp6_code =
              icmp->icmp6_code;
            ((struct icmp6_hdr *) neighborsolicit)->icmp6_cksum =
              icmp->icmp6_cksum;
            // Set nd_ns_target
            memcpy (&neighborsolicit->nd_ns_target, &ip6_icmp->ip6_dst,
                    sizeof (struct in6_addr)); /*dst ip should be link local */
            size = ip6_sz + sizeof (struct nd_neighbor_solicit) + len;
            sz = 4; /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        case ND_NEIGHBOR_ADVERT:
          {
            pkt = g_realloc (pkt,
                             ip6_sz + sizeof (struct nd_neighbor_advert) + len);
            // Update ip6_icmp because it gets used again below
            ip6_icmp = (struct ip6_hdr *) pkt;
            p = (char *) (pkt + 40);
            neighboradvert = (struct nd_neighbor_advert *) p;
            // Set icmp6 header members
            ((struct icmp6_hdr *) neighboradvert)->icmp6_type =
              icmp->icmp6_type;
            ((struct icmp6_hdr *) neighboradvert)->icmp6_code =
              icmp->icmp6_code;
            ((struct icmp6_hdr *) neighboradvert)->icmp6_cksum =
              icmp->icmp6_cksum;
            neighboradvert->nd_na_flags_reserved =
              get_int_var_by_name (lexic, "flags", 0);
            if (neighboradvert->nd_na_flags_reserved & 0x00000020)
              memcpy (
                &neighboradvert->nd_na_target, &ip6_icmp->ip6_src,
                sizeof (struct in6_addr)); /*dst ip should be link local */
            else
              {
                if (get_var_size_by_name (lexic, "target") != 0)
                  inet_pton (AF_INET6, get_str_var_by_name (lexic, "target"),
                             &neighboradvert->nd_na_target);
                else
                  {
                    nasl_perror (lexic,
                                 "forge_icmp_v6_packet: missing 'target' "
                                 "parameter required for constructing response "
                                 "to a Neighbor Solicitation\n");
                    g_free (ip6_icmp);
                    return NULL;
                  }
              }
            size = ip6_sz + sizeof (struct nd_neighbor_advert) + len;
            sz = 4; /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        default:
          {
            if (t < 0 || t > 255)
              {
                nasl_perror (lexic, "forge_icmp_v6_packet: illegal type %d\n",
                             t);
              }
            else
              {
                if (data != NULL)
                  bcopy (data, &(p[8]), len);
                icmp->icmp6_id = get_int_var_by_name (lexic, "icmp_id", 0);
                icmp->icmp6_seq = get_int_var_by_name (lexic, "icmp_seq", 0);
                size = ip6_sz + 8 + len;
                sz = 8;
              }
          }
        }

      if (UNFIX (ip6_icmp->ip6_ctlun.ip6_un1.ip6_un1_plen) <= 40)
        {
          if (get_int_var_by_name (lexic, "update_ip_len", 1) != 0)
            {
              ip6_icmp->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX (size - ip6_sz);
            }
        }
      if (get_int_var_by_name (lexic, "icmp_cksum", -1) == -1)
        {
          struct v6pseudo_icmp_hdr pseudohdr;
          char *icmpsumdata =
            g_malloc0 (sizeof (struct v6pseudo_icmp_hdr) + len + 1);

          bzero (&pseudohdr, sizeof (struct v6pseudo_icmp_hdr));
          memcpy (&pseudohdr.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
          memcpy (&pseudohdr.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

          pseudohdr.proto = 0x3a; /*ICMPv6 */
          pseudohdr.len = htons (size - ip6_sz);
          bcopy ((char *) icmp, (char *) &pseudohdr.icmpheader, sz);
          bcopy ((char *) &pseudohdr, icmpsumdata, sizeof (pseudohdr));
          if (data != NULL)
            bcopy ((char *) data, icmpsumdata + sizeof (pseudohdr), len);
          icmp->icmp6_cksum =
            np_in_cksum ((unsigned short *) icmpsumdata, size);
          g_free (icmpsumdata);
        }
      else
        icmp->icmp6_cksum =
          htons (get_int_var_by_name (lexic, "icmp_cksum", 0));
      switch (t)
        {
        case ICMP6_ECHO_REQUEST:
          break;
        case ND_ROUTER_SOLICIT:
          {
            routersolicit->nd_rs_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_ROUTER_ADVERT:
          {
            routeradvert->nd_ra_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_NEIGHBOR_SOLICIT:
          {
            neighborsolicit->nd_ns_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_NEIGHBOR_ADVERT:
          {
            neighboradvert->nd_na_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        default:
          {
          }
        }

      retc->x.str_val = (char *) pkt;
      retc->size = size;
    }
  else
    nasl_perror (lexic, "forge_icmp_v6_packet: missing 'ip6' parameter\n");

  return retc;
}

/*
 * @brief Obtain ICMPv6 header element.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] icmp    IPV6 datagram.
 * @param[in] element One of 'icmp_code', 'icmp_type', 'icmp_cksum', 'icmp_id',
 * 'icmp_seq', 'data'
 *
 * @return tree_cell with the ICMPv6 header element.
 */
tree_cell *
get_icmp_v6_element (lex_ctxt *lexic)
{
  struct icmp6_hdr *icmp;
  char *p;

  if ((p = get_str_var_by_name (lexic, "icmp")) != NULL)
    {
      char *elem = get_str_var_by_name (lexic, "element");
      int value;
      tree_cell *retc;

      icmp = (struct icmp6_hdr *) (p + 40);

      if (elem == NULL)
        {
          nasl_perror (lexic, "%s: Missing 'element' argument\n", __func__);
          return NULL;
        }

      else if (!strcmp (elem, "icmp_code"))
        value = icmp->icmp6_code;
      else if (!strcmp (elem, "icmp_type"))
        value = icmp->icmp6_type;
      else if (!strcmp (elem, "icmp_cksum"))
        value = ntohs (icmp->icmp6_cksum);
      else if (!strcmp (elem, "icmp_id"))
        value = ntohs (icmp->icmp6_id);
      else if (!strcmp (elem, "icmp_seq"))
        value = ntohs (icmp->icmp6_seq);
      else if (!strcmp (elem, "data"))
        {
          retc = alloc_typed_cell (CONST_DATA);
          retc->size = get_var_size_by_name (lexic, "icmp") - 40 - 8;
          if (retc->size > 0)
            {
              retc->x.str_val = g_malloc0 (retc->size + 1);
              memcpy (retc->x.str_val, &(p[40 + 8]), retc->size + 1);
            }
          else
            {
              retc->x.str_val = NULL;
              retc->size = 0;
            }
          return retc;
        }
      else
        {
          nasl_perror (lexic, "%s: '%s' not a valid 'element' argument\n",
                       __func__, elem);
          return NULL;
        }

      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = value;
      return retc;
    }
  else
    nasl_perror (lexic, "%s: missing 'icmp' parameter\n", __func__);

  return NULL;
}

/**
 * @brief Dump the ICMP part of a IP Datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IP datagrams to dump the ICMP part from.
 */
tree_cell *
dump_icmp_v6_packet (lex_ctxt *lexic)
{
  int i = 0;
  u_char *pkt;
  while ((pkt = (u_char *) get_str_var_by_num (lexic, i++)) != NULL)
    {
      unsigned int j;
      unsigned int limit;
      char *c;
      struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
      struct icmp6_hdr *icmp;
      icmp = (struct icmp6_hdr *) (pkt + 40);
      limit = get_var_size_by_num (lexic, i - 1);
      printf ("------\n");
      printf ("\ticmp6_id    : %d\n", ntohs (icmp->icmp6_id));
      printf ("\ticmp6_code  : %d\n", icmp->icmp6_code);
      printf ("\ticmp6_type  : %u\n", icmp->icmp6_type);
      printf ("\ticmp6_seq   : %u\n", ntohs (icmp->icmp6_seq));
      printf ("\ticmp6_cksum : %d\n", ntohs (icmp->icmp6_cksum));
      printf ("\tData        : ");
      c = (char *) ((char *) icmp + sizeof (struct icmp6_hdr));
      if (UNFIX (ip6->ip6_plen) > (sizeof (struct icmp6_hdr)))
        for (j = 0;
             j < UNFIX (ip6->ip6_plen) - sizeof (struct icmp6_hdr) && j < limit;
             j++)
          printf ("%c", isprint (c[j]) ? c[j] : '.');
      printf ("\n");
    }
  return NULL;
}

/*--------------[  IGMP  ]--------------------------------------------*/
/*
 * @brief Forge v6 IGMP packet.
 */

struct igmp6_hdr
{
  unsigned char type;
  unsigned char code;
  unsigned short cksum;
  struct in6_addr group;
};

/*
 * @brief Forge IGMPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 * @param[in] ip6   IPv6 datagram.
 * @param[in] data
 * @param[in] type
 * @param[in] code
 * @param[in] group
 *
 * @return tree_cell with the forged IGMPv6 packet containing IPv6 header.
 */
tree_cell *
forge_igmp_v6_packet (lex_ctxt *lexic)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *) get_str_var_by_name (lexic, "ip6");

  if (ip6 != NULL)
    {
      char *data = get_str_var_by_name (lexic, "data");
      int len = data ? get_var_size_by_name (lexic, "data") : 0;
      u_char *pkt = g_malloc0 (sizeof (struct igmp6_hdr) + 40 + len);
      struct ip6_hdr *ip6_igmp = (struct ip6_hdr *) pkt;
      struct igmp6_hdr *igmp;
      char *p;
      char *grp;
      tree_cell *retc;
      int ipsz = get_var_size_by_name (lexic, "ip6");

      bcopy (ip6, ip6_igmp, ipsz);

      if (UNFIX (ip6_igmp->ip6_ctlun.ip6_un1.ip6_un1_plen) <= 40)
        {
          int v = get_int_var_by_name (lexic, "update_ip6_len", 1);
          if (v != 0)
            {
              ip6_igmp->ip6_ctlun.ip6_un1.ip6_un1_plen =
                FIX (40 + sizeof (struct igmp6_hdr) + len);
            }
        }
      p = (char *) (pkt + 40);
      igmp = (struct igmp6_hdr *) p;

      igmp->code = get_int_var_by_name (lexic, "code", 0);
      igmp->type = get_int_var_by_name (lexic, "type", 0);
      grp = get_str_var_by_name (lexic, "group");

      if (grp != NULL)
        {
          inet_pton (AF_INET6, grp, &igmp->group);
        }

      igmp->cksum = np_in_cksum ((u_short *) igmp, sizeof (struct igmp6_hdr));
      if (data != NULL)
        {
          char *ptmp = (char *) (pkt + 40 + sizeof (struct igmp6_hdr));
          bcopy (ptmp, data, len);
        }
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) pkt;
      retc->size = 40 + sizeof (struct igmp6_hdr) + len;
      return retc;
    }
  else
    nasl_perror (lexic, "forge_igmp_v6_packet: missing 'ip6' parameter\n");

  return NULL;
}

/**
 * @brief Performs TCP Connect to test if host is alive.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 * @param[in] port  Port to ping. Internal list of common ports is used as
 * default.
 *
 * @return tree_cell > 0 if host is alive, 0 otherwise.
 */
/*---------------------------------------------------------------------------*/
tree_cell *
nasl_tcp_v6_ping (lex_ctxt *lexic)
{
  int port;
  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  int soc;
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *destination = plug_get_host_ip (script_infos);
  struct in6_addr source;
  struct sockaddr_in6 soca;
  int flag = 0;
  unsigned int i = 0;
  int bpf;
  char filter[255];
  tree_cell *retc;
  int opt = 1;
  struct timeval tv;
  int len;

#define rnd_tcp_port() (rand () % 65535 + 1024)
  int sports[] = {0, 0, 0, 0, 0, 1023, 0, 0, 0,  0, 0,  0, 0, 0, 0,
                  0, 0, 0, 0, 0, 53,   0, 0, 20, 0, 25, 0, 0, 0};
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,   6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548,  5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080, 0};
  char addr[INET6_ADDRSTRLEN];

  if (!destination || (IN6_IS_ADDR_V4MAPPED (destination) == 1))
    return NULL;

  for (i = 0; i < sizeof (sports) / sizeof (int); i++)
    {
      if (sports[i] == 0)
        sports[i] = rnd_tcp_port ();
    }

  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;

  if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL, (char *) &opt, sizeof (opt))
      < 0)
    perror ("setsockopt");

  port = get_int_var_by_name (lexic, "port", -1);
  if (port == -1)
    port = plug_get_host_open_port (script_infos);
  if (v6_islocalhost (destination) > 0)
    source = *destination;
  else
    {
      bzero (&source, sizeof (source));
      v6_routethrough (destination, &source);
    }

  snprintf (filter, sizeof (filter), "ip6 and src host %s",
            inet_ntop (AF_INET6, destination, addr, sizeof (addr)));
  bpf = init_v6_capture_device (*destination, source, filter);

  if (v6_islocalhost (destination) != 0)
    flag++;
  else
    {
      unsigned int num_ports = sizeof (sports) / sizeof (int);
      for (i = 0; i < num_ports && !flag; i++)
        {
          bzero (packet, sizeof (packet));
          /* IPv6 */
          int version = 0x60, tc = 0, fl = 0;
          ip->ip6_ctlun.ip6_un1.ip6_un1_flow = version | tc | fl;
          ip->ip6_nxt = 0x06, ip->ip6_hlim = 0x40, ip->ip6_src = source;
          ip->ip6_dst = *destination;
          ip->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX (sizeof (struct tcphdr));

          /* TCP */
          tcp->th_sport = port ? htons (rnd_tcp_port ()) : htons (sports[i]);
          tcp->th_flags = TH_SYN;
          tcp->th_dport = port ? htons (port) : htons (ports[i]);
          tcp->th_seq = rand ();
          tcp->th_ack = 0;
          tcp->th_x2 = 0;
          tcp->th_off = 5;
          tcp->th_win = htons (512);
          tcp->th_urp = 0;
          tcp->th_sum = 0;

          /* CKsum */
          {
            struct v6pseudohdr pseudoheader;

            bzero (&pseudoheader, 38 + sizeof (struct tcphdr));
            memcpy (&pseudoheader.s6addr, &ip->ip6_src,
                    sizeof (struct in6_addr));
            memcpy (&pseudoheader.d6addr, &ip->ip6_dst,
                    sizeof (struct in6_addr));

            pseudoheader.protocol = IPPROTO_TCP;
            pseudoheader.length = htons (sizeof (struct tcphdr));
            bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
                   sizeof (struct tcphdr));
            tcp->th_sum = np_in_cksum ((unsigned short *) &pseudoheader,
                                       38 + sizeof (struct tcphdr));
          }

          bzero (&soca, sizeof (soca));
          soca.sin6_family = AF_INET6;
          soca.sin6_addr = ip->ip6_dst;
          if (sendto (soc, (const void *) ip,
                      sizeof (struct tcphdr) + sizeof (struct ip6_hdr), 0,
                      (struct sockaddr *) &soca, sizeof (struct sockaddr_in6))
              < 0)
            {
              close (soc);
              return NULL;
            }
          tv.tv_sec = 0;
          tv.tv_usec = 100000;
          if (bpf >= 0 && bpf_next_tv (bpf, &len, &tv))
            flag++;
        }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = flag;
  if (bpf >= 0)
    bpf_close (bpf);
  close (soc);
  return retc;
}

/**
 * @brief Send forged IPv6 Packets.
 *
 * @param[in] lexic           Lexical context of NASL interpreter.
 * @param[in] ...             IPv6 packets to send.
 * @param[in] length          Length of each packet by default.
 * @param[in] pcap_active     TRUE by default. Otherwise, NASL does not listen
 * for the answers.
 * @param[in] pcap_filter     BPF filter.
 * @param[in] pcap_timeout    Capture timeout. 5 by default.
 * @param[in] allow_multicast Default 0.
 *
 * @return tree_cell with the response to the sent packet.
 */
tree_cell *
nasl_send_v6packet (lex_ctxt *lexic)
{
  tree_cell *retc = FAKE_CELL;
  int bpf = -1;
  u_char *answer;
  int answer_sz;
  struct sockaddr_in6 sockaddr;
  char *ip = NULL;
  struct ip6_hdr *sip = NULL;
  int vi = 0, b = 0, len = 0;
  int soc;
  int use_pcap = get_int_var_by_name (lexic, "pcap_active", 1);
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  int dfl_len = get_int_var_by_name (lexic, "length", -1);
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dstip = plug_get_host_ip (script_infos);
  int opt_on = 1;
  char name[INET6_ADDRSTRLEN];
  int allow_multicast = 0;

  if (dstip == NULL || (IN6_IS_ADDR_V4MAPPED (dstip) == 1))
    return NULL;
  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;

  if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL, (char *) &opt_on,
                  sizeof (opt_on))
      < 0)
    perror ("setsockopt");
  while ((ip = get_str_var_by_num (lexic, vi)) != NULL)
    {
      allow_multicast = get_int_var_by_name (lexic, "allow_multicast", 0);
      int sz = get_var_size_by_num (lexic, vi);
      vi++;

      if ((unsigned int) sz < sizeof (struct ip6_hdr))
        {
          nasl_perror (lexic, "send_v6packet: packet is too short\n");
          continue;
        }

      sip = (struct ip6_hdr *) ip;
      if (use_pcap != 0 && bpf < 0)
        bpf = init_v6_capture_device (sip->ip6_dst, sip->ip6_src, filter);

      bzero (&sockaddr, sizeof (struct sockaddr_in6));
      sockaddr.sin6_family = AF_INET6;
      sockaddr.sin6_addr = sip->ip6_dst;

      if (allow_multicast)
        {
          struct sockaddr_in6 multicast;

          if (setsockopt (soc, SOL_SOCKET, SO_BROADCAST, &opt_on,
                          sizeof (opt_on))
              < 0)
            perror ("setsockopt ");

          bzero (&multicast, sizeof (struct sockaddr_in6));
          sockaddr.sin6_family = AF_INET6;
          inet_pton (AF_INET6, "ff02::1", &(multicast.sin6_addr));

          if (!IN6_ARE_ADDR_EQUAL (&sockaddr.sin6_addr, &multicast.sin6_addr))
            allow_multicast = 0;
        }

      if (dstip != NULL && !IN6_ARE_ADDR_EQUAL (&sockaddr.sin6_addr, dstip)
          && !allow_multicast)
        {
          char txt1[64], txt2[64];
          strncpy (
            txt1,
            inet_ntop (AF_INET6, &sockaddr.sin6_addr, name, INET6_ADDRSTRLEN),
            sizeof (txt1));
          txt1[sizeof (txt1) - 1] = '\0';
          strncpy (txt2, inet_ntop (AF_INET6, dstip, name, INET6_ADDRSTRLEN),
                   sizeof (txt2));
          txt2[sizeof (txt2) - 1] = '\0';
          nasl_perror (lexic,
                       "send_v6packet: malicious or buggy script is trying to "
                       "send packet to %s instead of designated target %s\n",
                       txt1, txt2);
          if (bpf >= 0)
            bpf_close (bpf);
          close (soc);
          return NULL;
        }

      if (dfl_len > 0 && dfl_len < sz)
        len = dfl_len;
      else
        len = sz;

      b = sendto (soc, (u_char *) ip, len, 0, (struct sockaddr *) &sockaddr,
                  sizeof (struct sockaddr_in6));
      /* if(b < 0) perror("sendto "); */
      if (b >= 0 && use_pcap != 0 && bpf >= 0)
        {
          if (v6_islocalhost (&sip->ip6_dst))
            {
              answer = (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
              while (
                answer != NULL
                && (!memcmp (answer, (char *) ip, sizeof (struct ip6_hdr))))
                {
                  g_free (answer);
                  answer =
                    (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
                }
            }
          else
            {
              answer = (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
            }
          if (answer)
            {
              retc = alloc_typed_cell (CONST_DATA);
              retc->x.str_val = (char *) answer;
              retc->size = answer_sz;
              break;
            }
        }
    }
  if (bpf >= 0)
    bpf_close (bpf);
  close (soc);
  return retc;
}
