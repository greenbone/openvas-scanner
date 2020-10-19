/* Based on work Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#include "nasl_packet_forgery.h"

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

#include <arpa/inet.h> /* for inet_aton */
#include <ctype.h>     /* for isprint */
#include <errno.h>     /* for errno */
#include <pcap.h>      /* for PCAP_ERRBUF_SIZE */
#include <stdlib.h>    /* for rand */
#include <string.h>    /* for bcopy */
#include <sys/time.h>  /* for gettimeofday */
#include <unistd.h>    /* for close */

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
static int np_in_cksum (p, n) u_short *p;
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

  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = (int) ~sum;                /* ones-complement, truncate */
  return (answer);
}

/*--------------[ IP ]--------------------------------------------*/

/**
 * @brief Forge an IP datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] data    Payload.
 * @param[in] ip_hl   IP header length in 32 bits words. 5 by default.
 * @param[in] ip_id   Datagram ID. Random by default.
 * @param[in] ip_len  Length of the datagram. 20 plus the length of the data
 * field by default.
 * @param[in] ip_off  Fragment offset in 64 bits words. 0 by default.
 * @param[in] ip_p    IP protocol. 0 by default.
 * @param[in] ip_src  Source address in ASCII. NASL will convert it into an
 * integer in network order.
 * @param[in] ip_dst  Destination address in ASCII. NASL will convert it into an
 * integer in network order. Uses the target ip of the current plugin by
 * default.
 * @param[in] ip_sum  Packet header checksum. It will be computed by default.
 * @param[in] ip_tos  Type of service field. 0 by default
 * @param[in] ip_ttl  Time To Live field. 64 by default.
 * @param[in] ip_v    IP version. 4 by default.
 *
 * @return The forged IP packet.
 */
tree_cell *
forge_ip_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct ip *pkt;
  char *s;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dst_addr;
  char *data;
  int data_len;

  dst_addr = plug_get_host_ip (script_infos);

  if (dst_addr == NULL || (IN6_IS_ADDR_V4MAPPED (dst_addr) != 1))
    {
      nasl_perror (lexic, "forge_ip_packet: No valid dst_addr could be "
                          "determined via call to plug_get_host_ip().\n");
      return NULL;
    }

  data = get_str_var_by_name (lexic, "data");
  data_len = get_var_size_by_name (lexic, "data");

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = sizeof (struct ip) + data_len;

  pkt = (struct ip *) g_malloc0 (sizeof (struct ip) + data_len);
  retc->x.str_val = (char *) pkt;

  pkt->ip_hl = get_int_var_by_name (lexic, "ip_hl", 5);
  pkt->ip_v = get_int_var_by_name (lexic, "ip_v", 4);
  pkt->ip_tos = get_int_var_by_name (lexic, "ip_tos", 0);
  /* pkt->ip_len = FIX(get_int_var_by_name(lexic, "ip_len", 20 + data_len)); */

  pkt->ip_len = FIX (20 + data_len);

  pkt->ip_id = htons (get_int_var_by_name (lexic, "ip_id", rand ()));
  pkt->ip_off = get_int_var_by_name (lexic, "ip_off", 0);
  pkt->ip_off = FIX (pkt->ip_off);
  pkt->ip_ttl = get_int_var_by_name (lexic, "ip_ttl", 64);
  pkt->ip_p = get_int_var_by_name (lexic, "ip_p", 0);
  pkt->ip_sum = htons (get_int_var_by_name (lexic, "ip_sum", 0));
  /* source */
  s = get_str_var_by_name (lexic, "ip_src");
  if (s != NULL)
    inet_aton (s, &pkt->ip_src);
  /* else this host address? */

  /* I know that this feature looks dangerous, but anybody can edit an IP
   * packet with the string functions */
  s = get_str_var_by_name (lexic, "ip_dst");
  if (s != NULL)
    inet_aton (s, &pkt->ip_dst);
  else
    pkt->ip_dst.s_addr = dst_addr->s6_addr32[3];

  if (data != NULL)
    {
      bcopy (data, retc->x.str_val + sizeof (struct ip), data_len);
    }

  if (!pkt->ip_sum)
    {
      if (get_int_var_by_name (lexic, "ip_sum", -1) < 0)
        pkt->ip_sum = np_in_cksum ((u_short *) pkt, sizeof (struct ip));
    }

  return retc;
}

/**
 * @brief Extracts a field from an IP datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] element Name of the field, e.g. "ip_len" or "ip_src".
 * @param[in] ip      IP datagram or fragment.
 *
 * @return  integer or a string, depending on the type of the element.
 */
tree_cell *
get_ip_element (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct ip *ip = (struct ip *) get_str_var_by_name (lexic, "ip");
  char *element = get_str_var_by_name (lexic, "element");
  char ret_ascii[32];
  int ret_int = 0;
  int flag = 0;

  if (ip == NULL)
    {
      nasl_perror (lexic, "get_ip_element: no valid 'ip' argument\n");
      return NULL;
    }

  if (element == NULL)
    {
      nasl_perror (lexic, "get_ip_element: no valid 'element' argument\n");
      return NULL;
    }

  if (!strcmp (element, "ip_v"))
    {
      ret_int = ip->ip_v;
      flag++;
    }
  else if (!strcmp (element, "ip_id"))
    {
      ret_int = UNFIX (ip->ip_id);
      flag++;
    }
  else if (!strcmp (element, "ip_hl"))
    {
      ret_int = ip->ip_hl;
      flag++;
    }
  else if (!strcmp (element, "ip_tos"))
    {
      ret_int = ip->ip_tos;
      flag++;
    }
  else if (!strcmp (element, "ip_len"))
    {
      ret_int = UNFIX (ip->ip_len);
      flag++;
    }
  else if (!strcmp (element, "ip_off"))
    {
      ret_int = UNFIX (ip->ip_off);
      flag++;
    }
  else if (!strcmp (element, "ip_ttl"))
    {
      ret_int = ip->ip_ttl;
      flag++;
    }
  else if (!strcmp (element, "ip_p"))
    {
      ret_int = ip->ip_p;
      flag++;
    }
  else if (!strcmp (element, "ip_sum"))
    {
      ret_int = UNFIX (ip->ip_sum);
      flag++;
    }

  if (flag != 0)
    {
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = ret_int;
      return retc;
    }

  if (!strcmp (element, "ip_src"))
    {
      snprintf (ret_ascii, sizeof (ret_ascii), "%s", inet_ntoa (ip->ip_src));
      flag++;
    }
  else if (!strcmp (element, "ip_dst"))
    {
      snprintf (ret_ascii, sizeof (ret_ascii), "%s", inet_ntoa (ip->ip_dst));
      flag++;
    }

  if (flag == 0)
    {
      nasl_perror (lexic, "%s: unknown element '%s'\n", __func__, element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (ret_ascii);
  retc->x.str_val = g_strdup (ret_ascii);

  return retc;
}

/**
 * @brief Modify the fields of a datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ip      IP datagram to set fields on.
 * @param[in] ip_hl   IP header length in 32 bits words. 5 by default.
 * @param[in] ip_id   Datagram ID. Random by default.
 * @param[in] ip_len  Length of the datagram. 20 plus the length of the data
 * field by default.
 * @param[in] ip_off  Fragment offset in 64 bits words. 0 by default.
 * @param[in] ip_p    IP protocol. 0 by default.
 * @param[in] ip_src  Source address in ASCII. NASL will convert it into an
 * integer in network order.
 * @param[in] ip_sum  Packet header checksum. It will be computed by default.
 * @param[in] ip_tos  Type of service field. 0 by default
 * @param[in] ip_ttl  Time To Live field. 64 by default.
 * @param[in] ip_v    IP version. 4 by default.
 *
 * @return The modified IP datagram.
 */
tree_cell *
set_ip_elements (lex_ctxt *lexic)
{
  struct ip *o_pkt = (struct ip *) get_str_var_by_name (lexic, "ip");
  int size = get_var_size_by_name (lexic, "ip");
  tree_cell *retc;
  struct ip *pkt;
  char *s;

  if (o_pkt == NULL)
    {
      nasl_perror (lexic, "set_ip_elements: missing <ip> field\n");
      return NULL;
    }

  pkt = (struct ip *) g_malloc0 (size);
  bcopy (o_pkt, pkt, size);

  pkt->ip_hl = get_int_var_by_name (lexic, "ip_hl", pkt->ip_hl);
  pkt->ip_v = get_int_var_by_name (lexic, "ip_v", pkt->ip_v);
  pkt->ip_tos = get_int_var_by_name (lexic, "ip_tos", pkt->ip_tos);
  pkt->ip_len =
    FIX (get_int_var_by_name (lexic, "ip_len", UNFIX (pkt->ip_len)));
  pkt->ip_id = htons (get_int_var_by_name (lexic, "ip_id", pkt->ip_id));
  pkt->ip_off =
    FIX (get_int_var_by_name (lexic, "ip_off", UNFIX (pkt->ip_off)));
  pkt->ip_ttl = get_int_var_by_name (lexic, "ip_ttl", pkt->ip_ttl);
  pkt->ip_p = get_int_var_by_name (lexic, "ip_p", pkt->ip_p);

  s = get_str_var_by_name (lexic, "ip_src");
  if (s != NULL)
    inet_aton (s, &pkt->ip_src);

  pkt->ip_sum = htons (get_int_var_by_name (lexic, "ip_sum", 0));
  if (pkt->ip_sum == 0)
    pkt->ip_sum = np_in_cksum ((u_short *) pkt, sizeof (struct ip));

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = size;
  retc->x.str_val = (char *) pkt;

  return retc;
}

/**
 * @brief Add option datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ip      IP datagram to add the option to.
 * @param[in] code    Number of the option.
 * @param[in] length  Length of the option data.
 * @param[in] value   Option data.
 *
 * @return The modified IP datagram.
 */
tree_cell *
insert_ip_options (lex_ctxt *lexic)
{
  struct ip *ip = (struct ip *) get_str_var_by_name (lexic, "ip");
  int code = get_int_var_by_name (lexic, "code", 0);
  int len = get_int_var_by_name (lexic, "length", 0);
  char *value = get_str_var_by_name (lexic, "value");
  int value_size = get_var_size_by_name (lexic, "value");
  tree_cell *retc;
  struct ip *new_packet;
  char *p;
  int size = get_var_size_by_name (lexic, "ip");
  u_char uc_code, uc_len;
  int pad_len;
  char zero = '0';
  int i;
  int hl;

  if (ip == NULL)
    {
      nasl_perror (lexic, "Usage : insert_ip_options(ip:<ip>, code:<code>, "
                          "length:<len>, value:<value>\n");
      return NULL;
    }

  pad_len = 4 - ((sizeof (uc_code) + sizeof (uc_len) + value_size) % 4);
  if (pad_len == 4)
    pad_len = 0;

  hl = ip->ip_hl * 4 < UNFIX (ip->ip_len) ? ip->ip_hl * 4 : UNFIX (ip->ip_len);
  new_packet = g_malloc0 (size + 4 + value_size + pad_len);
  bcopy (ip, new_packet, hl);

  uc_code = (u_char) code;
  uc_len = (u_char) len;

  p = (char *) new_packet;
  bcopy (&uc_code, p + hl, sizeof (uc_code));
  bcopy (&uc_len, p + hl + sizeof (uc_code), sizeof (uc_len));
  bcopy (value, p + hl + sizeof (uc_code) + sizeof (uc_len), value_size);

  zero = 0;
  for (i = 0; i < pad_len; i++)
    {
      bcopy (&zero,
             p + hl + sizeof (uc_code) + sizeof (uc_len) + value_size + i, 1);
    }

  p = (char *) ip;
  bcopy (p + hl,
         new_packet
           + (sizeof (uc_code) + sizeof (uc_len) + value_size + pad_len) + hl,
         size - hl);

  new_packet->ip_hl =
    (hl + (sizeof (uc_code) + sizeof (uc_len) + value_size + pad_len)) / 4;
  new_packet->ip_len =
    FIX (size + sizeof (uc_code) + sizeof (uc_len) + value_size + pad_len);
  new_packet->ip_sum = 0;
  new_packet->ip_sum = np_in_cksum (
    (u_short *) new_packet, new_packet->ip_hl * 4 > UNFIX (new_packet->ip_len)
                              ? UNFIX (new_packet->ip_len)
                              : new_packet->ip_hl * 4);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = size + value_size + sizeof (uc_code) + sizeof (uc_len) + pad_len;
  retc->x.str_val = (char *) new_packet;

  return retc;
}

/**
 * @brief Dump IP datagrams.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IP datagrams to dump.
 */
tree_cell *
dump_ip_packet (lex_ctxt *lexic)
{
  int i;

  for (i = 0;; i++)
    {
      struct ip *ip = (struct ip *) get_str_var_by_num (lexic, i);
      if (ip == NULL)
        break;
      else
        {
          printf ("------\n");
          printf ("\tip_hl  : %d\n", ip->ip_hl);
          printf ("\tip_v   : %d\n", ip->ip_v);
          printf ("\tip_tos : %d\n", ip->ip_tos);
          printf ("\tip_len : %d\n", UNFIX (ip->ip_len));
          printf ("\tip_id  : %d\n", ntohs (ip->ip_id));
          printf ("\tip_off : %d\n", UNFIX (ip->ip_off));
          printf ("\tip_ttl : %d\n", ip->ip_ttl);
          switch (ip->ip_p)
            {
            case IPPROTO_TCP:
              printf ("\tip_p   : IPPROTO_TCP (%d)\n", ip->ip_p);
              break;
            case IPPROTO_UDP:
              printf ("\tip_p   : IPPROTO_UDP (%d)\n", ip->ip_p);
              break;
            case IPPROTO_ICMP:
              printf ("\tip_p   : IPPROTO_ICMP (%d)\n", ip->ip_p);
              break;
            default:
              printf ("\tip_p   : %d\n", ip->ip_p);
              break;
            }
          printf ("\tip_sum : 0x%x\n", ntohs (ip->ip_sum));
          printf ("\tip_src : %s\n", inet_ntoa (ip->ip_src));
          printf ("\tip_dst : %s\n", inet_ntoa (ip->ip_dst));
          printf ("\n");
        }
    }

  return FAKE_CELL;
}

/*--------------[ 	TCP 	]--------------------------------------------*/

struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcphdr tcpheader;
};

/**
 * @brief Fills an IP datagram with TCP data. Note that the ip_p field is not
 updated. It returns the modified IP datagram. Its arguments are:

 * @param[in] ip        IP datagram to be filled.
 * @param[in] data      TCP data payload.
 * @param[in] th_ack    Acknowledge number. NASL will convert it into network
 order if necessary. 0 by default.
 * @param[in] th_dport  Destination port. NASL will convert it into network
 order if necessary. 0 by default.
 * @param[in] th_flags  TCP flags. 0 by default.
 * @param[in] th_off    Size of the TCP header in 32 bits words. By default, 5.
 * @param[in] th_seq    TCP sequence number. NASL will convert it into network
 order if necessary. Random by default.
 * @param[in] th_sport  Source port. NASL will convert it into network order if
 necessary. 0 by default.
 * @param[in] th_sum    TCP checksum. Right value is computed by default.
 * @param[in] th_urp    Urgent pointer. 0 by default.
 * @param[in] th_win    TCP window size. NASL will convert it into network order
 if necessary. 0 by default.
 * @param[in] th_x2           Is a reserved field and should probably be left
 unchanged. 0 by default.
 * @param[in] update_ip_len   Flag (TRUE by default). If set, NASL will
 recompute the size field of the IP datagram.
 *
 * @return Modified IP datagram.
 */
tree_cell *
forge_tcp_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *data;
  int len;
  struct ip *ip, *tcp_packet;
  struct tcphdr *tcp;
  int ipsz;

  ip = (struct ip *) get_str_var_by_name (lexic, "ip");
  if (ip == NULL)
    {
      nasl_perror (lexic,
                   "forge_tcp_packet: You must supply the 'ip' argument\n");
      return NULL;
    }

  ipsz = get_var_size_by_name (lexic, "ip");
  if (ipsz > ip->ip_hl * 4)
    ipsz = ip->ip_hl * 4;

  data = get_str_var_by_name (lexic, "data");
  len = data == NULL ? 0 : get_var_size_by_name (lexic, "data");

  retc = alloc_typed_cell (CONST_DATA);
  tcp_packet = (struct ip *) g_malloc0 (ipsz + sizeof (struct tcphdr) + len);
  retc->x.str_val = (char *) tcp_packet;

  bcopy (ip, tcp_packet, ipsz);
  /* recompute the ip checksum, because the ip length changed */
  if (UNFIX (tcp_packet->ip_len) <= tcp_packet->ip_hl * 4)
    {
      if (get_int_var_by_name (lexic, "update_ip_len", 1))
        {
          tcp_packet->ip_len =
            FIX (tcp_packet->ip_hl * 4 + sizeof (struct tcphdr) + len);
          tcp_packet->ip_sum = 0;
          tcp_packet->ip_sum =
            np_in_cksum ((u_short *) tcp_packet, sizeof (struct ip));
        }
    }
  tcp = (struct tcphdr *) ((char *) tcp_packet + tcp_packet->ip_hl * 4);

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
      struct pseudohdr pseudoheader;
      char *tcpsumdata = g_malloc0 (sizeof (struct pseudohdr) + len + 1);
      struct in_addr source, dest;

      source.s_addr = ip->ip_src.s_addr;
      dest.s_addr = ip->ip_dst.s_addr;

      bzero (&pseudoheader, 12 + sizeof (struct tcphdr));
      pseudoheader.saddr.s_addr = source.s_addr;
      pseudoheader.daddr.s_addr = dest.s_addr;

      pseudoheader.protocol = IPPROTO_TCP;
      pseudoheader.length = htons (sizeof (struct tcphdr) + len);
      bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
             sizeof (struct tcphdr));
      /* fill tcpsumdata with data to checksum */
      bcopy ((char *) &pseudoheader, tcpsumdata, sizeof (struct pseudohdr));
      if (data != NULL)
        bcopy ((char *) data, tcpsumdata + sizeof (struct pseudohdr), len);
      tcp->th_sum = np_in_cksum ((unsigned short *) tcpsumdata,
                                 12 + sizeof (struct tcphdr) + len);
      g_free (tcpsumdata);
    }

  retc->size = ipsz + sizeof (struct tcphdr) + len;
  return retc;
}

/**
 * @brief Extracts TCP field from an IP datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] element Name of the the TCP field. See forge_tcp_packet().
 * @param[in] tcp     The full IP datagram (IP + TCP).
 *
 * @return  Data block or an integer, according to the type of the element.
 */
tree_cell *
get_tcp_element (lex_ctxt *lexic)
{
  u_char *packet = (u_char *) get_str_var_by_name (lexic, "tcp");
  struct ip *ip;
  int ipsz;
  struct tcphdr *tcp;
  char *element;
  int ret;
  tree_cell *retc;

  ipsz = get_var_size_by_name (lexic, "tcp");

  if (packet == NULL)
    {
      nasl_perror (lexic, "get_tcp_element: No valid 'tcp' argument\n");
      return NULL;
    }

  ip = (struct ip *) packet;

  if (ip->ip_hl * 4 > ipsz)
    return NULL; /* Invalid packet */

  if (UNFIX (ip->ip_len) > ipsz)
    return NULL; /* Invalid packet */

  tcp = (struct tcphdr *) (packet + ip->ip_hl * 4);

  element = get_str_var_by_name (lexic, "element");
  if (!element)
    {
      nasl_perror (lexic, "get_tcp_element: No valid 'element' argument\n");
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
      retc->size = UNFIX (ip->ip_len) - (tcp->th_off + ip->ip_hl) * 4;
      retc->x.str_val = g_malloc0 (retc->size);
      bcopy ((char *) tcp + tcp->th_off * 4, retc->x.str_val, retc->size);
      return retc;
    }
  else
    {
      nasl_perror (lexic, "get_tcp_element: Unknown tcp field %s\n", element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/**
 * @brief Modify the TCP fields of a datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] tcp       IP datagram.
 * @param[in] data      TCP data payload.
 * @param[in] th_ack    Acknowledge number. NASL will convert it into network
 * order if necessary.
 * @param[in] th_dport  Destination port. NASL will convert it into network
 * order if necessary.
 * @param[in] th_flags  TCP flags.
 * @param[in] th_off    Size of the TCP header in 32 bits words.
 * @param[in] th_seq    TCP sequence number. NASL will convert it into network
 * order if necessary.
 * @param[in] th_sport  Source port. NASL will convert it into network order
 * if necessary.
 * @param[in] th_sum    TCP checksum.
 * @param[in] th_urp    Urgent pointer.
 * @param[in] th_win    TCP window size. NASL will convert it into network
 * order if necessary.
 * @param[in] th_x2           Is a reserved field and should probably be left
 * unchanged.
 * @param[in] update_ip_len   Flag (TRUE by default). If set, NASL will
 * recompute the size field of the IP datagram.
 *
 * @return The modified IP datagram.
 */
tree_cell *
set_tcp_elements (lex_ctxt *lexic)
{
  char *pkt = get_str_var_by_name (lexic, "tcp");
  struct ip *ip = (struct ip *) pkt;
  int pktsz = get_var_size_by_name (lexic, "tcp");
  struct tcphdr *tcp;
  tree_cell *retc;
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = get_var_size_by_name (lexic, "data");
  char *npkt;

  if (!ip)
    {
      nasl_perror (lexic,
                   "set_tcp_elements: Invalid value for the argument 'tcp'\n");
      return NULL;
    }

  if (ip->ip_hl * 4 > pktsz)
    tcp =
      (struct tcphdr *) (pkt
                         + 20); /* ip->ip_hl is bogus, we work around that */
  else
    tcp = (struct tcphdr *) (pkt + ip->ip_hl * 4);

  if (pktsz < UNFIX (ip->ip_len))
    return NULL;

  if (data_len == 0)
    {
      data_len = UNFIX (ip->ip_len) - (ip->ip_hl * 4) - (tcp->th_off * 4);
      data = (char *) ((char *) tcp + tcp->th_off * 4);
    }

  npkt = g_malloc0 (ip->ip_hl * 4 + tcp->th_off * 4 + data_len);
  bcopy (pkt, npkt, UNFIX (ip->ip_len));

  ip = (struct ip *) (npkt);
  tcp = (struct tcphdr *) (npkt + ip->ip_hl * 4);

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
      ip->ip_len = ip->ip_hl * 4 + tcp->th_off * 4 + data_len;
      ip->ip_sum = 0;
      ip->ip_sum = np_in_cksum ((u_short *) pkt, ip->ip_hl * 4);
    }

  if (tcp->th_sum == 0)
    {
      struct pseudohdr pseudoheader;
      char *tcpsumdata = g_malloc0 (sizeof (struct pseudohdr) + data_len + 1);
      struct in_addr source, dest;

      source.s_addr = ip->ip_src.s_addr;
      dest.s_addr = ip->ip_dst.s_addr;

      bzero (&pseudoheader, sizeof (pseudoheader));
      pseudoheader.saddr.s_addr = source.s_addr;
      pseudoheader.daddr.s_addr = dest.s_addr;

      pseudoheader.protocol = IPPROTO_TCP;
      pseudoheader.length = htons (sizeof (struct tcphdr) + data_len);
      bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
             sizeof (struct tcphdr));
      /* fill tcpsumdata with data to checksum */
      bcopy ((char *) &pseudoheader, tcpsumdata, sizeof (struct pseudohdr));
      bcopy ((char *) data, tcpsumdata + sizeof (struct pseudohdr), data_len);
      tcp->th_sum = np_in_cksum ((unsigned short *) tcpsumdata,
                                 sizeof (pseudoheader) + data_len);
      g_free (tcpsumdata);
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = (ip->ip_hl * 4) + (tcp->th_off * 4) + data_len;
  retc->x.str_val = npkt;
  return retc;
}

/**
 * @brief Dump the TCP part of a IP Datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IP datagrams to dump the TCP part from.
 */
tree_cell *
dump_tcp_packet (lex_ctxt *lexic)
{
  int i = 0;
  u_char *pkt;
  while ((pkt = (u_char *) get_str_var_by_num (lexic, i++)) != NULL)
    {
      int a = 0;
      struct ip *ip = (struct ip *) pkt;
      struct tcphdr *tcp = (struct tcphdr *) (pkt + ip->ip_hl * 4);
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
      printf ("\tth_sum   : 0x%x\n", ntohs (tcp->th_sum));
      printf ("\tth_urp   : %d\n", ntohs (tcp->th_urp));
      printf ("\tData     : ");
      c = (char *) ((char *) tcp + sizeof (struct tcphdr));
      if (UNFIX (ip->ip_len) > (sizeof (struct ip) + sizeof (struct tcphdr)))
        for (j = 0; j < UNFIX (ip->ip_len) - sizeof (struct ip)
                          - sizeof (struct tcphdr)
                    && j < limit;
             j++)
          printf ("%c", isprint (c[j]) ? c[j] : '.');
      printf ("\n");

      printf ("\n");
    }
  return NULL;
}

/*--------------[ 	UDP 	]--------------------------------------------*/
struct pseudo_udp_hdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  char zero;
  char proto;
  unsigned short len;
  struct udphdr udpheader;
};

/**
 * @brief Fills an IP datagram with UDP data. Note that the ip_p field is not
 updated. It returns the modified IP datagram. Its arguments are:

 * @param[in] ip            IP datagram to be filled.
 * @param[in] data          Payload.
 * @param[in] uh_dport      Destination port. NASL will convert it into network
 order if necessary. 0 by default.
 * @param[in] uh_sport      Source port. NASL will convert it into network order
 if necessary. 0 by default.
 * @param[in] uh_sum        UDP checksum. Although it is not compulsary, the
 right value is computed by default.
 * @param[in] uh_ulen       Data length. By default it is set to the length of
 the data argument plus the size of the UDP header.
 * @param[in] update_ip_len Flag (TRUE by default). If set, NASL will recompute
 the size field of the IP datagram.
 *
 * @return Modified IP datagram.
 */
tree_cell *
forge_udp_packet (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct ip *ip = (struct ip *) get_str_var_by_name (lexic, "ip");

  if (ip != NULL)
    {
      char *data = get_str_var_by_name (lexic, "data");
      int data_len = get_var_size_by_name (lexic, "data");
      u_char *pkt;
      struct ip *udp_packet;
      struct udphdr *udp;

      pkt = g_malloc0 (sizeof (struct udphdr) + ip->ip_hl * 4
                       + sizeof (struct udphdr) + data_len);

      udp_packet = (struct ip *) pkt;
      udp = (struct udphdr *) (pkt + ip->ip_hl * 4);

      udp->uh_sport = htons (get_int_var_by_name (lexic, "uh_sport", 0));
      udp->uh_dport = htons (get_int_var_by_name (lexic, "uh_dport", 0));
      udp->uh_ulen = htons (get_int_var_by_name (
        lexic, "uh_ulen", data_len + sizeof (struct udphdr)));

      /* printf("len : %d %s\n", len, data); */
      if (data_len != 0 && data != NULL)
        bcopy (data, (pkt + ip->ip_hl * 4 + sizeof (struct udphdr)), data_len);

      udp->uh_sum = get_int_var_by_name (lexic, "uh_sum", 0);
      bcopy ((char *) ip, pkt, ip->ip_hl * 4);
      if (udp->uh_sum == 0)
        {
          struct pseudo_udp_hdr pseudohdr;
          struct in_addr source, dest;
          char *udpsumdata =
            g_malloc0 (sizeof (struct pseudo_udp_hdr) + data_len + 1);

          source.s_addr = ip->ip_src.s_addr;
          dest.s_addr = ip->ip_dst.s_addr;

          bzero (&pseudohdr, sizeof (struct pseudo_udp_hdr));
          pseudohdr.saddr.s_addr = source.s_addr;
          pseudohdr.daddr.s_addr = dest.s_addr;

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
                                     12 + sizeof (struct udphdr) + data_len);
          g_free (udpsumdata);
        }

      if (UNFIX (udp_packet->ip_len) <= udp_packet->ip_hl * 4)
        {
          int v = get_int_var_by_name (lexic, "update_ip_len", 1);
          if (v != 0)
            {
              udp_packet->ip_len =
                FIX (ntohs (udp->uh_ulen) + (udp_packet->ip_hl * 4));
              udp_packet->ip_sum = 0;
              udp_packet->ip_sum =
                np_in_cksum ((u_short *) udp_packet, udp_packet->ip_hl * 4);
            }
        }

      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) pkt;
      retc->size = 8 + ip->ip_hl * 4 + data_len;
      return retc;
    }
  else
    nasl_perror (lexic,
                 "forge_udp_packet: Invalid value for the argument 'ip'\n");

  return NULL;
}

/**
 * @brief Get an UDP element from a IP datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] udp     The full IP datagram (IP + UDP).
 * @param[in] element Name of the UDP field (see forge_udp_packet()).
 *
 * @return  Data block or an integer, according to the type of the element.
 */
tree_cell *
get_udp_element (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *udp;
  char *element;
  struct ip *ip;
  unsigned int ipsz;
  struct udphdr *udphdr;
  int ret;

  udp = get_str_var_by_name (lexic, "udp");
  ipsz = get_var_size_by_name (lexic, "udp");

  element = get_str_var_by_name (lexic, "element");
  if (udp == NULL || element == NULL)
    {
      nasl_perror (lexic, "get_udp_element: usage :\nelement = "
                          "get_udp_element(udp:<udp>,element:<element>\n");
      return NULL;
    }
  ip = (struct ip *) udp;

  if (ip->ip_hl * 4 + sizeof (struct udphdr) > ipsz)
    return NULL;

  udphdr = (struct udphdr *) (udp + ip->ip_hl * 4);
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

      if (ntohs (udphdr->uh_ulen) - ip->ip_hl * 4 - sizeof (struct udphdr)
          > ipsz)
        sz = ipsz - ip->ip_hl * 4 - sizeof (struct udphdr);

      retc->x.str_val = g_malloc0 (sz);
      retc->size = sz;
      bcopy (udp + ip->ip_hl * 4 + sizeof (struct udphdr), retc->x.str_val, sz);
      return retc;
    }
  else
    {
      nasl_perror (lexic, "%s: '%s' is not a value of a udp packet\n", __func__,
                   element);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/**
 * @brief Modify UDP fields of an IP datagram.
 *
 * @param[in] udp   IP datagram to modify.
 * @param[in] data          Payload.
 * @param[in] uh_dport      Destination port. NASL will convert it into network
 * order if necessary.
 * @param[in] uh_sport      Source port. NASL will convert it into network order
 * if necessary.
 * @param[in] uh_sum        UDP checksum.
 * @param[in] uh_ulen       Data length.
 *
 * @return Modified IP datagram.
 */
tree_cell *
set_udp_elements (lex_ctxt *lexic)
{
  struct ip *ip = (struct ip *) get_str_var_by_name (lexic, "udp");
  unsigned int sz = get_var_size_by_name (lexic, "udp");
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = get_var_size_by_name (lexic, "data");

  if (ip != NULL)
    {
      char *pkt;
      struct udphdr *udp;
      tree_cell *retc;
      int old_len;

      if (ip->ip_hl * 4 + sizeof (struct udphdr) > sz)
        return NULL;

      if (data != NULL)
        {
          sz = ip->ip_hl * 4 + sizeof (struct udphdr) + data_len;
          pkt = g_malloc0 (sz);
          bcopy (ip, pkt, ip->ip_hl * 4 + sizeof (struct udphdr));
        }
      else
        {
          pkt = g_malloc0 (sz);
          bcopy (ip, pkt, sz);
        }

      ip = (struct ip *) pkt;
      if (data != NULL)
        {
          ip->ip_len = FIX (sz);
          ip->ip_sum = 0;
          ip->ip_sum = np_in_cksum ((u_short *) ip, ip->ip_hl * 4);
        }
      udp = (struct udphdr *) (pkt + ip->ip_hl * 4);

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
          bcopy (data, pkt + ip->ip_hl * 4 + sizeof (struct udphdr), data_len);
          udp->uh_ulen = htons (sizeof (struct udphdr) + data_len);
        }

      if (udp->uh_sum == 0)
        {
          struct pseudo_udp_hdr pseudohdr;
          struct in_addr source, dest;
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

          udpsumdata = g_malloc0 (sizeof (struct pseudo_udp_hdr) + len + 1);

          source.s_addr = ip->ip_src.s_addr;
          dest.s_addr = ip->ip_dst.s_addr;

          bzero (&pseudohdr, sizeof (struct pseudo_udp_hdr));
          pseudohdr.saddr.s_addr = source.s_addr;
          pseudohdr.daddr.s_addr = dest.s_addr;

          pseudohdr.proto = IPPROTO_UDP;
          pseudohdr.len = htons (sizeof (struct udphdr) + len);
          bcopy ((char *) udp, (char *) &pseudohdr.udpheader,
                 sizeof (struct udphdr));
          bcopy ((char *) &pseudohdr, udpsumdata, sizeof (pseudohdr));
          if (ptr != NULL)
            {
              bcopy ((char *) ptr, udpsumdata + sizeof (pseudohdr), len);
            }
          udp->uh_sum = np_in_cksum ((unsigned short *) udpsumdata,
                                     12 + sizeof (struct udphdr) + len);
          g_free (udpsumdata);
        }
      retc = alloc_typed_cell (CONST_DATA);
      retc->size = sz;
      retc->x.str_val = pkt;
      return retc;
    }
  else
    nasl_perror (lexic,
                 "set_udp_elements:  Invalid value for the argument 'udp'.");

  return NULL;
}

/**
 * @brief Dump the UDP part of a IP Datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] ...     IP datagrams to dump the UDP part from.
 */
tree_cell *
dump_udp_packet (lex_ctxt *lexic)
{
  int i = 0;
  u_char *pkt;
  while ((pkt = (u_char *) get_str_var_by_num (lexic, i++)) != NULL)
    {
      struct udphdr *udp = (struct udphdr *) (pkt + sizeof (struct ip));
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
        for (j = sizeof (struct udphdr);
             j < (ntohs (udp->uh_ulen)) && j < limit; j++)
          printf ("%c", isprint (c[j]) ? c[j] : '.');

      printf ("\n");
    }
  return NULL;
}

/*--------------[  ICMP  ]--------------------------------------------*/

/**
 * @brief Fill an IP datagram with ICMP data.
 *
 * @param[in] lexic         Lexical context of NASL interpreter.
 * @param[in] ip            IP datagram that is updated.
 * @param[in] data          Payload.
 * @param[in] icmp_cksum    Checksum, computed by default.
 * @param[in] icmp_code     ICMP code. 0 by default.
 * @param[in] icmp_id       ICMP ID. 0 by default.
 * @param[in] icmp_seq      ICMP sequence number.
 * @param[in] icmp_type     ICMP type. 0  * @param[in]  update_ip_len Flag (TRUE
 * by default). If set, NASL will recompute the size field of the IP datagram.
 *
 * @return Modified IP datagram.
 */
tree_cell *
forge_icmp_packet (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct ip *ip;
  struct ip *ip_icmp;
  int ip_sz;
  struct icmp *icmp;
  char *data, *p;
  int len;
  u_char *pkt;
  int t;

  ip = (struct ip *) get_str_var_by_name (lexic, "ip");
  ip_sz = get_var_size_by_name (lexic, "ip");
  if (ip != NULL)
    {
      data = get_str_var_by_name (lexic, "data");
      len = data == NULL ? 0 : get_var_size_by_name (lexic, "data");

      t = get_int_var_by_name (lexic, "icmp_type", 0);
      if (t == 13 || t == 14)
        len += 3 * sizeof (time_t);

      if (ip->ip_hl * 4 > ip_sz)
        return NULL;

      pkt = g_malloc0 (sizeof (struct icmp) + ip_sz + len);
      ip_icmp = (struct ip *) pkt;

      bcopy (ip, ip_icmp, ip_sz);
      if (UNFIX (ip_icmp->ip_len) <= (ip_icmp->ip_hl * 4))
        {
          if (get_int_var_by_name (lexic, "update_ip_len", 1) != 0)
            {
              ip_icmp->ip_len = FIX (ip->ip_hl * 4 + 8 + len);
              ip_icmp->ip_sum = 0;
              ip_icmp->ip_sum =
                np_in_cksum ((u_short *) ip_icmp, ip->ip_hl * 4);
            }
        }
      p = (char *) (pkt + (ip->ip_hl * 4));
      icmp = (struct icmp *) p;

      icmp->icmp_code = get_int_var_by_name (lexic, "icmp_code", 0);
      icmp->icmp_type = t;
      icmp->icmp_seq = htons (get_int_var_by_name (lexic, "icmp_seq", 0));
      icmp->icmp_id = htons (get_int_var_by_name (lexic, "icmp_id", 0));

      if (data != NULL)
        bcopy (data, &(p[8]), len);

      if (get_int_var_by_name (lexic, "icmp_cksum", -1) == -1)
        icmp->icmp_cksum = np_in_cksum ((u_short *) icmp, len + 8);
      else
        icmp->icmp_cksum = htons (get_int_var_by_name (lexic, "icmp_cksum", 0));

      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) pkt;
      retc->size = ip_sz + len + 8;
    }
  else
    nasl_perror (lexic, "forge_icmp_packet: missing 'ip' parameter\n");

  return retc;
}

/**
 * @brief Get an ICMP element from a IP datagram.
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] icmp    Full IP datagram (IP + ICMP).
 * @param[in] element Name of the TCP field (see forge_tcp_packet()).
 *
 * @return Data block or an integer, according to the type of the element.
 */
tree_cell *
get_icmp_element (lex_ctxt *lexic)
{
  struct icmp *icmp;
  char *p;

  if ((p = get_str_var_by_name (lexic, "icmp")) != NULL)
    {
      char *elem = get_str_var_by_name (lexic, "element");
      int value;
      struct ip *ip = (struct ip *) p;
      tree_cell *retc;

      icmp = (struct icmp *) (p + ip->ip_hl * 4);

      if (elem == NULL)
        {
          nasl_perror (lexic,
                       "get_icmp_element: missing 'element' parameter\n");
          return NULL;
        }

      if (!strcmp (elem, "icmp_id"))
        value = ntohs (icmp->icmp_id);
      else if (!strcmp (elem, "icmp_code"))
        value = icmp->icmp_code;
      else if (!strcmp (elem, "icmp_type"))
        value = icmp->icmp_type;
      else if (!strcmp (elem, "icmp_seq"))
        value = ntohs (icmp->icmp_seq);
      else if (!strcmp (elem, "icmp_cksum"))
        value = ntohs (icmp->icmp_cksum);
      else if (!strcmp (elem, "data"))
        {
          retc = alloc_typed_cell (CONST_DATA);
          retc->size =
            get_var_size_by_name (lexic, "icmp") - (ip->ip_hl * 4) - 8;
          if (retc->size > 0)
            retc->x.str_val =
              g_memdup (&(p[ip->ip_hl * 4 + 8]), retc->size + 1);
          else
            {
              retc->x.str_val = NULL;
              retc->size = 0;
            }
          return retc;
        }
      else
        {
          nasl_perror (
            lexic,
            "get_icmp_element: Element '%s' is not a valid element to get.\n",
            elem);
          return NULL;
        }

      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = value;
      return retc;
    }
  else
    nasl_perror (lexic, "get_icmp_element: missing 'icmp' parameter\n");

  return NULL;
}

/*--------------[  IGMP  ]--------------------------------------------*/

struct igmp
{
  unsigned char type;
  unsigned char code;
  unsigned short cksum;
  struct in_addr group;
};

/**
 * @brief Fills an IP datagram with IGMP data.
 *
 * @param[in] lexic         Lexical context of NASL interpreter.
 * @param[in] ip            IP datagram that is updated.
 * @param[in] code          0 by default.
 * @param[in] data
 * @param[in] group
 * @param[in] type          0 by default.
 * @param[in] update_ip_len Flag (TRUE by default). If set, NASL will recompute
 * the size field of the IP datagram.
 *
 * @return Modified IP datagram.
 */
tree_cell *
forge_igmp_packet (lex_ctxt *lexic)
{
  struct ip *ip = (struct ip *) get_str_var_by_name (lexic, "ip");

  if (ip != NULL)
    {
      char *data = get_str_var_by_name (lexic, "data");
      int len = data ? get_var_size_by_name (lexic, "data") : 0;
      u_char *pkt = g_malloc0 (sizeof (struct igmp) + ip->ip_hl * 4 + len);
      struct ip *ip_igmp = (struct ip *) pkt;
      struct igmp *igmp;
      char *p;
      char *grp;
      tree_cell *retc;
      int ipsz = get_var_size_by_name (lexic, "ip");

      bcopy (ip, ip_igmp, ipsz);

      if (UNFIX (ip_igmp->ip_len) <= ip_igmp->ip_hl * 4)
        {
          int v = get_int_var_by_name (lexic, "update_ip_len", 1);
          if (v != 0)
            {
              ip_igmp->ip_len =
                FIX (ip->ip_hl * 4 + sizeof (struct igmp) + len);
              ip_igmp->ip_sum = 0;
              ip_igmp->ip_sum =
                np_in_cksum ((u_short *) ip_igmp, ip->ip_hl * 4);
            }
        }
      p = (char *) (pkt + ip_igmp->ip_hl * 4);
      igmp = (struct igmp *) p;

      igmp->code = get_int_var_by_name (lexic, "code", 0);
      igmp->type = get_int_var_by_name (lexic, "type", 0);
      grp = get_str_var_by_name (lexic, "group");

      if (grp != NULL)
        {
          inet_aton (grp, &igmp->group);
        }

      igmp->cksum = np_in_cksum ((u_short *) igmp, sizeof (struct igmp));
      if (data != NULL)
        {
          char *p = (char *) (pkt + ip->ip_hl * 4 + sizeof (struct igmp));
          bcopy (p, data, len);
        }
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = (char *) pkt;
      retc->size = ip->ip_hl * 4 + sizeof (struct igmp) + len;
      return retc;
    }
  else
    nasl_perror (lexic, "forge_igmp_packet: missing 'ip' parameter\n");

  return NULL;
}

/*---------------------------------------------------------------------------*/

/**
 * @brief Lunches a “TCP ping” against the target host.
 *
 * Tries to open a TCP connection and sees if anything comes back (SYN/ACK or
 * RST).
 *
 * @param[in] lexic   Lexical context of NASL interpreter.
 * @param[in] port    Port to ping. Internal list of common ports is used as
 * default.
 *
 * @return 1 if Ping was successul, 0 else.
 */
tree_cell *
nasl_tcp_ping (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dst = plug_get_host_ip (script_infos);
  if (IN6_IS_ADDR_V4MAPPED (dst) != 1)
    {
      tree_cell *retc = nasl_tcp_v6_ping (lexic);
      return retc;
    }
  int port;
  u_char packet[sizeof (struct ip) + sizeof (struct tcphdr)];
  int soc;
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip));
  struct in_addr src;
  struct sockaddr_in soca;
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
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,  6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548, 5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080};
  struct in_addr inaddr;

  if (dst == NULL || (IN6_IS_ADDR_V4MAPPED (dst) != 1))
    return NULL;
  inaddr.s_addr = dst->s6_addr32[3];
  for (i = 0; i < sizeof (sports) / sizeof (int); i++)
    {
      if (sports[i] == 0)
        sports[i] = rnd_tcp_port ();
    }

  soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;
  if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt, sizeof (opt)) < 0)
    perror ("setsockopt ");

  port = get_int_var_by_name (lexic, "port", -1);
  if (port == -1)
    port = plug_get_host_open_port (script_infos);

  if (islocalhost (&inaddr) > 0)
    src.s_addr = dst->s6_addr32[3];
  else
    {
      bzero (&src, sizeof (src));
      routethrough (&inaddr, &src);
    }

  snprintf (filter, sizeof (filter), "ip and src host %s", inet_ntoa (inaddr));
  bpf = init_capture_device (inaddr, src, filter);

  if (islocalhost (&inaddr) != 0)
    flag++;
  else
    {
      for (i = 0; i < sizeof (sports) / sizeof (int) && !flag; i++)
        {
          bzero (packet, sizeof (packet));
          /* IP */
          ip->ip_hl = 5;
          ip->ip_off = FIX (0);
          ip->ip_v = 4;
          ip->ip_len = FIX (40);
          ip->ip_tos = 0;
          ip->ip_p = IPPROTO_TCP;
          ip->ip_id = rand ();
          ip->ip_ttl = 0x40;
          ip->ip_src = src;
          ip->ip_dst = inaddr;
          ip->ip_sum = 0;
          ip->ip_sum = np_in_cksum ((u_short *) ip, 20);

          /* TCP */
          tcp->th_sport = port ? htons (rnd_tcp_port ()) : htons (sports[i]);
          tcp->th_flags = TH_SYN;
          tcp->th_dport = port ? htons (port) : htons (ports[i]);
          tcp->th_seq = rand ();
          tcp->th_ack = 0;
          tcp->th_x2 = 0;
          tcp->th_off = 5;
          tcp->th_win = 2048;
          tcp->th_urp = 0;
          tcp->th_sum = 0;

          /* CKsum */
          {
            struct in_addr source, dest;
            struct pseudohdr pseudoheader;
            source.s_addr = ip->ip_src.s_addr;
            dest.s_addr = ip->ip_dst.s_addr;

            bzero (&pseudoheader, 12 + sizeof (struct tcphdr));
            pseudoheader.saddr.s_addr = source.s_addr;
            pseudoheader.daddr.s_addr = dest.s_addr;

            pseudoheader.protocol = 6;
            pseudoheader.length = htons (sizeof (struct tcphdr));
            bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
                   sizeof (struct tcphdr));
            tcp->th_sum = np_in_cksum ((unsigned short *) &pseudoheader,
                                       12 + sizeof (struct tcphdr));
          }

          bzero (&soca, sizeof (soca));
          soca.sin_family = AF_INET;
          soca.sin_addr = ip->ip_dst;
          if (sendto (soc, (const void *) ip, 40, 0, (struct sockaddr *) &soca,
                      sizeof (soca))
              < 0)
            g_warning ("sendto: %s", strerror (errno));
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

/*---------------------------------------------------------------------------*/

/**
 * @brief Send a list of packets (passed as unnamed arguments) and listens to
 * the answers. It returns a block made of all the sniffed “answers”.
 *
 * @param[in] lexic           Lexical context of NASL interpreter.
 * @param[in] ...             Packets to send.
 * @param[in] length          Length of each packet by default.
 * @param[in] pcap_active     TRUE by default. Otherwise, NASL does not listen
 * for the answers.
 * @param[in] pcap_filter     BPF filter.
 * @param[in] pcap_timeout    Capture timout. 5 by default.
 * @param[in] allow_broadcast Default 0.
 *
 * @return block made of all the sniffed “answers”.
 */
tree_cell *
nasl_send_packet (lex_ctxt *lexic)
{
  tree_cell *retc = FAKE_CELL;
  int bpf = -1;
  u_char *answer;
  int answer_sz;
  struct sockaddr_in sockaddr;
  char *ip = NULL;
  struct ip *sip = NULL;
  int vi = 0, b, len = 0;
  int soc;
  int use_pcap = get_int_var_by_name (lexic, "pcap_active", 1);
  int to = get_int_var_by_name (lexic, "pcap_timeout", 5);
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  int dfl_len = get_int_var_by_name (lexic, "length", -1);
  int opt_on = 1;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dstip = plug_get_host_ip (script_infos);
  struct in_addr inaddr;
  int allow_broadcast = 0;

  if (dstip == NULL || (IN6_IS_ADDR_V4MAPPED (dstip) != 1))
    return NULL;
  inaddr.s_addr = dstip->s6_addr32[3];
  soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;
  if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt_on,
                  sizeof (opt_on))
      < 0)
    perror ("setsockopt ");

  while ((ip = get_str_var_by_num (lexic, vi)) != NULL)
    {
      allow_broadcast = get_int_var_by_name (lexic, "allow_broadcast", 0);
      int sz = get_var_size_by_num (lexic, vi);
      vi++;

      if ((unsigned int) sz < sizeof (struct ip))
        {
          nasl_perror (lexic, "send_packet: packet is too short\n");
          continue;
        }

      sip = (struct ip *) ip;
      if (use_pcap != 0 && bpf < 0)
        bpf = init_capture_device (sip->ip_dst, sip->ip_src, filter);

      bzero (&sockaddr, sizeof (struct sockaddr_in));
      sockaddr.sin_family = AF_INET;
      sockaddr.sin_addr = sip->ip_dst;

      if (allow_broadcast)
        {
          if (setsockopt (soc, SOL_SOCKET, SO_BROADCAST, &opt_on,
                          sizeof (opt_on))
              < 0)
            perror ("setsockopt ");
          if (sockaddr.sin_addr.s_addr != INADDR_BROADCAST)
            allow_broadcast = 0;
        }

      if (sockaddr.sin_addr.s_addr != inaddr.s_addr && !allow_broadcast)
        {
          char txt1[64], txt2[64];
          strncpy (txt1, inet_ntoa (sockaddr.sin_addr), sizeof (txt1));
          txt1[sizeof (txt1) - 1] = '\0';
          strncpy (txt2, inet_ntoa (inaddr), sizeof (txt2));
          txt2[sizeof (txt2) - 1] = '\0';
          nasl_perror (lexic,
                       "send_packet: malicious or buggy script is trying to "
                       "send packet to %s instead of designated target %s\n",
                       txt1, txt2);
#if 1
          if (bpf >= 0)
            bpf_close (bpf);
          close (soc);
          return NULL;
#else
          sip->ip_dst = inaddr;
          sip->ip_sum = np_in_cksum ((u_short *) sip, sizeof (struct ip));
#endif
        }

      if (dfl_len > 0 && dfl_len < sz)
        len = dfl_len;
      else
        len = sz;

      b = sendto (soc, (u_char *) ip, len, 0, (struct sockaddr *) &sockaddr,
                  sizeof (sockaddr));
      /* if(b < 0) perror("sendto "); */
      if (b >= 0 && use_pcap != 0 && bpf >= 0)
        {
          if (islocalhost (&sip->ip_dst))
            {
              answer = (u_char *) capture_next_packet (bpf, to, &answer_sz);
              while (answer != NULL
                     && (!memcmp (answer, (char *) ip, sizeof (struct ip))))
                {
                  g_free (answer);
                  answer = (u_char *) capture_next_packet (bpf, to, &answer_sz);
                }
            }
          else
            answer = (u_char *) capture_next_packet (bpf, to, &answer_sz);

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

/*---------------------------------------------------------------------------*/

/**
 * @brief Listen to one packet and return it.
 *
 * @param[in] lexic         Lexical context of NASL interpreter.
 * @param[in] interface     Network interface name. By default, NASL will try to
 * find the best one.
 * @param[in] pcap_filter   BPF filter. By default, it listens to everything.
 * @param[in] timeout       5 seconds by default.
 *
 * @return Packet which was captured.
 */
tree_cell *
nasl_pcap_next (lex_ctxt *lexic)
{
  char *interface = get_str_var_by_name (lexic, "interface");
  int bpf = -1;
  static char errbuf[PCAP_ERRBUF_SIZE];
  int is_ip = 0;
  struct ip *ret = NULL;
  struct ip6_hdr *ret6 = NULL;
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  pcap_if_t *alldevsp = NULL; /* list of capture devices */
  int timeout = get_int_var_by_name (lexic, "timeout", 5);
  tree_cell *retc;
  int sz;
  struct in6_addr *dst = plug_get_host_ip (lexic->script_infos);
  struct in_addr inaddr;

  if (dst == NULL)
    {
      return NULL;
    }
  int v4_addr = IN6_IS_ADDR_V4MAPPED (dst);
  if (interface == NULL)
    {
      if (v4_addr)
        {
          struct in_addr src;
          bzero (&src, sizeof (src));
          inaddr.s_addr = dst->s6_addr32[3];
          interface = routethrough (&inaddr, &src);
        }
      else
        {
          struct in6_addr src;
          bzero (&src, sizeof (src));
          interface = v6_routethrough (dst, &src);
        }
      if (interface == NULL)
        {
          if (pcap_findalldevs (&alldevsp, errbuf) < 0)
            g_message ("Error for pcap_findalldevs(): %s", errbuf);
          if (alldevsp != NULL)
            interface = alldevsp->name;
        }
    }

  if (interface != NULL)
    {
      bpf = bpf_open_live (interface, filter);
    }

  if (bpf < 0)
    {
      nasl_perror (lexic, "pcap_next: Could not get a bpf\n");
      return NULL;
    }
  else
    {
      int len;
      int dl_len = get_datalink_size (bpf_datalink (bpf));
      char *packet;
      struct timeval then, now;

      gettimeofday (&then, NULL);
      for (;;)
        {
          packet = (char *) bpf_next (bpf, &len);

          if (packet != NULL)
            break;

          if (timeout != 0)
            {
              gettimeofday (&now, NULL);
              if (now.tv_sec - then.tv_sec >= timeout)
                {
                  break;
                }
            }
        }

      if (packet)
        {
          if (v4_addr)
            {
              struct ip *ip;
              ip = (struct ip *) (packet + dl_len);
              sz = UNFIX (ip->ip_len);
              ret = g_malloc0 (sz);

              is_ip = (ip->ip_v == 4);

              if (is_ip)
                {
                  bcopy (ip, ret, sz);
                }
              else
                {
                  sz = len - dl_len;
                  bcopy (ip, ret, sz);
                }
            }
          else
            {
              struct ip6_hdr *ip;
              ip = (struct ip6_hdr *) (packet + dl_len);
              sz = UNFIX (ip->ip6_plen);
              ret6 = g_malloc0 (sz);

              is_ip = ((ip->ip6_flow & 0x3ffff) == 96);
              if (is_ip)
                {
                  bcopy (ip, ret6, sz);
                }
              else
                {
                  sz = len - dl_len;
                  bcopy (ip, ret6, sz);
                }
            }
        }
      else
        {
          bpf_close (bpf);
          return NULL;
        }
    }
  bpf_close (bpf);
  retc = alloc_typed_cell (CONST_DATA);
  if (v4_addr)
    retc->x.str_val = (char *) ret;
  else
    retc->x.str_val = (char *) ret6;
  retc->size = sz;

  if (alldevsp != NULL)
    pcap_freealldevs (alldevsp);

  return retc;
}

/**
 * @brief Send a capture.
 *
 * @param[in] interface string
 * @param[in] pcap filter string
 * @param[in] timeout integer
 *
 * @return Packet which was captured.
 */
tree_cell *
nasl_send_capture (lex_ctxt *lexic)
{
  char *interface = get_str_var_by_name (lexic, "interface");
  int bpf = -1;
  static char errbuf[PCAP_ERRBUF_SIZE];
  int is_ip = 0;
  struct ip *ret = NULL;
  struct ip6_hdr *ret6 = NULL;
  char *filter = get_str_var_by_name (lexic, "pcap_filter");
  pcap_if_t *alldevsp = NULL; /* list of capture devices */
  int timeout = get_int_var_by_name (lexic, "timeout", 5);
  tree_cell *retc;
  int sz;
  struct in6_addr *dst = plug_get_host_ip (lexic->script_infos);
  struct in_addr inaddr;

  if (dst == NULL)
    return NULL;

  int v4_addr = IN6_IS_ADDR_V4MAPPED (dst);
  if (interface == NULL)
    {
      if (v4_addr)
        {
          struct in_addr src;
          bzero (&src, sizeof (src));
          inaddr.s_addr = dst->s6_addr32[3];
          interface = routethrough (&inaddr, &src);
        }
      else
        {
          struct in6_addr src;
          bzero (&src, sizeof (src));
          interface = v6_routethrough (dst, &src);
        }
      if (interface == NULL)
        {
          if (pcap_findalldevs (&alldevsp, errbuf) < 0)
            g_message ("Error for pcap_findalldevs(): %s", errbuf);
          if (alldevsp != NULL)
            interface = alldevsp->name;
        }
    }

  if (interface != NULL)
    bpf = bpf_open_live (interface, filter);

  if (bpf < 0)
    {
      nasl_perror (lexic, "pcap_next: Could not get a bpf\n");
      return NULL;
    }
  else
    {
      int len;
      int dl_len = get_datalink_size (bpf_datalink (bpf));
      char *packet;
      struct timeval then, now;

      retc = nasl_send (lexic);
      g_free (retc);

      gettimeofday (&then, NULL);
      for (;;)
        {
          packet = (char *) bpf_next (bpf, &len);

          if (packet != NULL)
            break;

          if (timeout != 0)
            {
              gettimeofday (&now, NULL);
              if (now.tv_sec - then.tv_sec >= timeout)
                break;
            }
        }

      if (packet)
        {
          if (v4_addr)
            {
              struct ip *ip;
              ip = (struct ip *) (packet + dl_len);
              sz = UNFIX (ip->ip_len);
              ret = g_malloc0 (sz);

              is_ip = (ip->ip_v == 4);
              if (is_ip)
                {
                  bcopy (ip, ret, sz);
                }
              else
                {
                  sz = len - dl_len;
                  bcopy (ip, ret, sz);
                }
            }
          else
            {
              struct ip6_hdr *ip;
              ip = (struct ip6_hdr *) (packet + dl_len);
              sz = UNFIX (ip->ip6_plen);
              ret6 = g_malloc0 (sz);
              is_ip = ((ip->ip6_flow & 0x3ffff) == 96);
              if (is_ip)
                {
                  bcopy (ip, ret6, sz);
                }
              else
                {
                  sz = len - dl_len;
                  bcopy (ip, ret6, sz);
                }
            }
        }
      else
        {
          bpf_close (bpf);
          return NULL;
        }
    }
  bpf_close (bpf);
  retc = alloc_typed_cell (CONST_DATA);
  if (v4_addr)
    retc->x.str_val = (char *) ret;
  else
    retc->x.str_val = (char *) ret6;
  retc->size = sz;

  if (alldevsp != NULL)
    pcap_freealldevs (alldevsp);

  return retc;
}
