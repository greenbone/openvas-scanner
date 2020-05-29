/* Copyright (C) 2020 Greenbone Networks GmbH
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

#include "alivedetection.h"

#include "../misc/pcap.c" /* routethrough functions */

#include <arpa/inet.h>
#include <errno.h>
#include <gvm/base/networking.h> /* for gvm_source_addr() */
#include <gvm/base/prefs.h>      /* for prefs_get() */
#include <gvm/util/kb.h>         /* for kb_t operations */
#include <ifaddrs.h>             /* for getifaddrs() */
#include <net/ethernet.h>
#include <net/if.h> /* for if_nametoindex() */
#include <net/if_arp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <pcap.h>
#include <pthread.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

struct scanner scanner;
struct scan_restrictions scan_restrictions;
struct hosts_data hosts_data;

/* for using int value in #defined string */
#define STR(X) #X
#define ASSTR(X) STR (X)
/* packets are sent to port 9910*/
#define FILTER_PORT 9910
#define FILTER_STR                                                           \
  "(ip6 or ip or arp) and (ip6[40]=129 or icmp[icmptype] == icmp-echoreply " \
  "or dst port " ASSTR (FILTER_PORT) " or arp[6:2]=2)"

/* Conditional variable and mutex to make sure sniffer thread already started
 * before sending out pings. */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static boreas_error_t
get_alive_test_methods (alive_test_t *alive_test);

/**
 * @brief The scanner struct holds data which is used frequently by the alive
 * detection thread.
 */
struct scanner
{
  /* sockets */
  int tcpv4soc;
  int tcpv6soc;
  int icmpv4soc;
  int icmpv6soc;
  int arpv4soc;
  int arpv6soc;
  /* UDP socket needed for getting the source IP for the TCP header. */
  int udpv4soc;
  /* TH_SYN or TH_ACK */
  uint8_t tcp_flag;
  /* ports used for TCP ACK/SYN */
  GArray *ports;
  /* source addresses */
  struct in_addr *sourcev4;
  struct in6_addr *sourcev6;
  /* redis connection */
  kb_t main_kb;
  /* pcap handle */
  pcap_t *pcap_handle;
};

/* Max_scan_hosts and max_alive_hosts related struct. */
struct scan_restrictions
{
  /* Maximum number of hosts allowed to be scanned. No more alive hosts are put
   * on the queue after max_scan_hosts number of alive hosts is reached.
   * max_scan_hosts_reached is set to true and the finish signal gets put on
   * the queue. */
  int max_scan_hosts;
  /* Maximum number of hosts to be identified as alive. After max_alive_hosts
   * number of hosts are identified as alive max_alive_hosts_reached is set to
   * true which signals the stop of sending new pings. */
  int max_alive_hosts;
  /* Count of unique identified alive hosts. */
  int alive_hosts_count;
  gboolean max_scan_hosts_reached;
  gboolean max_alive_hosts_reached;
};

/**
 * @brief The hosts_data struct holds the alive hosts and target hosts in
 * separate hashtables.
 */
struct hosts_data
{
  /* Set of the form (ip_str, ip_str).
   * Hosts which passed our pcap filter. May include hosts which are alive but
   * are not in the targethosts list */
  GHashTable *alivehosts;
  /* Hashtable of the form (ip_str, gvm_host_t *). The gvm_host_t pointers point
   * to hosts which are to be freed by the caller of start_alive_detection(). */
  GHashTable *targethosts;
  /* Hosts which were detected as alive and are in the targetlist but are not
   * sent to openvas because max_scan_hosts was reached. */
  GHashTable *alivehosts_not_to_be_sent_to_openvas;
};

/**
 * @brief type of sockets
 */
enum socket_type
{
  TCPV4,
  TCPV6,
  ICMPV4,
  ICMPV6,
  ARPV4,
  ARPV6,
  UDPV4,
};

struct arp_hdr
{
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

struct sniff_ethernet
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

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
};

struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcphdr tcpheader;
};

const char *
str_boreas_error (boreas_error_t boreas_error)
{
  const gchar *msg;

  msg = NULL;
  switch (boreas_error)
    {
    case BOREAS_OPENING_SOCKET_FAILED:
      msg = "Boreas was not able to open a new socket";
      break;
    case BOREAS_SETTING_SOCKET_OPTION_FAILED:
      msg = "Boreas was not able to set socket option for socket";
      break;
    case BOREAS_NO_VALID_ALIVE_TEST_SPECIFIED:
      msg =
        "No valid alive detction method was specified for Boreas by the user";
      break;
    case BOREAS_CLEANUP_ERROR:
      msg = "Boreas encountered an error during clean up.";
      break;
    case BOREAS_NO_SRC_ADDR_FOUND:
      msg = "Boreas was not able to determine a source address for the given "
            "destination.";
      break;
    case NO_ERROR:
      msg = "No error was encountered by Boreas";
      break;
    default:
      break;
    }
  return msg;
}

/**
 * @brief Get the openvas scan id of the curent task.
 *
 * @param db_address  Address of the Redis db.
 * @param db_id ID of the scan main db.
 *
 * @return Scan id of current task or NULL on error.
 */
static gchar *
get_openvas_scan_id (const gchar *db_address, int db_id)
{
  kb_t main_kb = NULL;
  gchar *scan_id;
  if ((main_kb = kb_direct_conn (db_address, db_id)))
    {
      scan_id = kb_item_get_str (main_kb, ("internal/scanid"));
      kb_lnk_reset (main_kb);
      return scan_id;
    }
  return NULL;
}

/**
 * @brief open a new pcap handle ad set provided filter.
 *
 * @param iface interface to use.
 * @param filter pcap filter to use.
 *
 * @return pcap_t handle or NULL on error
 */
static pcap_t *
open_live (char *iface, char *filter)
{
  /* iface considerations:
   * pcap_open_live(iface, ...) sniffs on all interfaces(linux) if iface
   * argument is NULL pcap_lookupnet(iface, ...) is used to set ipv4 network
   * number and mask associated with iface pcap_compile(..., mask) netmask
   * specifies the IPv4 netmask of the network on which packets are being
   * captured; it is used only when checking for IPv4 broadcast addresses in the
   * filter program
   *
   *  If we are not checking for IPv4 broadcast addresses in the filter program
   * we do not need an iface (if we also want to listen on all interface) and we
   * do not need to call pcap_lookupnet
   */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;
  struct bpf_program filter_prog;

  /* iface, snapshot length of handle, promiscuous mode, packet buffer timeout
   * (ms), errbuff */
  errbuf[0] = '\0';
  pcap_handle = pcap_open_live (iface, 1500, 0, 100, errbuf);
  if (pcap_handle == NULL)
    {
      g_warning ("%s: %s", __func__, errbuf);
      return NULL;
    }
  if (g_utf8_strlen (errbuf, -1) != 0)
    {
      g_warning ("%s: %s", __func__, errbuf);
    }

  /* handle, struct bpf_program *fp, int optimize, bpf_u_int32 netmask */
  if (pcap_compile (pcap_handle, &filter_prog, filter, 1, PCAP_NETMASK_UNKNOWN)
      < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }

  if (pcap_setfilter (pcap_handle, &filter_prog) < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }
  pcap_freecode (&filter_prog);

  return pcap_handle;
}

/**
 * @brief Get new host from alive detection scanner.
 *
 * Check if an alive host was found by the alive detection scanner. If an alive
 * host is found it is packed into a gvm_host_t and returned. If no host was
 * found or an error occurred NULL is returned. If alive detection finished
 * scanning all hosts, NULL is returned and the status flag
 * alive_detection_finished is set to TRUE.
 *
 * @param alive_hosts_kb  Redis connection for accessing the queue on which the
 * alive detection scanner puts found hosts.
 * @param alive_deteciton_finished  Status of alive detection process.
 * @return  If valid alive host is found return a gvm_host_t. If alive scanner
 * finished NULL is returened and alive_deteciton_finished set. On error or if
 * no host was found return NULL.
 */
gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, gboolean *alive_deteciton_finished)
{
  /* redis connection not established yet */
  if (!alive_hosts_kb)
    {
      g_debug ("%s: connection to redis is not valid", __func__);
      return NULL;
    }

  /* string representation of an ip address or ALIVE_DETECTION_FINISHED */
  gchar *host_str = NULL;
  /* complete host to be returned */
  gvm_host_t *host = NULL;

  /* try to get item from db, string needs to be freed, NULL on empty or
   * error
   */
  host_str = kb_item_pop_str (alive_hosts_kb, (ALIVE_DETECTION_QUEUE));
  if (!host_str)
    {
      return NULL;
    }
  /* got some string from redis queue */
  else
    {
      /* check for finish signal/string */
      if (g_strcmp0 (host_str, ALIVE_DETECTION_FINISHED) == 0)
        {
          /* Send Error message if max_scan_hosts was reached. */
          if (scan_restrictions.max_scan_hosts_reached)
            {
              kb_t main_kb = NULL;
              int i = atoi (prefs_get ("ov_maindbid"));

              if ((main_kb = kb_direct_conn (prefs_get ("db_address"), i)))
                {
                  char buf[256];
                  g_snprintf (
                    buf, 256,
                    "ERRMSG||| ||| ||| |||Maximum number of allowed scans "
                    "reached. There are still %d alive hosts available "
                    "which are not scanned.",
                    scan_restrictions.alive_hosts_count
                      - scan_restrictions.max_scan_hosts);
                  if (kb_item_push_str (main_kb, "internal/results", buf) != 0)
                    g_warning ("%s: kb_item_push_str() failed to push "
                               "error message.",
                               __func__);
                  kb_lnk_reset (main_kb);
                }
              else
                g_warning (
                  "%s: Boreas was unable to connect to the Redis db.Info about "
                  "number of alive hosts could not be sent.",
                  __func__);
            }
          g_debug ("%s: Boreas already finished scanning and we reached the "
                   "end of the Queue of alive hosts.",
                   __func__);
          g_free (host_str);
          *alive_deteciton_finished = TRUE;
          return NULL;
        }
      /* probably got host */
      else
        {
          host = gvm_host_from_str (host_str);
          g_free (host_str);

          if (!host)
            {
              g_warning ("%s: Could not transform IP string \"%s\" into "
                         "internal representation.",
                         __func__, host_str);
              return NULL;
            }
          else
            {
              return host;
            }
        }
    }
}

/**
 * @brief Checksum calculation.
 *
 * From W.Richard Stevens "UNIX NETWORK PROGRAMMING" book. libfree/in_cksum.c
 * TODO: Section 8.7 of TCPv2 has more efficient implementation
 **/
static uint16_t
in_cksum (uint16_t *addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);
}

/**
 * @brief Put finish signal on alive detection queue.
 *
 * If the finish signal (a string) was already put on the queue it is not put on
 * it again.
 *
 * @param error  Set to 0 on success. Is set to -1 if finish signal was already
 * put on queue. Set to -2 if function was no able to push finish string on
 * queue.
 */
static void
put_finish_signal_on_queue (void *error)
{
  static gboolean fin_msg_already_on_queue = FALSE;
  if (fin_msg_already_on_queue)
    {
      g_debug ("%s: Finish signal was already put on queue.", __func__);
      *(int *) error = -1;
      return;
    }
  if ((kb_item_push_str (scanner.main_kb, ALIVE_DETECTION_QUEUE,
                         ALIVE_DETECTION_FINISHED))
      != 0)
    {
      g_debug ("%s: Could not push the Boreas finish signal on the alive "
               "detection Queue.",
               __func__);
      *(int *) error = -2;
    }
  else
    {
      *(int *) error = 0;
      fin_msg_already_on_queue = TRUE;
    }
}

/**
 * @brief Put host value string on queue of hosts to be considered as alive.
 *
 * @param key Host value string.
 * @param value Pointer to gvm_host_t.
 * @param user_data
 */
static void
put_host_on_queue (gpointer key, __attribute__ ((unused)) gpointer value,
                   __attribute__ ((unused)) gpointer user_data)
{
  if (kb_item_push_str (scanner.main_kb, ALIVE_DETECTION_QUEUE, (char *) key)
      != 0)
    g_debug ("%s: kb_item_push_str() failed. Could not push \"%s\" on queue of "
             "hosts to be considered as alive.",
             __func__, (char *) key);
}

/**
 * @brief Handle restrictions imposed by max_scan_hosts and max_alive_hosts.
 *
 * Put host address string on alive detection queue if max_scan_hosts was not
 * reached already. If max_scan_hosts was reached only count alive hosts and
 * don't put them on the queue. Put finish signal on queue if max_scan_hosts is
 * reached.
 *
 * @param add_str Host address string to put on queue.
 */
static void
handle_scan_restrictions (gchar *addr_str)
{
  scan_restrictions.alive_hosts_count++;
  /* Put alive hosts on queue as long as max_scan_hosts not reached. */
  if (!scan_restrictions.max_scan_hosts_reached)
    put_host_on_queue (addr_str, NULL, NULL);
  else
    g_hash_table_add (hosts_data.alivehosts_not_to_be_sent_to_openvas,
                      addr_str);

  /* Put finish signal on queue if max_scan_hosts reached. */
  if (!scan_restrictions.max_scan_hosts_reached
      && (scan_restrictions.alive_hosts_count
          == scan_restrictions.max_scan_hosts))
    {
      int err;
      scan_restrictions.max_scan_hosts_reached = TRUE;
      put_finish_signal_on_queue (&err);
      if (err != 0)
        g_debug ("%s: Error in put_finish_signal_on_queue(): %d ", __func__,
                 err);
    }
  /* Thread which sends out new pings should stop sending when max_alive_hosts
   * is reached. */
  if (scan_restrictions.alive_hosts_count == scan_restrictions.max_alive_hosts)
    scan_restrictions.max_alive_hosts_reached = TRUE;
}

/**
 * @brief Processes single packets captured by pcap. Is a callback function.
 *
 * For every packet we check if it is ipv4 ipv6 or arp and extract the sender ip
 * address. This ip address is then inserted into the alive_hosts table if not
 * already present and if in the target table.
 *
 * @param args
 * @param header
 * @param packet  Packet to process.
 *
 * TODO: simplify and read https://tools.ietf.org/html/rfc826
 */
static void
got_packet (__attribute__ ((unused)) u_char *args,
            __attribute__ ((unused)) const struct pcap_pkthdr *header,
            const u_char *packet)
{
  struct ip *ip = (struct ip *) (packet + 16); // why not 14(ethernet size)??
  unsigned int version = ip->ip_v;

  /* Stop processing of packets if max_alive_hosts is reached. */
  if (scan_restrictions.max_alive_hosts_reached)
    return;

  if (version == 4)
    {
      gchar addr_str[INET_ADDRSTRLEN];
      struct in_addr sniffed_addr;
      /* was +26 (14 ETH + 12 IP) originally but was off by 2 somehow */
      memcpy (&sniffed_addr.s_addr, packet + 26 + 2, 4);
      if (inet_ntop (AF_INET, (const char *) &sniffed_addr, addr_str,
                     INET_ADDRSTRLEN)
          == NULL)
        g_debug (
          "%s: Failed to transform IPv4 address into string representation: %s",
          __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are searching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts and max_alive_hosts related restrictions. */
          handle_scan_restrictions (addr_str);
        }
    }
  else if (version == 6)
    {
      gchar addr_str[INET6_ADDRSTRLEN];
      struct in6_addr sniffed_addr;
      /* (14 ETH + 8 IP + offset 2)  */
      memcpy (&sniffed_addr.s6_addr, packet + 24, 16);
      if (inet_ntop (AF_INET6, (const char *) &sniffed_addr, addr_str,
                     INET6_ADDRSTRLEN)
          == NULL)
        g_debug ("%s: Failed to transform IPv6 into string representation: %s",
                 __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are searching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts and max_alive_hosts related restrictions. */
          handle_scan_restrictions (addr_str);
        }
    }
  /* TODO: check collision situations.
   * everything not ipv4/6 is regarded as arp.
   * It may be possible to get other types then arp replies in which case the
   * ip from inet_ntop should be bogus. */
  else
    {
      /* TODO: at the moment offset of 6 is set but arp header has variable
       * sized field. */
      /* read rfc https://tools.ietf.org/html/rfc826 for exact length or how
      to get it */
      struct arphdr *arp =
        (struct arphdr *) (packet + 14 + 2 + 6 + sizeof (struct arphdr));
      gchar addr_str[INET_ADDRSTRLEN];
      if (inet_ntop (AF_INET, (const char *) arp, addr_str, INET_ADDRSTRLEN)
          == NULL)
        g_debug ("%s: Failed to transform IP into string representation: %s",
                 __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue
      we are searching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts and max_alive_hosts related restrictions. */
          handle_scan_restrictions (addr_str);
        }
    }
}

/**
 * @brief Sniff packets by starting pcap_loop with callback function.
 *
 * @param vargp
 */
static void *
sniffer_thread (__attribute__ ((unused)) void *vargp)
{
  int ret;
  pthread_mutex_lock (&mutex);
  pthread_cond_signal (&cond);
  pthread_mutex_unlock (&mutex);

  /* reads packets until error or pcap_breakloop() */
  if ((ret = pcap_loop (scanner.pcap_handle, -1, got_packet, NULL))
      == PCAP_ERROR)
    g_debug ("%s: pcap_loop error %s", __func__,
             pcap_geterr (scanner.pcap_handle));
  else if (ret == 0)
    g_debug ("%s: count of packets is exhausted", __func__);
  else if (ret == PCAP_ERROR_BREAK)
    g_debug ("%s: Loop was successfully broken after call to pcap_breakloop",
             __func__);

  pthread_exit (0);
}

/**
 * @brief delete key from hashtable
 *
 * @param key Key to delete from hashtable
 * @param value
 * @param hashtable   table to remove keys from
 *
 */
static void
exclude (gpointer key, __attribute__ ((unused)) gpointer value,
         gpointer hashtable)
{
  /* delete key from targethost*/
  g_hash_table_remove (hashtable, (gchar *) key);
}

__attribute__ ((unused)) static void
print_host_str (gpointer key, __attribute__ ((unused)) gpointer value,
                __attribute__ ((unused)) gpointer user_data)
{
  g_message ("host_str: %s", (gchar *) key);
}

/**
 * @brief Get the source mac address of the given interface
 * or of the first non lo interface.
 *
 * @param interface Interface to get mac address from or NULL if first non lo
 * interface should be used.
 * @param[out]  mac Location where to store mac address.
 *
 * @return 0 on success, -1 on error.
 */
static int
get_source_mac_addr (gchar *interface, uint8_t *mac)
{
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  int interface_provided = 0;

  if (interface)
    interface_provided = 1;

  if (getifaddrs (&ifaddr) == -1)
    {
      g_debug ("%s: getifaddr failed: %s", __func__, strerror (errno));
      return -1;
    }
  else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)
              && !(ifa->ifa_flags & (IFF_LOOPBACK)))
            {
              if (interface_provided)
                {
                  if (g_strcmp0 (interface, ifa->ifa_name) == 0)
                    {
                      struct sockaddr_ll *s =
                        (struct sockaddr_ll *) ifa->ifa_addr;
                      memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                    }
                }
              else
                {
                  struct sockaddr_ll *s = (struct sockaddr_ll *) ifa->ifa_addr;
                  memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                }
            }
        }
      freeifaddrs (ifaddr);
    }
  return 0;
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param type  Type of imcp. e.g. ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST.
 */
static void
send_icmp_v6 (int soc, struct in6_addr *dst, int type)
{
  struct sockaddr_in6 soca;
  char sendbuf[1500];
  int len;
  int datalen = 56;
  struct icmp6_hdr *icmp6;

  icmp6 = (struct icmp6_hdr *) sendbuf;
  icmp6->icmp6_type = type; /* ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST */
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = 234;
  icmp6->icmp6_seq = 0;

  memset ((icmp6 + 1), 0xa5, datalen);
  gettimeofday ((struct timeval *) (icmp6 + 1), NULL); // only for testing
  len = 8 + datalen;

  /* send packet */
  memset (&soca, 0, sizeof (struct sockaddr_in6));
  soca.sin6_family = AF_INET6;
  soca.sin6_addr = *dst;

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (struct sockaddr *) &soca,
              sizeof (struct sockaddr_in6))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
static void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  /* datalen + MAXIPLEN + MAXICMPLEN */
  char sendbuf[56 + 60 + 76];
  struct sockaddr_in soca;

  int len;
  int datalen = 56;
  struct icmphdr *icmp;

  icmp = (struct icmphdr *) sendbuf;
  icmp->type = ICMP_ECHO;
  icmp->code = 0;

  len = 8 + datalen;
  icmp->checksum = 0;
  icmp->checksum = in_cksum ((u_short *) icmp, len);

  memset (&soca, 0, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param user_data
 */
static void
send_icmp (__attribute__ ((unused)) gpointer key, gpointer value,
           __attribute__ ((unused)) gpointer user_data)
{
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  static int count;

  count = 1;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      send_icmp_v6 (scanner.icmpv6soc, dst6_p, ICMP6_ECHO_REQUEST);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_icmp_v4 (scanner.icmpv4soc, dst4_p);
    }
}

/**
 * @brief Send tcp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param tcp_flag  TH_SYN or TH_ACK.
 */
static void
send_tcp_v6 (int soc, struct in6_addr *dst_p, uint8_t tcp_flag)
{
  struct sockaddr_in6 soca;

  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));

  struct in6_addr src;

  if (scanner.sourcev6 == NULL)
    {
      gchar addr_str[INET6_ADDRSTRLEN];
      gchar *interface = v6_routethrough (dst_p, &src);
      g_debug ("%s: interface to use: %s.", __func__, interface);
      scanner.sourcev6 = g_memdup (&src, sizeof (struct in6_addr));

      if (inet_ntop (AF_INET6, (const char *) &scanner.sourcev6, addr_str,
                     INET6_ADDRSTRLEN)
          == NULL)
        g_debug ("%s: Failed to transform IPv6 into string representation: %s",
                 __func__, strerror (errno));

      g_debug ("%s: Use %s as source IP for IPv4 pings.", __func__, addr_str);
    }

  /* No ports in portlist. */
  if (scanner.ports->len == 0)
    return;

  /* For ports in ports array send packet. */
  for (guint i = 0; i < scanner.ports->len; i++)
    {
      memset (packet, 0, sizeof (packet));
      /* IPv6 */
      ip->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
      ip->ip6_plen = htons (20); // TCP_HDRLEN
      ip->ip6_nxt = IPPROTO_TCP;
      ip->ip6_hops = 255; // max value

      ip->ip6_src = *scanner.sourcev6;
      ip->ip6_dst = *dst_p;

      /* TCP */
      tcp->th_sport = htons (FILTER_PORT);
      tcp->th_dport = htons (g_array_index (scanner.ports, uint16_t, i));
      tcp->th_seq = htonl (0);
      tcp->th_ack = htonl (0);
      tcp->th_x2 = 0;
      tcp->th_off = 20 / 4; // TCP_HDRLEN / 4 (size of tcphdr in 32 bit words)
      tcp->th_flags = tcp_flag; // TH_SYN or TH_ACK
      tcp->th_win = htons (65535);
      tcp->th_urp = htons (0);
      tcp->th_sum = 0;

      /* CKsum */
      {
        struct v6pseudohdr pseudoheader;

        memset (&pseudoheader, 0, 38 + sizeof (struct tcphdr));
        memcpy (&pseudoheader.s6addr, &ip->ip6_src, sizeof (struct in6_addr));
        memcpy (&pseudoheader.d6addr, &ip->ip6_dst, sizeof (struct in6_addr));

        pseudoheader.protocol = IPPROTO_TCP;
        pseudoheader.length = htons (sizeof (struct tcphdr));
        memcpy ((char *) &pseudoheader.tcpheader, (char *) tcp,
                sizeof (struct tcphdr));
        tcp->th_sum = in_cksum ((unsigned short *) &pseudoheader,
                                38 + sizeof (struct tcphdr));
      }

      memset (&soca, 0, sizeof (soca));
      soca.sin6_family = AF_INET6;
      soca.sin6_addr = ip->ip6_dst;
      /*  TCP_HDRLEN(20) IP6_HDRLEN(40) */
      if (sendto (soc, (const void *) ip, 40 + 20, MSG_NOSIGNAL,
                  (struct sockaddr *) &soca, sizeof (struct sockaddr_in6))
          < 0)
        {
          g_warning ("%s: sendto():  %s", __func__, strerror (errno));
        }
    }
}

/**
 * @brief Send tcp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param tcp_flag  TH_SYN or TH_ACK.
 */
static void
send_tcp_v4 (int soc, struct in_addr *dst_p, uint8_t tcp_flag)
{
  struct sockaddr_in soca;

  u_char packet[sizeof (struct ip) + sizeof (struct tcphdr)];
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip));

  struct in_addr src; /* ip src */

  /* get src address */
  if (scanner.sourcev4 == NULL)
    {
      gchar addr_str[INET_ADDRSTRLEN];
      gchar *interface = routethrough (dst_p, &src);
      scanner.sourcev4 = g_memdup (&src, sizeof (struct in_addr));
      g_debug ("%s: interface to use: %s", __func__, interface);

      if (inet_ntop (AF_INET, (const void *) scanner.sourcev4, addr_str,
                     INET_ADDRSTRLEN)
          == NULL)
        g_debug (
          "%s: Failed to transform IPv4 address into string representation: %s",
          __func__, strerror (errno));

      g_debug ("%s: Use %s as source IP for IPv4 pings.", __func__, addr_str);
    }

  /* No ports in portlist. */
  if (scanner.ports->len == 0)
    return;

  /* For ports in ports array send packet. */
  for (guint i = 0; i < scanner.ports->len; i++)
    {
      memset (packet, 0, sizeof (packet));
      /* IP */
      ip->ip_hl = 5;
      ip->ip_off = htons (0);
      ip->ip_v = 4;
      ip->ip_tos = 0;
      ip->ip_p = IPPROTO_TCP;
      ip->ip_id = rand ();
      ip->ip_ttl = 0x40;
      ip->ip_src = *scanner.sourcev4;
      ip->ip_dst = *dst_p;
      ip->ip_sum = 0;

      /* TCP */
      tcp->th_sport = htons (FILTER_PORT);
      tcp->th_flags = tcp_flag; // TH_SYN TH_ACK;
      tcp->th_dport = htons (g_array_index (scanner.ports, uint16_t, i));
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

        memset (&pseudoheader, 0, 12 + sizeof (struct tcphdr));
        pseudoheader.saddr.s_addr = source.s_addr;
        pseudoheader.daddr.s_addr = dest.s_addr;

        pseudoheader.protocol = IPPROTO_TCP;
        pseudoheader.length = htons (sizeof (struct tcphdr));
        memcpy ((char *) &pseudoheader.tcpheader, (char *) tcp,
                sizeof (struct tcphdr));
        tcp->th_sum = in_cksum ((unsigned short *) &pseudoheader,
                                12 + sizeof (struct tcphdr));
      }

      memset (&soca, 0, sizeof (soca));
      soca.sin_family = AF_INET;
      soca.sin_addr = ip->ip_dst;
      if (sendto (soc, (const void *) ip, 40, MSG_NOSIGNAL,
                  (struct sockaddr *) &soca, sizeof (soca))
          < 0)
        {
          g_warning ("%s: sendto(): %s", __func__, strerror (errno));
        }
    }
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param user_data
 */
static void
send_tcp (__attribute__ ((unused)) gpointer key, gpointer value,
          __attribute__ ((unused)) gpointer user_data)
{
  static int count = 0;
  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      send_tcp_v6 (scanner.tcpv6soc, dst6_p, scanner.tcp_flag);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_tcp_v4 (scanner.tcpv4soc, dst4_p, scanner.tcp_flag);
    }
}

/**
 * @brief Send arp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
static void
send_arp_v4 (int soc, struct in_addr *dst_p)
{
  struct sockaddr_ll soca;
  struct arp_hdr arphdr;
  int frame_length;
  uint8_t *ether_frame;

  static gboolean first_time_setup_done = FALSE;
  static struct in_addr src;
  static int ifaceindex;
  static uint8_t src_mac[6];
  static uint8_t dst_mac[6];

  memset (&soca, 0, sizeof (soca));

  /* Set up data which does not change between function calls. */
  if (!first_time_setup_done)
    {
      /* Set src address. */
      gchar *interface = routethrough (dst_p, &src);
      if (!interface)
        g_warning ("%s: no appropriate interface was found", __func__);
      g_debug ("%s: interface to use: %s", __func__, interface);

      /* Get interface index for sockaddr_ll. */
      if ((ifaceindex = if_nametoindex (interface)) == 0)
        g_warning ("%s: if_nametoindex: %s", __func__, strerror (errno));

      /* Set MAC addresses. */
      memset (src_mac, 0, 6 * sizeof (uint8_t));
      memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
      if (get_source_mac_addr (interface, (unsigned char *) src_mac) != 0)
        g_warning ("%s: get_source_mac_addr() returned error", __func__);

      g_debug ("%s: Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
               __func__, src_mac[0], src_mac[1], src_mac[2], src_mac[3],
               src_mac[4], src_mac[5]);
      g_debug ("%s: Destination mac address: %02x:%02x:%02x:%02x:%02x:%02x",
               __func__, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3],
               dst_mac[4], dst_mac[5]);

      first_time_setup_done = TRUE;
    }

  /* Fill in sockaddr_ll.*/
  soca.sll_ifindex = ifaceindex;
  soca.sll_family = AF_PACKET;
  memcpy (soca.sll_addr, src_mac, 6 * sizeof (uint8_t));
  soca.sll_halen = 6;

  /* Fill ARP header.*/
  /* IP addresses. */
  memcpy (&arphdr.target_ip, dst_p, 4 * sizeof (uint8_t));
  memcpy (&arphdr.sender_ip, &src, 4 * sizeof (uint8_t));
  /* Hardware type ethernet.
   * Protocol type IP.
   * Hardware address length is MAC address length.
   * Protocol address length is length of IPv4.
   * OpCode is ARP request. */
  arphdr.htype = htons (1);
  arphdr.ptype = htons (ETH_P_IP);
  arphdr.hlen = 6;
  arphdr.plen = 4;
  arphdr.opcode = htons (1);
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  /* Ethernet frame to send. */
  ether_frame = g_malloc0 (IP_MAXPACKET);
  /* (MAC + MAC + ethernet type + ARP_HDRLEN) */
  frame_length = 6 + 6 + 2 + 28;

  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
  /* ethernet type code */
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;
  /* ARP header.  ETH_HDRLEN = 14, ARP_HDRLEN = 28 */
  memcpy (ether_frame + 14, &arphdr, 28 * sizeof (uint8_t));

  if ((sendto (soc, ether_frame, frame_length, MSG_NOSIGNAL,
               (struct sockaddr *) &soca, sizeof (soca)))
      <= 0)
    g_warning ("%s: sendto(): %s", __func__, strerror (errno));

  g_free (ether_frame);

  return;
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param user_data
 */
static void
send_arp (__attribute__ ((unused)) gpointer key, gpointer value,
          __attribute__ ((unused)) gpointer user_data)
{
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  static int count = 0;
  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      /* IPv6 does simulate ARP by using the Neighbor Discovery Protocol with
       * ICMPv6. */
      send_icmp_v6 (scanner.arpv6soc, dst6_p, ND_NEIGHBOR_SOLICIT);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_arp_v4 (scanner.arpv4soc, dst4_p);
    }
}

/**
 * @brief Send all dead hosts to ospd-openvas.
 *
 * All hosts which are not identified as alive are sent to ospd-openvas. This is
 * needed for the calculation of the progress bar for gsa in ospd-openvas.
 *
 * @return number of dead IPs, or -1 in case of an error.
 */
static int
send_dead_hosts_to_ospd_openvas (void)
{
  kb_t main_kb = NULL;
  int maindbid;
  int count_dead_ips = 0;
  char dead_host_msg_to_ospd_openvas[2048];

  GHashTableIter target_hosts_iter;
  gpointer host_str, value;

  maindbid = atoi (prefs_get ("ov_maindbid"));
  main_kb = kb_direct_conn (prefs_get ("db_address"), maindbid);

  if (!main_kb)
    {
      g_debug ("%s: Could not connect to main_kb for sending dead hosts to "
               "ospd-openvas.",
               __func__);
      return -1;
    }

  /* Delete all alive hosts which are not send to openvas because
   * max_alive_hosts was reached, from the alivehosts list. These hosts are
   * considered as dead by the progress bar of the openvas vuln scan because no
   * vuln scan was ever started for them. */
  g_hash_table_foreach (hosts_data.alivehosts_not_to_be_sent_to_openvas,
                        exclude, hosts_data.alivehosts);

  for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
       g_hash_table_iter_next (&target_hosts_iter, &host_str, &value);)
    {
      /* If a host in the target hosts is not in the list of alive hosts we know
       * it is dead. */
      if (!g_hash_table_contains (hosts_data.alivehosts, host_str))
        {
          count_dead_ips++;
        }
    }

  snprintf (dead_host_msg_to_ospd_openvas,
            sizeof (dead_host_msg_to_ospd_openvas), "DEADHOST||| ||| ||| |||%d",
            count_dead_ips);
  kb_item_push_str (main_kb, "internal/results", dead_host_msg_to_ospd_openvas);

  kb_lnk_reset (main_kb);

  return count_dead_ips;
}

/**
 * @brief Scan function starts a sniffing thread which waits for packets to
 * arrive and sends pings to hosts we want to test. Blocks until Scan is
 * finished or error occurred.
 *
 * Start a sniffer thread. Get what method of alive detection to use. Send
 * appropriate pings  for every host we want to test.
 *
 * @return 0 on success, <0 on failure.
 */
static int
scan (alive_test_t alive_test)
{
  int number_of_targets, number_of_targets_checked = 0;
  int number_of_dead_hosts;
  int err;
  void *retval;
  pthread_t sniffer_thread_id;
  GHashTableIter target_hosts_iter;
  gpointer key, value;
  struct timeval start_time, end_time;
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  gchar *scan_id;
  kb_t main_kb = NULL;

  gettimeofday (&start_time, NULL);
  number_of_targets = g_hash_table_size (hosts_data.targethosts);

  scanner.pcap_handle = open_live (NULL, FILTER_STR);
  if (scanner.pcap_handle == NULL)
    {
      g_warning ("%s: Unable to open valid pcap handle.", __func__);
      return -2;
    }

  scan_id = get_openvas_scan_id (prefs_get ("db_address"), scandb_id);
  g_message ("Alive scan %s started: Target has %d hosts", scan_id,
             number_of_targets);

  /* Start sniffer thread. */
  err = pthread_create (&sniffer_thread_id, NULL, sniffer_thread, NULL);
  if (err == EAGAIN)
    g_warning ("%s: pthread_create() returned EAGAIN: Insufficient resources "
               "to create thread.",
               __func__);
  /* Wait for thread to start up before sending out pings. */
  pthread_mutex_lock (&mutex);
  pthread_cond_wait (&cond, &mutex);
  pthread_mutex_unlock (&mutex);
  /* Mutex and cond not needed anymore. */
  pthread_mutex_destroy (&mutex);
  pthread_cond_destroy (&cond);
  sleep (2);

  if (alive_test
      == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    {
      g_debug ("%s: ICMP, TCP-ACK Service & ARP Ping", __func__);
      g_debug ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_tcp (key, value, NULL);
          number_of_targets_checked++;
        }
      g_debug ("%s: ICMP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_icmp (key, value, NULL);
          number_of_targets_checked++;
        }
      g_debug ("%s: ARP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_arp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ARP))
    {
      g_debug ("%s: TCP-ACK Service & ARP Ping", __func__);
      g_debug ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_tcp (key, value, NULL);
          number_of_targets_checked++;
        }
      g_debug ("%s: ARP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_arp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    {
      g_debug ("%s: ICMP & ARP Ping", __func__);
      g_debug ("%s: ICMP PING", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_icmp (key, value, NULL);
          number_of_targets_checked++;
        }
      g_debug ("%s: ARP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_arp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_TCP_ACK_SERVICE))
    {
      g_debug ("%s: ICMP & TCP-ACK Service Ping", __func__);
      g_debug ("%s: ICMP PING", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_icmp (key, value, NULL);
          number_of_targets_checked++;
        }
      g_debug ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_tcp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_ARP))
    {
      g_debug ("%s: ARP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_arp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE))
    {
      scanner.tcp_flag = TH_ACK;
      g_debug ("%s: TCP-ACK Service Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_tcp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_TCP_SYN_SERVICE))
    {
      g_debug ("%s: TCP-SYN Service Ping", __func__);
      scanner.tcp_flag = TH_SYN;
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_tcp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_ICMP))
    {
      g_debug ("%s: ICMP Ping", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          send_icmp (key, value, NULL);
          number_of_targets_checked++;
        }
    }
  else if (alive_test == (ALIVE_TEST_CONSIDER_ALIVE))
    {
      g_debug ("%s: Consider Alive", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter, hosts_data.targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value)
           && !scan_restrictions.max_alive_hosts_reached;)
        {
          handle_scan_restrictions (key);
          number_of_targets_checked++;
        }
    }

  g_debug (
    "%s: all ping packets have been sent, wait a bit for rest of replies.",
    __func__);
  sleep (WAIT_FOR_REPLIES_TIMEOUT);

  g_debug ("%s: Try to stop thread which is sniffing for alive hosts. ",
           __func__);
  /* Try to break loop in sniffer thread. */
  pcap_breakloop (scanner.pcap_handle);
  /* Give thread chance to exit on its own. */
  sleep (2);

  /* Cancel thread. May be necessary if pcap_breakloop() does not break the
   * loop. */
  err = pthread_cancel (sniffer_thread_id);
  if (err == ESRCH)
    g_debug ("%s: pthread_cancel() returned ESRCH; No thread with the "
             "supplied ID could be found.",
             __func__);

  /* join sniffer thread*/
  err = pthread_join (sniffer_thread_id, &retval);
  if (err == EDEADLK)
    g_warning ("%s: pthread_join() returned EDEADLK.", __func__);
  if (err == EINVAL)
    g_warning ("%s: pthread_join() returned EINVAL.", __func__);
  if (err == ESRCH)
    g_warning ("%s: pthread_join() returned ESRCH.", __func__);
  if (retval == PTHREAD_CANCELED)
    g_debug ("%s: pthread_join() returned PTHREAD_CANCELED.", __func__);

  g_debug ("%s: Stopped thread which was sniffing for alive hosts.", __func__);

  /* close handle */
  if (scanner.pcap_handle != NULL)
    {
      pcap_close (scanner.pcap_handle);
    }

  /* Send error message if max_alive_hosts was reached. */
  if (scan_restrictions.max_alive_hosts_reached)
    {
      if ((main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id)))
        {
          char buf[256];
          int not_checked;
          /* Targts could be checked multiple times. */
          not_checked = number_of_targets_checked >= number_of_targets
                          ? 0
                          : number_of_targets - number_of_targets_checked;
          g_snprintf (buf, 256,
                      "ERRMSG||| ||| ||| |||Maximum allowed number of alive "
                      "hosts identified. There are still %d hosts whose alive "
                      "status will not be checked.",
                      not_checked);
          if (kb_item_push_str (main_kb, "internal/results", buf) != 0)
            g_warning ("%s: Failed to send message to ospd-openvas about "
                       "max_alive_hosts reached and for how many host the "
                       "alive status will not be checked.",
                       __func__);
          kb_lnk_reset (main_kb);
        }
      else
        g_warning (
          "%s: Boreas was unable to connect to the Redis db. Failed to send "
          "message to ospd-openvas that max_alive_hosts was reached and for "
          "how many host the alive status will not be checked.",
          __func__);
    }

  /* Send info about dead hosts to ospd-openvas. This is needed for the
   * calculation of the progress bar for gsa. */
  number_of_dead_hosts = send_dead_hosts_to_ospd_openvas ();

  gettimeofday (&end_time, NULL);

  g_message ("Alive scan %s finished in %ld seconds: %d alive hosts of %d.",
             scan_id, end_time.tv_sec - start_time.tv_sec,
             number_of_targets - number_of_dead_hosts, number_of_targets);
  g_free (scan_id);

  return 0;
}

/**
 * @brief Set the SO_BROADCAST socket option for given socket.
 *
 * @param socket  The socket to apply the option to.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_broadcast (int socket)
{
  boreas_error_t error = NO_ERROR;
  int broadcast = 1;
  if (setsockopt (socket, SOL_SOCKET, SO_BROADCAST, &broadcast,
                  sizeof (broadcast))
      < 0)
    {
      g_warning ("%s: failed to set socket option SO_BROADCAST: %s", __func__,
                 strerror (errno));
      error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
    }
  return error;
}

/**
 * @brief Set a new socket of specified type.
 *
 * @param[in] socket_type  What type of socket to get.
 *
 * @param[out] scanner_socket  Location to save the socket into.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_socket (enum socket_type socket_type, int *scanner_socket)
{
  boreas_error_t error = NO_ERROR;
  int soc;
  switch (socket_type)
    {
    case UDPV4:
      {
        soc = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open UDPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case TCPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt = 1;
            if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt,
                            sizeof (opt))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV4 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case TCPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt_on = 1;
            if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL,
                            (char *) &opt_on, // IPV6_HDRINCL
                            sizeof (opt_on))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV6 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case ICMPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ICMPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV6:
    case ICMPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV6/ICMPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV4:
      {
        soc = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV4 socket: %s", __func__,
                       strerror (errno));
            return BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    default:
      error = BOREAS_OPENING_SOCKET_FAILED;
      break;
    }

  /* set SO_BROADCAST socket option. If not set we get permission denied error
   * on pinging broadcast address */
  if (!error)
    {
      if ((error = set_broadcast (soc)) != 0)
        return error;
    }

  *scanner_socket = soc;
  return error;
}

/**
 * @brief Set all sockets needed for the chosen detection methods.
 *
 * @param alive_test  Methods of alive detection to use provided as bitflag.
 *
 * @return  0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_all_needed_sockets (alive_test_t alive_test)
{
  boreas_error_t error = NO_ERROR;
  if (alive_test & ALIVE_TEST_ICMP)
    {
      if ((error = set_socket (ICMPV4, &scanner.icmpv4soc)) != 0)
        return error;
      if ((error = set_socket (ICMPV6, &scanner.icmpv6soc)) != 0)
        return error;
    }

  if ((alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
      || (alive_test & ALIVE_TEST_TCP_SYN_SERVICE))
    {
      if ((error = set_socket (TCPV4, &scanner.tcpv4soc)) != 0)
        return error;
      if ((error = set_socket (TCPV6, &scanner.tcpv6soc)) != 0)
        return error;
      if ((error = set_socket (UDPV4, &scanner.udpv4soc)) != 0)
        return error;
    }

  if ((alive_test & ALIVE_TEST_ARP))
    {
      if ((error = set_socket (ARPV4, &scanner.arpv4soc)) != 0)
        return error;
      if ((error = set_socket (ARPV6, &scanner.arpv6soc)) != 0)
        return error;
    }

  return error;
}

/**
 * @brief Put all ports of a given port range into the ports array.
 *
 * @param range Pointer to a range_t.
 * @param ports_array Pointer to an GArray.
 */
static void
fill_ports_array (gpointer range, gpointer ports_array)
{
  gboolean range_exclude;
  uint16_t range_start;
  uint16_t range_end;
  uint16_t port;

  range_start = ((range_t *) range)->start;
  range_end = ((range_t *) range)->end;
  range_exclude = ((range_t *) range)->exclude;

  /* If range should be excluded do not use it. */
  if (range_exclude)
    return;

  /* Only single port in range. */
  if (range_end == 0 || (range_start == range_end))
    {
      g_array_append_val (ports_array, range_start);
      return;
    }
  else
    {
      for (port = range_start; port <= range_end; port++)
        g_array_append_val (ports_array, port);
    }
}

/**
 * @brief Initialise the alive detection scanner.
 *
 * Fill scanner struct with appropriate values.
 *
 * @param hosts gvm_hosts_t list of hosts to alive test.
 * @param alive_test methods to use for alive detection.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
alive_detection_init (gvm_hosts_t *hosts, alive_test_t alive_test)
{
  g_debug ("%s: Initialise alive scanner. ", __func__);

  /* Used for ports array initialisation. */
  const gchar *port_list = NULL;
  GPtrArray *portranges_array;
  boreas_error_t error = NO_ERROR;

  /* Scanner */

  /* Sockets */
  if ((error = set_all_needed_sockets (alive_test)) != 0)
    return error;

  /* sources */
  scanner.sourcev4 = NULL;
  scanner.sourcev6 = NULL;
  /* kb_t redis connection */
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  if ((scanner.main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id))
      == NULL)
    return -7;
  /* TODO: pcap handle */
  // scanner.pcap_handle = open_live (NULL, FILTER_STR); //
  scanner.pcap_handle = NULL; /* is set in ping function */

  /* Results data */
  /* hashtables */
  hosts_data.alivehosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  hosts_data.targethosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  hosts_data.alivehosts_not_to_be_sent_to_openvas =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  /* put all hosts we want to check in hashtable */
  gvm_host_t *host;
  for (host = gvm_hosts_next (hosts); host; host = gvm_hosts_next (hosts))
    {
      g_hash_table_insert (hosts_data.targethosts, gvm_host_value_str (host),
                           host);
    }
  /* reset hosts iter */
  hosts->current = 0;

  /* Init ports used for scanning. */
  scanner.ports = NULL;
  port_list = "80,137,587,3128,8081";
  if (validate_port_range (port_list))
    {
      g_warning ("%s: Invalid port range supplied for alive detection module. "
                 "Using global port range instead.",
                 __func__);
      /* This port list was already validated by openvas so we don't do it here
       * again. */
      port_list = prefs_get ("port_range");
    }
  scanner.ports = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  if (port_list)
    portranges_array = port_range_ranges (port_list);
  else
    g_warning (
      "%s: Port list supplied by user is empty. Alive detection may not find "
      "any alive hosts when using TCP ACK/SYN scanning methods. ",
      __func__);
  /* Fill ports array with ports from the ranges. Duplicate ports are not
   * removed. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, scanner.ports);
  array_free (portranges_array);

  /* Scan restrictions. max_scan_hosts and max_alive_hosts related. */
  const gchar *pref_str;
  scan_restrictions.max_alive_hosts_reached = FALSE;
  scan_restrictions.max_scan_hosts_reached = FALSE;
  scan_restrictions.alive_hosts_count = 0;
  scan_restrictions.max_scan_hosts = INT_MAX;
  scan_restrictions.max_alive_hosts = INT_MAX;
  if ((pref_str = prefs_get ("max_scan_hosts")) != NULL)
    scan_restrictions.max_scan_hosts = atoi (pref_str);
  if ((pref_str = prefs_get ("max_alive_hosts")) != NULL)
    scan_restrictions.max_alive_hosts = atoi (pref_str);
  if (scan_restrictions.max_alive_hosts < scan_restrictions.max_scan_hosts)
    scan_restrictions.max_alive_hosts = scan_restrictions.max_scan_hosts;

  g_debug ("%s: Initialisation of alive scanner finished.", __func__);

  return error;
}

/**
 * @brief Free all the data used by the alive detection scanner.
 *
 * @param[out] error Set to 0 on success, boreas_error_t on error.
 */
static void
alive_detection_free (void *error)
{
  boreas_error_t alive_test_err;
  alive_test_t alive_test;

  if ((alive_test_err = get_alive_test_methods (&alive_test)) != 0)
    {
      g_warning ("%s: %s. Could not get info about which sockets to close.",
                 __func__, str_boreas_error (alive_test_err));
      *(int *) error = BOREAS_CLEANUP_ERROR;
    }
  else
    {
      if (alive_test & ALIVE_TEST_ICMP)
        {
          if ((close (scanner.icmpv4soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
          if ((close (scanner.icmpv6soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
        }

      if ((alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
          || (alive_test & ALIVE_TEST_TCP_SYN_SERVICE))
        {
          if ((close (scanner.tcpv4soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
          if ((close (scanner.tcpv6soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
          if ((close (scanner.udpv4soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
        }

      if ((alive_test & ALIVE_TEST_ARP))
        {
          if ((close (scanner.arpv4soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
          if ((close (scanner.arpv6soc)) != 0)
            {
              g_warning ("%s: Error in close(): %s", __func__,
                         strerror (errno));
              *(int *) error = BOREAS_CLEANUP_ERROR;
            }
        }
    }

  /*pcap_close (scanner.pcap_handle); //pcap_handle is closed in ping/scan
   * function for now */
  if ((kb_lnk_reset (scanner.main_kb)) != 0)
    {
      g_warning ("%s: error in kb_lnk_reset()", __func__);
      *(int *) error = BOREAS_CLEANUP_ERROR;
    }

  /* addresses */
  g_free (scanner.sourcev4);
  g_free (scanner.sourcev6);

  /* Ports array. */
  g_array_free (scanner.ports, TRUE);

  g_hash_table_destroy (hosts_data.alivehosts);
  /* targethosts: (ipstr, gvm_host_t *)
   * gvm_host_t are freed by caller of start_alive_detection()! */
  g_hash_table_destroy (hosts_data.targethosts);
  g_hash_table_destroy (hosts_data.alivehosts_not_to_be_sent_to_openvas);
}

/**
 * @brief Get the bitflag which describes the methods to use for alive
 * deteciton.
 *
 * @param[out]  alive_test  Bitflag of all specified alive detection methods.
 *
 * @return 0 on succes, boreas_error_t on failure.
 */
static boreas_error_t
get_alive_test_methods (alive_test_t *alive_test)
{
  boreas_error_t error = NO_ERROR;
  const gchar *alive_test_pref_as_str;

  alive_test_pref_as_str = prefs_get ("ALIVE_TEST");
  if (alive_test_pref_as_str == NULL)
    {
      g_warning ("%s: No valid alive_test specified.", __func__);
      error = BOREAS_NO_VALID_ALIVE_TEST_SPECIFIED;
    }

  *alive_test = atoi (alive_test_pref_as_str);
  return error;
}

/**
 * @brief Start the scan of all specified hosts in gvm_hosts_t
 * list. Finish signal is put on Queue if scan is finished or an error occurred.
 *
 * @param hosts_to_test gvm_hosts_t list of hosts to alive test. which is to be
 * freed by caller.
 */
void *
start_alive_detection (void *hosts_to_test)
{
  boreas_error_t init_err;
  boreas_error_t alive_test_err;
  int fin_err;
  boreas_error_t free_err;
  gvm_hosts_t *hosts;
  alive_test_t alive_test;

  if ((alive_test_err = get_alive_test_methods (&alive_test)) != 0)
    {
      g_warning ("%s: %s. Exit Boreas.", __func__,
                 str_boreas_error (alive_test_err));
      put_finish_signal_on_queue (&fin_err);
      if (fin_err != 0)
        g_warning ("%s: Could not put finish signal on Queue. Openvas needs to "
                   "be stopped manually. ",
                   __func__);
      pthread_exit (0);
    }

  hosts = (gvm_hosts_t *) hosts_to_test;
  if ((init_err = alive_detection_init (hosts, alive_test)) != 0)
    {
      g_warning (
        "%s. Boreas could not initialise alive detection. %s. Exit Boreas.",
        __func__, str_boreas_error (init_err));
      put_finish_signal_on_queue (&fin_err);
      if (fin_err != 0)
        g_warning ("%s: Could not put finish signal on Queue. Openvas needs to "
                   "be stopped manually. ",
                   __func__);
      pthread_exit (0);
    }

  /* If alive detection thread returns, is canceled or killed unexpectedly all
   * used resources are freed and sockets, connections closed.*/
  pthread_cleanup_push (alive_detection_free, &free_err);
  /* If alive detection thread returns, is canceled or killed unexpectedly a
   * finish signal is put on the queue for openvas to process.*/
  pthread_cleanup_push (put_finish_signal_on_queue, &fin_err);
  /* Start the scan. */
  if (scan (alive_test) < 0)
    g_warning ("%s: error in scan()", __func__);
  /* Put finish signal on queue. */
  pthread_cleanup_pop (1);
  /* Free memory, close sockets and connections. */
  pthread_cleanup_pop (1);
  if (free_err != 0)
    g_warning ("%s: %s. Exit Boreas thread none the less.", __func__,
               str_boreas_error (free_err));

  pthread_exit (0);
}
