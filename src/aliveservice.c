#include "aliveservice.h"

// #include "../misc/pcap_openvas.h" /* islocalhost_v4() */
// #include "../misc/bpf_share.h"
#include "../misc/pcap.c" /* routethrough functions */

#include <arpa/inet.h>
#include <errno.h>
#include <gvm/base/networking.h> /* gvm_source_addr() */
#include <gvm/base/prefs.h>      /* prefs_get() */
#include <gvm/util/kb.h>         /* kb_t operations */
#include <ifaddrs.h>             /* getifaddrs() */
#include <net/ethernet.h>        /* struct ether_addr ether_hdr */
#include <net/if.h>              /* IFF_LOOPBACK, if_nametoindex() */
#include <net/if_arp.h>
// #include <net/if_packet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h> /* struct sockaddr_ll */
#include <pcap.h>
#include <pthread.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>

struct scanner scanner;
struct hosts_data hosts_data;

/* for using int value in #defined string */
#define STR(X) #X
#define ASSTR(X) STR (X)
/* packets are sent to port 9910*/
#define FILTER_PORT 9910
#define FILTER_STR                                                           \
  "(ip6 or ip or arp) and (ip6[40]=129 or icmp[icmptype] == icmp-echoreply " \
  "or dst port " ASSTR (FILTER_PORT) " or arp[6:2]=2)"

struct scanner
{
  /* sockets */
  int tcpv4soc;
  int tcpv6soc;
  int icmpv4soc;
  int icmpv6soc;
  int arpv4soc;
  int arpv6soc;
  /* flags */
  uint8_t tcp_flag; /* TH_SYN or TH_ACK from <netinet/tcp.h> */
  /* arp */
  int ifaceindex;
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  /* source addresses */
  struct in_addr *sourcev4;
  struct in6_addr *sourcev6;
  struct in_addr *sourcearpv4;
  /* redis connection */
  kb_t main_kb;
  pcap_t *pcap_handle;
};

/* */
struct hosts_data
{
  GHashTable *alivehosts;  /* (str, str) */
  GHashTable *targethosts; /* (str, gvm_host_t) */
};

/* type of socket */
enum socket_type
{
  TCPV4,
  TCPV6,
  ICMPV4,
  ICMPV6,
  ARPV4,
  ARPV6,
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

void
printipv6 (void *ipv6)
{
  char *str = g_malloc0 (INET6_ADDRSTRLEN);
  inet_ntop (AF_INET6, ipv6, str, INET6_ADDRSTRLEN);
  g_message ("%s: IP: %s", __func__, str);
  g_free (str);
}

void
printipv4 (void *ipv4)
{
  char *str = g_malloc0 (INET_ADDRSTRLEN);
  inet_ntop (AF_INET, ipv4, str, INET_ADDRSTRLEN);
  g_message ("%s: IP: %s", __func__, str);
  g_free (str);
}

/**
 * @return pcap_t handle or NULL on error
 */
pcap_t *
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

  /* pcap version */
  g_debug ("%s: pcap version: %s", __func__, pcap_lib_version ());

  /* iface, snapshot length of handle, promiscuous mode, packet buffer timeout
   * (ms), errbuff */
  errbuf[0] = '\0';
  pcap_handle = pcap_open_live (iface, 1500, 0, 100, errbuf);
  if (pcap_handle == NULL)
    {
      g_error ("%s: %s", __func__, errbuf);
      return NULL;
    }
  if (g_utf8_strlen (errbuf, -1) != 0)
    {
      g_info ("%s: %s", __func__, errbuf);
    }

  /* TODO pcap_loop() and pcap_next() will not work in ''non-blocking'' mode.
   * previously non-blocking mode was set to 1 */
  if (pcap_setnonblock (pcap_handle, 0, errbuf) != 0)
    {
      g_error ("%s: %s", __func__, errbuf);
    }

  /* get current ''non-blocking'' state of the capture descriptor */
  int non_blocking_state = -1;
  if ((non_blocking_state = pcap_getnonblock (pcap_handle, errbuf)) < 0)
    {
      g_error ("%s: %s", __func__, errbuf);
    }
  else
    {
      g_debug ("%s: non-blocking state = %d", __func__, non_blocking_state);
    }

  /* handle, struct bpf_program *fp, int optimize, bpf_u_int32 netmask */
  if (pcap_compile (pcap_handle, &filter_prog, filter, 1, PCAP_NETMASK_UNKNOWN)
      < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_error ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }

  if (pcap_setfilter (pcap_handle, &filter_prog) < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_error ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }
  pcap_freecode (&filter_prog);

  return pcap_handle;
}

gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, int timeout)
{
  g_message ("%s: get new host from Queue", __func__);

  /* redis connection not established yet */
  if (!alive_hosts_kb)
    {
      g_error ("%s: connection to redis is not valid", __func__);
      return NULL;
    }

  /* timeout count in seconds */
  int count = 0;
  /* string representation of an ip address or "finish" */
  gchar *host_str = NULL;
  /* complete host to be returned */
  gvm_host_t *host = NULL;

  /* poll redis message queue for new results until success, timout or error */
  for (; !host && (timeout != count); count++)
    {
      /* after the first try in getting a new host we wait for one second */
      if (count)
        sleep (1);

      /* try to get item from db, string needs to be freed, NULL on empty or
       * error
       */
      host_str = kb_item_pop_str (alive_hosts_kb, ("alive_detection"));
      if (!host_str)
        {
          g_message ("%s: ALIVE_DETECTION_SCANNING, no item found on queue(or "
                     "error) but "
                     "alive detection still ongoing, try again in a sec",
                     __func__);
          continue;
        }
      /* got some string from redis queue */
      else
        {
          /* check for finish signal/string */
          if (g_strcmp0 (host_str, "finish") == 0)
            {
              g_message ("%s: ALIVE_DETECTION_FINISHED, scan was finished. "
                         "return NULL host",
                         __func__);
              g_free (host_str);
              return NULL;
            }
          /* probably got host */
          else
            {
              g_message ("%s: ALIVE_DETECTION_OK, got item from queue",
                         __func__);
              host = gvm_host_from_str (host_str);
              if (!host)
                {
                  g_error (
                    "%s: error in call to gvm_host_from_str() for host_str: %s",
                    __func__, host_str);
                  continue;
                }
              else
                {
                  g_free (host_str);
                  return host;
                }
            }
        }
    }
  g_free (host_str);
  return NULL;
}

/**
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

/* TODO: simplify and read https://tools.ietf.org/html/rfc826*/
void
got_packet (__attribute__ ((unused)) u_char *args,
            __attribute__ ((unused)) const struct pcap_pkthdr *header,
            const u_char *packet)
{
  // g_message ("%s: sniffed some packet in packet2", __func__);

  struct ip *ip = (struct ip *) (packet + 16); // why not 14(ethernet size)??
  unsigned int version = ip->ip_v;

  if (version == 4)
    {
      gchar addr_str[INET_ADDRSTRLEN];
      struct in_addr sniffed_addr;
      /* was +26 (14 ETH + 12 IP) originally but was off by 2 somehow */
      memcpy (&sniffed_addr.s_addr, packet + 26 + 2, 4);
      if (inet_ntop (AF_INET, (const char *) &sniffed_addr, addr_str,
                     INET_ADDRSTRLEN)
          == NULL)
        g_error ("%s: inet_ntop: %s", __func__, strerror (errno));
      // g_message ("%s: IP version = 4, addr: %s", __func__, addr_str);

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are seaching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          g_debug ("%s: Thread sniffed unique address to put on queue: %s",
                   __func__, addr_str);
          if (kb_item_push_str (scanner.main_kb, "alive_detection", addr_str)
              != 0)
            g_error ("%s: kb_item_push_str() failed", __func__);
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
        g_error ("%s: inet_ntop: %s", __func__, strerror (errno));
      // g_message ("%s: IP version = 6, addr: %s", __func__, addr_str);

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are seaching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          g_debug ("%s: Thread sniffed unique address to put on queue: %s",
                   __func__, addr_str);
          if (kb_item_push_str (scanner.main_kb, "alive_detection", addr_str)
              != 0)
            g_error ("%s: kb_item_push_str() failed", __func__);
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
        g_error ("%s: inet_ntop: %s", __func__, strerror (errno));
      // g_message ("%s: ARP, IP addr: %s", __func__, addr_str);

      /* Do not put already found host on Queue and only put hosts on Queue
      we are seaching for. */
      if (g_hash_table_add (hosts_data.alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data.targethosts, addr_str) == TRUE)
        {
          g_debug ("%s: Thread sniffed unique address to put on queue: %s",
                   __func__, addr_str);
          if (kb_item_push_str (scanner.main_kb, "alive_detection", addr_str)
              != 0)
            g_error ("%s: kb_item_push_str() failed", __func__);
        }
    }
}

static void *
sniffer_thread (__attribute__ ((unused)) void *vargp)
{
  int ret;
  g_info ("%s: start packet sniffing thread", __func__);

  /* reads packets until error or pcap_breakloop() */
  if ((ret = pcap_loop (scanner.pcap_handle, -1, got_packet, NULL))
      == PCAP_ERROR)
    g_error ("%s: pcap_loop error %s", __func__,
             pcap_geterr (scanner.pcap_handle));
  else if (ret == 0)
    g_warning ("%s: count of packets is exhausted", __func__);
  else if (ret == PCAP_ERROR_BREAK)
    g_info ("%s: Loop was succesfully broken after call to pcap_breakloop",
            __func__);

  pthread_exit (0);
}

/**
 * @brief Delete alive hosts from targethosts
 *
 * @param targethosts   target_hosts hashtable
 *
 */
void
exclude (gpointer key, __attribute__ ((unused)) gpointer value,
         gpointer targethosts)
{
  /* delte key from targethost*/
  g_hash_table_remove (targethosts, (gchar *) key);
}

void
print_host_str (gpointer key, __attribute__ ((unused)) gpointer value,
                __attribute__ ((unused)) gpointer user_data)
{
  g_message ("host_str: %s", (gchar *) key);
}

/**
 * @brief get the source mac address of the given interface
 * or of the first non lo interface
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
      g_error ("%s: getifaddr failed: %s", __func__, strerror (errno));
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

static void
send_icmp_v6 (int soc, struct in6_addr *dst, int type)
{
  // g_message ("%s: send imcpv6", __func__);

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

  if (sendto (soc, sendbuf, len, 0, (struct sockaddr *) &soca,
              sizeof (struct sockaddr_in6))
      < 0)
    {
      g_error ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

static void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  // g_message ("%s: IN ICMP func", __func__);
  char sendbuf[1500];
  struct sockaddr_in soca;

  int len;
  int datalen = 56;
  struct icmp *icmp;

  icmp = (struct icmp *) sendbuf;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = 234;
  icmp->icmp_seq = 0;
  memset (icmp->icmp_data, 0xa5, datalen);

  len = 8 + datalen;
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = in_cksum ((u_short *) icmp, len);

  memset (&soca, 0, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  if (sendto (soc, sendbuf, len, 0, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    {
      g_error ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
static void
send_icmp (__attribute__ ((unused)) gpointer key, gpointer value,
           __attribute__ ((unused)) gpointer user_data)
{
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  /* For setting the socket option SO_BINDTODEVICE only once */
  static gboolean icmpv4socopt_set = FALSE;
  static gboolean icmpv6socopt_set = FALSE;

  static int count = 0;
  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_error ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_error ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      // g_message ("%s got ipv6 address to handle", __func__);
      /* set device for icmpv4 */
      if (!icmpv6socopt_set)
        {
          g_info ("%s: set icmpv6 socket option SO_BINDTODEVICE", __func__);
          gchar *interface = v6_routethrough (dst6_p, NULL);
          // g_message ("%s: interface to use: %s", __func__, interface);
          if (!interface)
            g_warning ("%s: no appropriate interface was found", __func__);
          struct ifreq if_bind;
          if (g_strlcpy (if_bind.ifr_name, interface, IFNAMSIZ) <= 0)
            g_warning ("%s: copied 0 length interface", __func__);

          if (setsockopt (scanner.icmpv6soc, SOL_SOCKET, SO_BINDTODEVICE,
                          interface, IFNAMSIZ)
              < 0)
            {
              g_error ("%s: failed to set socket option SO_BINDTODEVICE: %s",
                       __func__, strerror (errno));
              return;
            }
          icmpv6socopt_set = TRUE;
        }
      /* send packets */
      send_icmp_v6 (scanner.icmpv6soc, dst6_p, ICMP6_ECHO_REQUEST);
    }
  else
    {
      // g_message ("%s got ipv4 address to handle", __func__);
      dst4.s_addr = dst6_p->s6_addr32[3];

      /* set device for icmpv6 */
      if (!icmpv4socopt_set)
        {
          g_message ("%s set icmpv4 socket option SO_BINDTODEVICE", __func__);
          gchar *interface = routethrough (dst4_p, NULL);
          if (!interface)
            g_warning ("%s: no appropriate interface was found", __func__);
          // g_message ("%s: interface to use: %s", __func__, interface);
          struct ifreq if_bind;
          g_strlcpy (if_bind.ifr_name, interface, IFNAMSIZ);
          g_warning ("%s: copied 0 length interface", __func__);

          if (setsockopt (scanner.icmpv4soc, SOL_SOCKET, SO_BINDTODEVICE,
                          interface, IFNAMSIZ)
              < 0)
            {
              g_error ("%s: failed to set socket option SO_BINDTODEVICE: %s",
                       __func__, strerror (errno));
              return;
            }
          icmpv4socopt_set = TRUE;
        }
      /* send packets */
      send_icmp_v4 (scanner.icmpv4soc, dst4_p);
    }
}

static void
send_tcp_v6 (int soc, struct in6_addr *dst_p, uint8_t tcp_flag)
{
  // g_message ("%s:ipv6", __func__);
  struct sockaddr_in6 soca;

  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));

  struct in6_addr src;

  int port = 0;
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,  6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548, 5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080};

  if (scanner.sourcev6 == NULL)
    {
      gchar *interface = v6_routethrough (dst_p, &src);
      g_info ("%s: interface to use: %s", __func__, interface);
      scanner.sourcev6 = g_memdup (&src, sizeof (struct in6_addr));
      printipv6 (scanner.sourcev6);
    }

  /* for ports in portrange send packets */
  for (long unsigned int i = 0; i < sizeof (ports) / sizeof (int); i++)
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
      tcp->th_dport = port ? htons (port) : htons (ports[i]);
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
      if (sendto (soc, (const void *) ip, 40 + 20, 0, (struct sockaddr *) &soca,
                  sizeof (struct sockaddr_in6))
          < 0)
        {
          g_error ("%s: sendto():  %s", __func__, strerror (errno));
        }
    }
}

void
send_tcp_v4 (int soc, struct in_addr *dst_p, uint8_t tcp_flag)
{
  struct sockaddr_in soca;

  u_char packet[sizeof (struct ip) + sizeof (struct tcphdr)];
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip));

  struct in_addr src; /* ip src */

  int port = 0;
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,  6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548, 5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080};

  /* get src address */
  if (scanner.sourcev4 == NULL) // scanner.sourcev4 == NULL
    {
      gchar *interface = routethrough (dst_p, &src);
      scanner.sourcev4 = g_memdup (&src, sizeof (struct in_addr));
      g_info ("%s: interface to use: %s", __func__, interface);
      printipv4 (scanner.sourcev4);
    }

  /* for ports in portrange send packets */
  for (long unsigned int i = 0; i < sizeof (ports) / sizeof (int); i++)
    {
      memset (packet, 0, sizeof (packet));
      /* IP */
      ip->ip_hl = 5;
      ip->ip_off = htons (0);
      ip->ip_v = 4;
      ip->ip_len = htons (40);
      ip->ip_tos = 0;
      ip->ip_p = IPPROTO_TCP;
      ip->ip_id = rand ();
      ip->ip_ttl = 0x40;
      ip->ip_src = *scanner.sourcev4;
      ip->ip_dst = *dst_p;
      ip->ip_sum = 0;
      ip->ip_sum = in_cksum ((u_short *) ip, 20);

      /* TCP */
      tcp->th_sport = htons (FILTER_PORT);
      tcp->th_flags = tcp_flag; // TH_SYN TH_ACK;
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
      if (sendto (soc, (const void *) ip, 40, 0, (struct sockaddr *) &soca,
                  sizeof (soca))
          < 0)
        {
          g_error ("%s: sendto(): %s", __func__, strerror (errno));
        }
    }
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
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
    g_error ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_error ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      // g_message ("%s: got ipv6 address to handle", __func__);
      send_tcp_v6 (scanner.tcpv6soc, dst6_p, scanner.tcp_flag);
    }
  else
    {
      // g_message ("%s: got ipv4 address to handle", __func__);
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_tcp_v4 (scanner.tcpv4soc, dst4_p, scanner.tcp_flag);
    }
}

void
send_arp_v4 (__attribute__ ((unused)) int soc, struct in_addr *dst_p,
             uint8_t *src_mac, __attribute__ ((unused)) uint8_t *dst_mac)
{
  // g_message ("%s: SENDING ARP", __func__);
  struct sockaddr_ll soca;
  struct in_addr src;
  struct arp_hdr arphdr;
  int frame_length;
  uint8_t *ether_frame;

  memset (&soca, 0, sizeof (soca));

  /* set up first time data */
  if (scanner.sourcearpv4 == NULL)
    {
      /* src address */
      gchar *interface = routethrough (dst_p, &src);
      if (!interface)
        g_warning ("%s: no appropriate interface was found", __func__);
      scanner.sourcearpv4 = g_memdup (&src, sizeof (struct in_addr));
      g_message ("%s: interface to use: %s", __func__, interface);
      printipv4 (scanner.sourcearpv4);
      printipv4 (dst_p);

      /* interface index */
      if ((scanner.ifaceindex = if_nametoindex (interface)) == 0)
        {
          g_error ("%s: if_nametoindex: %s", __func__, strerror (errno));
        }

      /* mac addresses */
      memset (&scanner.src_mac, 0, 6 * sizeof (uint8_t));
      /* dst mac */
      memset (scanner.dst_mac, 0xff, 6 * sizeof (uint8_t));
      /* src mac */
      if (get_source_mac_addr (interface, (unsigned char *) &scanner.src_mac)
          != 0)
        g_error ("%s: get_source_mac_addr() returned error", __func__);
      g_info ("%s: source mac address: %02x:%02x:%02x:%02x:%02x:%02x", __func__,
              scanner.src_mac[0], scanner.src_mac[1], scanner.src_mac[2],
              scanner.src_mac[3], scanner.src_mac[4], scanner.src_mac[5]);
      g_info ("%s: source mac address: %02x:%02x:%02x:%02x:%02x:%02x", __func__,
              scanner.dst_mac[0], scanner.dst_mac[1], scanner.dst_mac[2],
              scanner.dst_mac[3], scanner.dst_mac[4], scanner.dst_mac[5]);
    }
  soca.sll_ifindex = scanner.ifaceindex;

  g_info ("%s: Index for interface: %i", __func__, soca.sll_ifindex);
  soca.sll_family = AF_PACKET;
  memcpy (soca.sll_addr, src_mac, 6 * sizeof (uint8_t));
  soca.sll_halen = 6;

  /* IP addresses */
  memcpy (&arphdr.target_ip, dst_p, 4 * sizeof (uint8_t));
  memcpy (&arphdr.sender_ip, scanner.sourcearpv4, 4 * sizeof (uint8_t));

  // Hardware type (16 bits): 1 for ethernet
  arphdr.htype = htons (1);
  // Protocol type (16 bits): 2048 for IP
  arphdr.ptype = htons (ETH_P_IP);
  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr.hlen = 6;
  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr.plen = 4;
  // OpCode: 1 for ARP request
  arphdr.opcode = htons (1);
  // Sender hardware address (48 bits): MAC address
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
  // Sender protocol address (32 bits)
  // See getaddrinfo() resolution of src_ip.
  // Target hardware address (48 bits): zero, since we don't know it yet.
  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) +
  // ethernet data (ARP header)
  frame_length = 6 + 6 + 2 + 28; /* ARP_HDRLEN = 28 */

  // Destination and Source MAC addresses
  ether_frame = g_malloc0 (IP_MAXPACKET);
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

  // ARP header
  // ETH_HDRLEN = 14, ARP_HDRLEN = 28
  memcpy (ether_frame + 14, &arphdr, 28 * sizeof (uint8_t));

  // Send ethernet frame to socket.
  if ((sendto (soc, ether_frame, frame_length, 0, (struct sockaddr *) &soca,
               sizeof (soca)))
      <= 0)
    {
      g_error ("%s: sendto(): %s", __func__, strerror (errno));
    }

  g_free (ether_frame);

  return;
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
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
    g_error ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_error ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      // g_message ("got ipv6 address to handle");
      send_icmp_v6 (scanner.arpv6soc, dst6_p, ND_NEIGHBOR_SOLICIT);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_arp_v4 (scanner.arpv4soc, dst4_p, scanner.src_mac, scanner.dst_mac);
    }
}

static int
scan (void)
{
  g_message ("%s: scan for alive hosts started", __func__);
  int err = -1;

  scanner.pcap_handle = open_live (NULL, FILTER_STR);
  if (scanner.pcap_handle == NULL)
    return -1;

  /* start sniffer thread and wait a bit for startup */
  /* TODO: use mutex instead of sleep */
  pthread_t tid; /* thread id */
  if ((err = pthread_create (&tid, NULL, sniffer_thread, NULL)) != 0)
    {
      g_error ("%s: pthread_create: %d", __func__, err);
    }
  sleep (2);

  g_info ("%s: get method of alive dettection", __func__);
  /* get ALIVE_TEST enum */
  alive_test_t alive_test = atoi (prefs_get ("ALIVE_TEST"));
  if (alive_test
      == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    {
      g_info ("%s: ICMP, TCP-ACK Service & ARP Ping", __func__);
      g_info ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      g_hash_table_foreach (hosts_data.targethosts, send_tcp, NULL);
      g_info ("%s: ICMP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_icmp, NULL);
      g_info ("%s: ARP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_arp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ARP))
    {
      g_info ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      g_hash_table_foreach (hosts_data.targethosts, send_tcp, NULL);
      g_info ("%s: ARP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_arp, NULL);
      g_info ("%s: TCP-ACK Service & ARP Ping", __func__);
    }
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    {
      g_info ("%s: ICMP & ARP Ping", __func__);
      g_info ("%s: ICMP PING", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_icmp, NULL);
      g_info ("%s: ARP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_arp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_TCP_ACK_SERVICE))
    {
      g_info ("%s: ICMP & TCP-ACK Service Ping", __func__);
      g_info ("%s: ICMP PING", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_icmp, NULL);
      g_info ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK;
      g_hash_table_foreach (hosts_data.targethosts, send_tcp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_ARP))
    {
      g_info ("%s: ARP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_arp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE))
    {
      scanner.tcp_flag = TH_ACK;
      g_info ("%s: TCP-ACK Service Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_tcp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_TCP_SYN_SERVICE))
    {
      g_info ("%s: TCP-SYN Service Ping", __func__);
      scanner.tcp_flag = TH_SYN;
      g_hash_table_foreach (hosts_data.targethosts, send_tcp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_ICMP))
    {
      g_info ("%s: ICMP Ping", __func__);
      g_hash_table_foreach (hosts_data.targethosts, send_icmp, NULL);
    }
  else if (alive_test == (ALIVE_TEST_CONSIDER_ALIVE))
    g_info ("%s: Consider Alive", __func__);

  g_info ("%s: all ping packets are sent, wait a bit for rest of replies",
          __func__);
  sleep (5);
  g_info ("%s: finish waiting for replies", __func__);

  /* break sniffer loop */
  /* TODO: research problems breaking loop form other thread */
  pcap_breakloop (scanner.pcap_handle);
  g_info ("%s: pcap_breakloop", __func__);

  /* join sniffer thread*/
  if ((err = pthread_join (tid, NULL)) != 0)
    {
      g_error ("%s: pthread_join: %d", __func__, err);
    }
  g_info ("%s: joined thread", __func__);

  /* close handle */
  if (scanner.pcap_handle != NULL)
    {
      g_info ("%s: close pcap handle", __func__);
      pcap_close (scanner.pcap_handle);
    }

  g_info ("%s: scan for alive hosts ended", __func__);

  return 0;
}

static int
get_socket (enum socket_type socket_type)
{
  int soc;
  switch (socket_type)
    {
    case TCPV4:
      {
        int opt = 1;
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_error ("%s: failed to open TCPV4 socket: %s", __func__,
                     strerror (errno));
            return -1;
          }
        if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt,
                        sizeof (opt))
            < 0)
          {
            g_error ("%s: failed to set socket options on TCPV4 socket: %s",
                     __func__, strerror (errno));
            return -1;
          }
      }
      break;
    case TCPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_error ("%s: failed to open TCPV6 socket: %s", __func__,
                     strerror (errno));
            return -1;
          }

        int opt_on = 1;
        if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL,
                        (char *) &opt_on, // IPV6_HDRINCL
                        sizeof (opt_on))
            < 0)
          {
            g_error ("%s: failed to set socket options on TCPV6 socket: %s",
                     __func__, strerror (errno));
            return -1;
          }
      }
      break;
    case ICMPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (soc < 0)
          {
            g_critical ("%s: failed to open ICMPV4 socket: %s", __func__,
                        strerror (errno));
            return -1;
          }
      }
      break;
    case ARPV6:
    case ICMPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (soc < 0)
          {
            g_critical ("%s: failed to open ARPV6/ICMPV6 socket: %s", __func__,
                        strerror (errno));
            return -1;
          }
      }
      break;
    case ARPV4:
      {
        soc = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
        if (soc < 0)
          {
            g_critical ("%s: failed to open ARPV4 socket: %s", __func__,
                        strerror (errno));
            return -1;
          }
      }
      break;
    default:
      return -2;
      break;
    }
  return soc;
}

static int
alive_detection_init (gvm_hosts_t *hosts)
{
  g_info ("%s: initialise alive scanner", __func__);

  /* Scanner */
  /* sockets */
  if ((scanner.tcpv4soc = get_socket (TCPV4)) < 0)
    return -1;
  if ((scanner.tcpv6soc = get_socket (TCPV6)) < 0)
    return -2;
  if ((scanner.icmpv4soc = get_socket (ICMPV4)) < 0)
    return -3;
  if ((scanner.icmpv6soc = get_socket (ICMPV6)) < 0)
    return -4;
  if ((scanner.arpv4soc = get_socket (ARPV4)) < 0)
    return -5;
  if ((scanner.arpv6soc = get_socket (ARPV6)) < 0)
    return -6;
  /* sources */
  scanner.sourcev4 = NULL;
  scanner.sourcev6 = NULL;
  scanner.sourcearpv4 = NULL;
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
  /* put all hosts we want to check in hashtable */
  gvm_host_t *host;
  for (host = gvm_hosts_next (hosts); host; host = gvm_hosts_next (hosts))
    {
      g_hash_table_insert (hosts_data.targethosts, gvm_host_value_str (host),
                           host);
    }
  /* reset hosts iter */
  hosts->current = 0;

  g_info ("%s: initialisation of alive scanner finished", __func__);

  return 0;
}

int
alive_detection_free (void)
{
  int ret = 0;
  if ((close (scanner.tcpv4soc)) != 0)
    {
      ret = -1;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  if ((close (scanner.tcpv6soc)) != 0)
    {
      ret = -2;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  if ((close (scanner.icmpv4soc)) != 0)
    {
      ret = -3;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  if ((close (scanner.icmpv6soc)) != 0)
    {
      ret = -4;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  if ((close (scanner.arpv4soc)) != 0)
    {
      ret = -5;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  if ((close (scanner.arpv6soc)) != 0)
    {
      ret = -6;
      g_error ("%s: close(): %s", __func__, strerror (errno));
    }
  /*pcap_close (scanner.pcap_handle); //pcap_handle is closed in ping/scan
   * function for now */
  if ((kb_lnk_reset (scanner.main_kb)) != 0)
    {
      ret = -7;
      g_error ("%s: error in kb_lnk_reset()", __func__);
    }

  /* addresses */
  g_free (scanner.sourcev4);
  g_free (scanner.sourcev6);
  g_free (scanner.sourcearpv4);

  g_hash_table_destroy (hosts_data.alivehosts);
  /* targethosts: (ipstr, gvm_host_t *)
   * gvm_host_t are freed by caller of start_alive_detection()! */
  g_hash_table_destroy (hosts_data.targethosts);

  return ret;
}

/**
 * @brief start the send_tcp_syn scan of all specified hosts in gvm_hosts_t
 * list. Finish signal is put on Queue if pinger returned.
 *
 * @in: gvm_hosts_t structure which is to be freed by caller
 */
void *
start_alive_detection (void *args)
{
  int err;
  gvm_hosts_t *hosts = (gvm_hosts_t *) args;
  if ((err = alive_detection_init (hosts)) < 0)
    g_error ("%s: error in alive_detection_init(): %d", __func__, err);

  g_info ("%s: start scan()", __func__);
  /* blocks until detection process is finished */
  if (scan () < 0)
    g_error ("%s: error in scan()", __func__);

  /* put finish signal on Queue if all packets were sent and we waited long
   * enough for packets to arrive */
  if ((kb_item_push_str (scanner.main_kb, "alive_detection", "finish")) != 0)
    g_error ("%s: error in kb_item_push_str()", __func__);
  else
    g_info ("%s: alive detection process finished. finish signal put on Q.",
            __func__);

  if ((err = alive_detection_free ()) < 0)
    g_error ("%s: error in alive_detection_free(): %d", __func__, err);

  pthread_exit (0);
}