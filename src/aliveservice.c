#include "aliveservice.h"

// #include "../misc/pcap_openvas.h" /* islocalhost() */
// #include "../misc/bpf_share.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gvm/base/networking.h> /* gvm_source_addr() */
#include <gvm/base/prefs.h>      /* prefs_get() */
#include <gvm/util/kb.h>         /* kb_t operations */
#include <ifaddrs.h>             /* getifaddrs() */
#include <net/ethernet.h>        /* struct ether_addr ether_hdr */
#include <net/if.h>              /* IFF_LOOPBACK, if_nametoindex() */
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

/* for using int value in #defined string */
#define STR(X) #X
#define ASSTR(X) STR (X)
/* packets are sent to port 9910*/
#define FILTER_PORT 9910
#define FILTER_STR                                             \
  "(ip6 or ip or arp) and (icmp6 or icmp or dst port " ASSTR ( \
    FILTER_PORT) " or arp[6:2]=2)"

enum alive_detection
{
  ALIVE_DETECTION_FINISHED,
  ALIVE_DETECTION_SCANNING,
  ALIVE_DETECTION_OK,
  ALIVE_DETECTION_INIT,
  ALIVE_DETECTION_ERROR
};

/* data for tcp_ping */
struct tcp_ping
{
  int tcpv4soc;     /* socket */
  int tcpv6soc;     /* socket */
  uint8_t tcp_flag; /* TH_SYN or TH_ACK from <netinet/tcp.h> */
};

/* data for icmp_ping */
struct icmp_ping
{
  int icmpv4soc; /* socket */
  int icmpv6soc; /* socket */
};

/* data for arp_ping */
struct arp_ping
{
  int arpv4soc;
  int arpv6soc; /* is icmpv6soc */
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
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

/* global phandle for alive detection */
/* TODO: use static kb_t. connect to it on start and link_reset on finish */
pcap_t *handle;
static kb_t main_kb;
GHashTable *alivehosts;  /* (str, ?) */
GHashTable *targethosts; /* (str, gvm_host_t) */

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
  pcap_t *ret;
  struct bpf_program filter_prog;

  /* iface, snapshot length of handle, promiscuous mode, packet buffer timeout
   * (ms), errbuff */
  ret = pcap_open_live (iface, 1500, 1, 0, errbuf);
  if (ret == NULL)
    {
      g_message ("%s", errbuf);
      return NULL;
    }

  /* needed for our usage of pcap_break_loop() */
  pcap_setnonblock (ret, 1, errbuf);

  if (pcap_compile (ret, &filter_prog, filter, 1, 0) < 0)
    {
      char *msg = pcap_geterr (ret);
      g_message ("pcap_compile : %s", msg);
      pcap_close (ret);
      return NULL;
    }

  if (pcap_setfilter (ret, &filter_prog) < 0)
    {
      char *msg = pcap_geterr (ret);
      g_message ("pcap_setfilter : %s", msg);
      pcap_close (ret);
      return NULL;
    }
  pcap_freecode (&filter_prog);

  return ret;
}

int
islocalhost_v6 (struct in6_addr *addr)
{
  int ret = 0;
  if (!addr)
    return -1;

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      /* Adde starts with 127.0.0.1 */
      if ((addr->s6_addr32[3] & htonl (0xFF000000)) == htonl (0x7F000000))
        return 1;
      /* Addr is 0.0.0.0 */
      if (!addr->s6_addr32[3])
        return 1;
    }

  if (IN6_IS_ADDR_LOOPBACK (addr))
    return 1;

  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs (&ifaddr) == -1)
    return -1;

  /* Search for the adequate interface/family. */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_addr->sa_family == AF_INET6)
        {
          struct sockaddr_in6 *addr2;

          addr2 = (struct sockaddr_in6 *) ifa->ifa_addr;
          // memcpy (&global_source_addr6.s6_addr, &addr2->sin6_addr,
          //         sizeof (struct in6_addr));
          if (IN6_ARE_ADDR_EQUAL (addr2, addr))
            ret = 1;
        }
    }
  freeifaddrs (ifaddr);
  return ret;
}

/**
 * @brief checks if addr is likely to be localhost
 *
 * @in: addr to check
 * @out: 1 if localhost, -1 on error
 * TODO: either make working for ipv6 too or write seperate method
 * ipv6islocalhost()
 */
int
islocalhost (struct in_addr *addr)
{
  int ret = 0;
  if (!addr)
    return -1;

  /* Addr is 0.0.0.0 */
  if (!addr->s_addr)
    return 1;
  /* Addr starts with 127. */
  if ((addr->s_addr & htonl (0xFF000000)) == htonl (0x7F000000))
    return 1;

  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs (&ifaddr) == -1)
    return -1;

  /* Search for the adequate interface/family. */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_addr->sa_family == AF_INET)
        {
          struct in_addr *addr2 =
            &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;

          /* TODO: maybe compare strings instead of addresses */
          if ((int) (*addr).s_addr == (int) (*addr2).s_addr)
            ret = 1;
        }
      /* TODO: ipv6
       * else if (ifa->ifa_addr->sa_family == AF_INET6)
       */
    }
  freeifaddrs (ifaddr);
  return ret;
}

/**
 * @brief get new item from queue
 *
 * @in: flag which is set to status of scan process
 * @out: host_string or NULL if no item present or finish signal
 */
static char *
get_alive_host_str (int *flag)
{
  char *host = NULL;
  /* handle race condition. main_kb may not yet be initialized */
  /* TODO: find better solution  */
  if (!main_kb)
    {
      *flag = ALIVE_DETECTION_INIT;
      return NULL;
    }

  host = kb_item_pop_str (main_kb, ("alive_detection"));
  /* 3 if item is not found return NULL and set flag to ALIVE_DETECTION_SCANNING
   */
  if (host == NULL)
    {
      *flag = ALIVE_DETECTION_SCANNING;
      return NULL;
    }
  /* 3 if item is 'finish' return NULL and set flag to ALIVE_DETECTION_FINISHED
   */
  else if (host != NULL && (g_strcmp0 (host, "finish") == 0))
    {
      *flag = ALIVE_DETECTION_FINISHED;
      return NULL;
    }
  /* 3 if item is host_str return host_str and set flag to ALIVE_DETECTION_OK */
  else
    {
      *flag = ALIVE_DETECTION_OK;
      return host;
    }
}

/**
 * @brief get new host from queue and put it into an gvm_host_t struct
 *
 * @in:  timeout for waiting for new alive host. If timout <= 0 we wait
 * 'indefinetly'(INT_MAX seconds)
 * @out: host structure from Queue
 *
 */
gvm_host_t *
get_host_from_queue (int timeout)
{
  /* default timeout is indef. (until alive detection process is finished) */
  if (timeout <= 0)
    timeout = INT_MAX;

  char *host_str = NULL;
  int alive_detection_flag = 0;
  gvm_host_t *host = NULL;

  g_message ("%s: get new host from Queue", __func__);
  host_str = get_alive_host_str (
    &alive_detection_flag); /* get host string from Queue or NULL*/

  if (host_str)
    host = gvm_host_from_str (host_str);
  while (!host && (alive_detection_flag != ALIVE_DETECTION_FINISHED)
         && timeout--)
    {
      sleep (1);
      host_str = get_alive_host_str (&alive_detection_flag);
      host = gvm_host_from_str (host_str);
    }

  if (alive_detection_flag == ALIVE_DETECTION_FINISHED)
    {
      host = NULL;
    }
  g_free (host_str);
  return host;
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 * From ping examples in W.Richard Stevens "UNIX NETWORK PROGRAMMING" book.
 * TODO:
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

/* TODO: simplify */
void
got_packet (__attribute__ ((unused)) u_char *args,
            __attribute__ ((unused)) const struct pcap_pkthdr *header,
            const u_char *packet)
{
  g_message ("%s: sniffed some packet", __func__);

  // gchar addr_str1[INET_ADDRSTRLEN];
  // struct sniff_ethernet *ether = (struct sniff_ethernet *) (packet + 2);
  // inet_ntop (AF_INET, (const char *) ether->ether_dhost, addr_str1,
  //            INET_ADDRSTRLEN);
  // g_message ("%s: IP version = 4, addr: %s", __func__, addr_str1);
  // inet_ntop (AF_INET, (const char *) ether->ether_shost, addr_str1,
  //            INET_ADDRSTRLEN);
  // g_message ("%s: IP version = 4, addr: %s", __func__, addr_str1);
  // // printipv4(ether->ether_dhost);
  // // printipv4(ether->ether_shost);
  // g_message ("%s: type:%x", __func__, (unsigned int) ether->ether_type);
  struct ip *ip = (struct ip *) (packet + 16); // why not 14(ethernet size)??
  unsigned int version = ip->ip_v;
  g_message ("IP version: %x", ip->ip_v);

  if (version == 4)
    {
      gchar addr_str[INET_ADDRSTRLEN];
      struct in_addr sniffed_addr;
      /* was +26 (14 ETH + 12 IP) originally but was off by 2 somehow */
      memcpy (&sniffed_addr.s_addr, packet + 26 + 2, 4);
      inet_ntop (AF_INET, (const char *) &sniffed_addr, addr_str,
                 INET_ADDRSTRLEN);
      g_message ("%s: IP version = 4, addr: %s", __func__, addr_str);

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are seaching for. */
      if (g_hash_table_add (alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (targethosts, addr_str) == TRUE)
        {
          g_message ("%s: Thread sniffed unique address to put on queue: %s",
                     __func__, addr_str);
          kb_item_push_str (main_kb, "alive_detection", addr_str);
        }
    }
  else if (version == 6)
    {
      gchar addr_str[INET6_ADDRSTRLEN];
      struct in6_addr sniffed_addr;
      /* (14 ETH + 8 IP + offset 2)  */
      memcpy (&sniffed_addr.s6_addr, packet + 24, 16);
      inet_ntop (AF_INET6, (const char *) &sniffed_addr, addr_str,
                 INET6_ADDRSTRLEN);
      g_message ("%s: IP version = 6, addr: %s", __func__, addr_str);

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are seaching for. */
      if (g_hash_table_add (alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (targethosts, addr_str) == TRUE)
        {
          g_message ("%s: Thread sniffed unique address to put on queue: %s",
                     __func__, addr_str);
          kb_item_push_str (main_kb, "alive_detection", addr_str);
        }
    }
}

static void *
sniffer_thread (__attribute__ ((unused)) void *vargp)
{
  int ret;
  g_message ("%s: start sniffing", __func__);

  /* reads packets until error or pcap_breakloop() */
  if ((ret = pcap_loop (handle, -1, got_packet, NULL)) == PCAP_ERROR)
    g_warning ("%s: pcap_loop error %s", __func__, pcap_geterr (handle));
  else if (ret == 0)
    g_warning ("%s: count of packets is exhausted", __func__);
  else if (ret == PCAP_ERROR_BREAK)
    g_message ("%s: Loop was succesfully broken after call to pcap_breakloop",
               __func__);

  pthread_exit (0);
}

static void
set_src_addr_v6 (struct in6_addr *src)
{
  /* check if src addr already set. get host addr if not already set. */
  char buf[400];
  gvm_source_addr6 (src);
  /* check if src addr is not null */
  int addr_was_set = 0;
  for (int i = 0; i < 16; ++i)
    {
      addr_was_set |= src->s6_addr[i];
    }
  if (addr_was_set)
    {
      g_debug ("%s: We use global_source_addr as src because it was "
               "already set by apply_source_iface_preference: %s",
               __func__, inet_ntop (AF_INET6, src, (char *) &buf, 400));
    }
  else
    {
      /* TODO: put in seperate function */
      struct ifaddrs *ifaddr, *ifa;
      if (getifaddrs (&ifaddr) == -1)
        return;
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (!ifa->ifa_addr)
            {
              continue;
            }
          if (ifa->ifa_addr->sa_family == AF_INET6)
            {
              struct sockaddr_in6 *addr2;

              addr2 = (struct sockaddr_in6 *) ifa->ifa_addr;
              memcpy (src, &addr2->sin6_addr, sizeof (struct in6_addr));
            }
        }
    }
  g_debug ("%s: address set to: %s", __func__,
           inet_ntop (AF_INET6, src, (char *) &buf, 400));
}

static void
set_src_addr (struct in_addr *src)
{
  /* check if src addr already set. get host addr if not already set. */
  gvm_source_addr (src);
  if (src->s_addr)
    {
      g_debug ("%s: We use global_source_addr as src because it was "
               "already set by apply_source_iface_preference",
               __func__);
    }
  else
    {
      /* TODO: put in seperate function */
      struct ifaddrs *ifaddr, *ifa;
      if (getifaddrs (&ifaddr) == -1)
        return; // better return value or message
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (!ifa->ifa_addr)
            {
              continue;
            }
          if (ifa->ifa_addr->sa_family == AF_INET)
            {
              struct in_addr *addr =
                &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;

              memcpy (src, addr, sizeof (struct in_addr));
            }
          /* ipv6 */
          /* else if (ifa->ifa_addr->sa_family == AF_INET6){} */
        }
    }
}

static int
get_arpv4soc (void)
{
  int soc;
  soc = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (soc < 0)
    {
      g_critical ("%s: failed to set arpv4soc for alive detection: %s",
                  __func__, strerror (errno));
      return -1;
    }
  return soc;
}

static int
get_icmpv4soc (void)
{
  int soc;
  soc = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (soc < 0)
    {
      g_critical ("%s: failed to set ipv6socket for alive detection: %s",
                  __func__, strerror (errno));
      return -1;
    }
  return soc;
}

static int
get_tcpv4soc (void)
{
  int soc;
  int opt = 1;
  soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    {
      g_critical ("%s: failed to open socker for alive detection: %s", __func__,
                  strerror (errno));
      return -1;
    }
  if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt, sizeof (opt)) < 0)
    {
      g_critical (
        "%s: failed to set socket options on alive detection socket: %s",
        __func__, strerror (errno));
      return -1;
    }
  return soc;
}

static int
get_icmpv6soc (void)
{
  int soc;
  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (soc < 0)
    {
      g_critical ("%s: failed to set ipv6socket for alive detection: %s",
                  __func__, strerror (errno));
      return -1;
    }
  return soc;
}

static int
get_tcpv6soc (void)
{
  int soc;
  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    {
      g_critical ("%s: failed to set ipv6socket for alive detection: %s",
                  __func__, strerror (errno));
      return -1;
    }

  int opt_on = 1;
  if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL,
                  (char *) &opt_on, // IPV6_HDRINCL
                  sizeof (opt_on))
      < 0)
    {
      g_critical (
        "%s: failed to set socket options on alive detection socket: %s",
        __func__, strerror (errno));
      return -1;
    }
  return soc;
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
__attribute__ ((unused)) static int
get_source_mac_addr (gchar *interface, uint8_t *mac)
{
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  int interface_provided = 0;

  if (interface)
    interface_provided = 1;

  if (getifaddrs (&ifaddr) == -1)
    {
      perror ("getifaddrs");
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
send_icmp_v6 (int soc, struct in6_addr *dst)
{
  g_message ("%s: send imcpv6", __func__);

  struct sockaddr_in6 soca;
  char sendbuf[1500];
  int len;
  int datalen = 56;
  struct icmp6_hdr *icmp6;

  icmp6 = (struct icmp6_hdr *) sendbuf;
  icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = 234; //
  icmp6->icmp6_seq = 0;  //

  memset ((icmp6 + 1), 0xa5, datalen);
  gettimeofday ((struct timeval *) (icmp6 + 1), NULL); // only for testing
  len = 8 + datalen;

  /* send packet */
  bzero (&soca, sizeof (struct sockaddr_in6));
  soca.sin6_family = AF_INET6;
  soca.sin6_addr = *dst;

  printipv6 (dst);
  sendto (soc, sendbuf, len, 0, (struct sockaddr *) &soca,
          sizeof (struct sockaddr_in6));
}

static void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  g_message ("%s: IN ICMP func", __func__);
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
  icmp->icmp_cksum = np_in_cksum ((u_short *) icmp, len);

  bzero (&soca, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  printipv4 (dst);
  if (sendto (soc, sendbuf, len, 0, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    g_warning ("sendto: %s", strerror (errno));
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
static void
send_icmp (__attribute__ ((unused)) gpointer key, gpointer value,
           gpointer user_data)
{
  struct icmp_ping icmp_ping = *((struct icmp_ping *) user_data);

  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_message ("could not get addr6 from gvm_host_t");
  if (dst6_p == NULL)
    g_message ("dst6_p == NULL");
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      g_message ("got ipv6 address to handle");
      send_icmp_v6 (icmp_ping.icmpv6soc, dst6_p);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_icmp_v4 (icmp_ping.icmpv4soc, dst4_p);
    }
}

static void
send_tcp_v6 (int soc, struct in6_addr *dst_p, uint8_t tcp_flag)
{
  g_message ("%s:ipv6", __func__);
  struct sockaddr_in6 soca;

  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));

  struct in6_addr src;

  int port = 0;
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,  6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548, 5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080};

  if (islocalhost_v6 (dst_p) > 0)
    src = *dst_p;
  else
    set_src_addr_v6 (&src);

  /* for ports in portrange send packets */
  for (long unsigned int i = 0; i < sizeof (ports) / sizeof (int); i++)
    {
      bzero (packet, sizeof (packet));
      /* IPv6 */
      ip->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
      ip->ip6_plen = htons (20); // TCP_HDRLEN
      ip->ip6_nxt = IPPROTO_TCP;
      ip->ip6_hops = 255; // max value

      printipv6 (&src);
      printipv6 (dst_p);
      ip->ip6_src = src;
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

        bzero (&pseudoheader, 38 + sizeof (struct tcphdr));
        memcpy (&pseudoheader.s6addr, &ip->ip6_src, sizeof (struct in6_addr));
        memcpy (&pseudoheader.d6addr, &ip->ip6_dst, sizeof (struct in6_addr));

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
      /*  TCP_HDRLEN(20) IP6_HDRLEN(40) */
      if (sendto (soc, (const void *) ip, 40 + 20, 0, (struct sockaddr *) &soca,
                  sizeof (struct sockaddr_in6))
          < 0)
        g_warning ("sendto: %s", strerror (errno));
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
  if (islocalhost (dst_p) > 0)
    src.s_addr = dst_p->s_addr;
  else
    set_src_addr (&src);

  /* for ports in portrange send packets */
  for (long unsigned int i = 0; i < sizeof (ports) / sizeof (int); i++)
    {
      bzero (packet, sizeof (packet));
      /* IP */
      ip->ip_hl = 5;
      ip->ip_off = htons (0);
      ip->ip_v = 4;
      ip->ip_len = htons (40);
      ip->ip_tos = 0;
      ip->ip_p = IPPROTO_TCP;
      ip->ip_id = rand ();
      ip->ip_ttl = 0x40;
      ip->ip_src = src;
      ip->ip_dst = *dst_p;
      ip->ip_sum = 0;
      ip->ip_sum = np_in_cksum ((u_short *) ip, 20);

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

        bzero (&pseudoheader,
               12 + sizeof (struct tcphdr)); // bzero is deprecated. use
                                             // memset(3) instead
        pseudoheader.saddr.s_addr = source.s_addr;
        pseudoheader.daddr.s_addr = dest.s_addr;

        pseudoheader.protocol = 6; // IPPROTO_TCP
        pseudoheader.length = htons (sizeof (struct tcphdr));
        bcopy ((char *) tcp,
               (char *) &pseudoheader.tcpheader, // bcopy is deprecated. use
                                                 // memcpy(3) or memmove(3) ?
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
    }
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
static void
send_tcp (__attribute__ ((unused)) gpointer key, gpointer value,
          gpointer user_data)
{
  g_message ("%s: try to send", __func__);

  struct tcp_ping tcp_ping = *((struct tcp_ping *) user_data);

  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_message ("could not get addr6 from gvm_host_t");
  if (dst6_p == NULL)
    g_message ("dst6_p == NULL");
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      g_message ("got ipv6 address to handle");
      send_tcp_v6 (tcp_ping.tcpv6soc, dst6_p, tcp_ping.tcp_flag);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      printipv4 (dst4_p);
      send_tcp_v4 (tcp_ping.tcpv4soc, dst4_p, tcp_ping.tcp_flag);
    }
}

void
send_arp_v4 (__attribute__ ((unused)) int soc, struct in_addr *dst_p,
             uint8_t *src_mac, __attribute__ ((unused)) uint8_t *dst_mac)
{
  g_message ("%s: SENDING ARP", __func__);
  struct sockaddr_ll soca;
  struct in_addr src;
  struct arp_hdr arphdr;
  int frame_length;
  uint8_t *ether_frame;

  /* get src address */
  if (islocalhost (dst_p) > 0)
    src.s_addr = dst_p->s_addr;
  else
    set_src_addr (&src);

  /* sockaddr_ll */
  /* TODO: get index of interface a other way */
  memset (&soca, 0, sizeof (soca));
  // soca.sll_ifindex = 1;
  if ((soca.sll_ifindex = if_nametoindex ("enp0s3")) == 0)
    {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }
  printf ("Index for interface  is %i\n", soca.sll_ifindex);
  soca.sll_family = AF_PACKET;
  memcpy (soca.sll_addr, src_mac, 6 * sizeof (uint8_t));
  soca.sll_halen = 6;

  /* IP addresses */
  memcpy (&arphdr.target_ip, dst_p, 4 * sizeof (uint8_t));
  memcpy (&arphdr.sender_ip, &src, 4 * sizeof (uint8_t));

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
  ether_frame = g_malloc0 (IP_MAXPACKET); /* TODO: error handling */
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
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }

  g_free (ether_frame);

  return;
}

/* check if ipv6 or ipv4, get correct socket and start ping function */
static void
send_arp (__attribute__ ((unused)) gpointer key, gpointer value,
          gpointer user_data)
{
  g_message ("%s: check what ip received", __func__);

  struct arp_ping arp_ping = *((struct arp_ping *) user_data);

  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_message ("could not get addr6 from gvm_host_t");
  if (dst6_p == NULL)
    g_message ("dst6_p == NULL");
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      g_message ("got ipv6 address to handle");
      g_message ("Not implemented yet!");
      // send_tcp_v
      // (arp_ping.arpv6soc, dst6_p, arp_ping.tcp_flag);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      printipv4 (dst4_p);
      send_arp_v4 (arp_ping.arpv4soc, dst4_p, arp_ping.src_mac,
                   arp_ping.dst_mac);
    }
}

static int
ping (void)
{
  pthread_t tid; /* thread id */

  handle = open_live (NULL, FILTER_STR);

  /* get ALIVE_TEST enum */
  alive_test_t alive_test = atoi (prefs_get ("ALIVE_TEST"));
  if (alive_test
      == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    g_message ("%s: ICMP, TCP-ACK Service & ARP Ping", __func__);
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ARP))
    g_message ("%s: TCP-ACK Service & ARP Ping", __func__);
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_ARP))
    g_message ("%s: ICMP & ARP Ping", __func__);
  else if (alive_test == (ALIVE_TEST_ICMP | ALIVE_TEST_TCP_ACK_SERVICE))
    g_message ("%s: ICMP & TCP-ACK Service Ping", __func__);
  else if (alive_test == (ALIVE_TEST_ARP))
    {
      g_message ("%s: ARP Ping", __func__);
      pthread_create (&tid, NULL, sniffer_thread, NULL);

      struct arp_ping arp_ping = {.arpv4soc = get_arpv4soc (),
                                  .arpv6soc = get_icmpv6soc ()};
      bzero (&arp_ping.src_mac, 6 * sizeof (uint8_t));
      memset (arp_ping.dst_mac, 0xff, 6 * sizeof (uint8_t));

      get_source_mac_addr ("enp0s3", (unsigned char *) &arp_ping.src_mac);
      g_message ("%02x:%02x:%02x:%02x:%02x:%02x", arp_ping.src_mac[0],
                 arp_ping.src_mac[1], arp_ping.src_mac[2], arp_ping.src_mac[3],
                 arp_ping.src_mac[4], arp_ping.src_mac[5]);
      g_message ("%02x:%02x:%02x:%02x:%02x:%02x", arp_ping.dst_mac[0],
                 arp_ping.dst_mac[1], arp_ping.dst_mac[2], arp_ping.dst_mac[3],
                 arp_ping.dst_mac[4], arp_ping.dst_mac[5]);
      sleep (2);
      g_hash_table_foreach (targethosts, send_arp, &arp_ping);
      // 3. get source address
      /* wait for replies and break loop */
      sleep (3);
      pcap_breakloop (handle);
      g_message ("%s: break_loop", __func__);

      /* join thread */
      if (pthread_join (tid, NULL) != 0)
        g_warning ("%s: got error from pthread_join", __func__);
      g_message ("%s: join thread", __func__);

      close (arp_ping.arpv4soc);
      close (arp_ping.arpv6soc);
      g_message ("%s: close tcp_ack_ping sockets ", __func__);
    }
  else if (alive_test == (ALIVE_TEST_TCP_ACK_SERVICE))
    {
      g_message ("%s: TCP-ACK Service Ping", __func__);
      struct tcp_ping tcp_ping = {.tcpv4soc = get_tcpv4soc (),
                                  .tcpv6soc = get_tcpv6soc (),
                                  .tcp_flag = TH_ACK};

      pthread_create (&tid, NULL, sniffer_thread, NULL);
      /* give sniffer thread time to start */
      sleep (2);
      g_hash_table_foreach (targethosts, send_tcp, &tcp_ping);

      /* wait for replies and break loop */
      sleep (3);
      pcap_breakloop (handle);
      g_message ("%s: break_loop", __func__);

      /* join thread */
      if (pthread_join (tid, NULL) != 0)
        g_warning ("%s: got error from pthread_join", __func__);
      g_message ("%s: join thread", __func__);

      /* exclude alivehosts form targethosts so we dont test them again */
      g_hash_table_foreach (alivehosts, exclude, targethosts);
      close (tcp_ping.tcpv4soc);
      close (tcp_ping.tcpv6soc);
      g_message ("%s: close tcp_ack_ping sockets ", __func__);
    }
  else if (alive_test == (ALIVE_TEST_TCP_SYN_SERVICE))
    {
      g_message ("%s: TCP-SYN Service Ping", __func__);
      struct tcp_ping tcp_ping = {.tcpv4soc = get_tcpv4soc (),
                                  .tcpv6soc = get_tcpv6soc (),
                                  .tcp_flag = TH_SYN};

      pthread_create (&tid, NULL, sniffer_thread, NULL);
      /* give sniffer thread time to start */
      sleep (2);
      g_hash_table_foreach (targethosts, send_tcp, &tcp_ping);

      /* wait for replies and break loop */
      sleep (3);
      pcap_breakloop (handle);
      g_message ("%s: break_loop", __func__);

      /* join thread*/
      if (pthread_join (tid, NULL) != 0)
        g_warning ("%s: got error from pthread_join", __func__);
      g_message ("%s: join thread", __func__);

      /* exclude alivehosts form targethosts so we dont test them again */
      g_hash_table_foreach (alivehosts, exclude, targethosts);

      close (tcp_ping.tcpv4soc);
      close (tcp_ping.tcpv6soc);
      g_message ("%s: close tcp_syn_ping sockets ", __func__);
    }
  else if (alive_test == (ALIVE_TEST_ICMP))
    {
      g_message ("%s: ICMP Ping", __func__);

      struct icmp_ping icmp_ping = {.icmpv4soc = get_icmpv4soc (),
                                    .icmpv6soc = get_icmpv6soc ()};

      pthread_create (&tid, NULL, sniffer_thread, NULL);
      sleep (2);
      g_hash_table_foreach (targethosts, send_icmp, &icmp_ping);

      /* wait for replies and break loop */
      sleep (3);
      pcap_breakloop (handle);
      g_message ("%s: break_loop", __func__);

      /* join thread*/
      if (pthread_join (tid, NULL) != 0)
        g_warning ("%s: got error from pthread_join", __func__);
      g_message ("%s: join thread", __func__);

      /* exclude alivehosts form targethosts so we dont test them again */
      g_hash_table_foreach (alivehosts, exclude, targethosts);

      close (icmp_ping.icmpv4soc);
      close (icmp_ping.icmpv6soc);
      g_message ("%s: close icmp_ping sockets ", __func__);
    }
  else if (alive_test == (ALIVE_TEST_CONSIDER_ALIVE))
    g_message ("%s: Consider Alive", __func__);

  /* close handle */
  if (handle != NULL)
    {
      g_message ("%s: close pcap handle", __func__);
      pcap_close (handle);
    }

  return 0;
}

/**
 * @brief start the send_tcp_syn scan of all specified hosts in gvm_hosts_t
 * list. Finish signal is put on Queue if pinger returned.
 *
 * @in: gvm_hosts_t structure
 */
void *
start_alive_detection (void *args)
{
  gvm_hosts_t *hosts = (gvm_hosts_t *) args;
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  /* This kb_t is only used once every alive detection process */
  main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id);

  targethosts = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  alivehosts = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  /* put all hosts we want to check in hashtable */
  gvm_host_t *host;
  for (host = gvm_hosts_next (hosts); host; host = gvm_hosts_next (hosts))
    {
      g_hash_table_insert (targethosts, gvm_host_value_str (host), host);
    }
  /* reset iter */
  hosts->current = 0;

  g_message ("%s: alive detection process started", __func__);
  /* blocks until detection process is finished */
  if (ping () < 0)
    g_warning ("%s: pinger returned some error code", __func__);

  /* put finish signal on Q if all packets were send and we waited long enough
   * for packets to arrive */
  kb_item_push_str (main_kb, "alive_detection", "finish");
  kb_lnk_reset (main_kb);

  g_message ("%s: alive detection process finished. finish signal put on Q.",
             __func__);

  // g_message ("%s sleep.", __func__);
  // sleep(50); // debugging process termination
  // g_message ("%s: slept.", __func__);
  g_hash_table_destroy (targethosts);
  g_hash_table_destroy (alivehosts);

  pthread_exit (0);
}