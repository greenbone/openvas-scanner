#include "aliveservice.h"

// #include "../misc/pcap_openvas.h" /* islocalhost() */
// #include "../misc/bpf_share.h"

#include <arpa/inet.h>
#include <errno.h>               /* for errno */
#include <gvm/base/networking.h> /* gvm_source_addr() */
#include <gvm/base/prefs.h>      /* for prefs_get() */
#include <gvm/util/kb.h>         /* kb_t ... */
#include <ifaddrs.h>             /* for getifaddrs() */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>    /* pcap functions*/
#include <pthread.h> /* for threading */
#include <sys/param.h>
#include <sys/wait.h> /* for waitpid() */
#include <unistd.h>

enum alive_detection
{
  ALIVE_DETECTION_FINISHED,
  ALIVE_DETECTION_SCANNING,
  ALIVE_DETECTION_OK,
  ALIVE_DETECTION_ERROR
};

/* global phandle for alive detection */
/* TODO: use static kb_t. connect to it on start and link_reset on finish */
pcap_t *handle;
static kb_t main_kb;
GHashTable *hashtable;

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

/* pid of alive detection process*/
static int alive_detection_pid = 0;

/**
 * @brief returns pid of alive detection process
 * @out: pid of alive detection process
 */
int
get_alive_detection_pid (void)
{
  return alive_detection_pid;
}
/**
 * @brief set alive detection pid
 *
 * @in: pid to set
 */
void
set_alive_detection_pid (int pid)
{
  alive_detection_pid = pid;
}

/**
 * @brief kill alive detection process if pid is available
 * TODO: use waitpid to check status before killing
 */
void
kill_alive_detection_process (void)
{
  g_message ("we need to kill the microservice with pid: %d",
             get_alive_detection_pid ());
  if (!get_alive_detection_pid ())
    return;
  if (kill (get_alive_detection_pid (), SIGKILL) < 0)
    {
      g_message ("some error occured when trying to kill the alive detection "
                 "child. maybe it already exited");
    }
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
char *
get_alive_host_str (int *flag)
{
  /* This kb_t is used at minimum once every second
   * and at most as often as new alive hosts arrive
   * TODO: use global main_kb or other method */
  kb_t main_kb;
  char *host = NULL;

  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id);
  host = kb_item_pop_str (main_kb, ("alive_detection"));
  /* 3 if item is not found return NULL and set flag to ALIVE_DETECTION_SCANNING
   */
  if (host == NULL)
    {
      *flag = ALIVE_DETECTION_SCANNING;
      kb_lnk_reset (main_kb);
      return NULL;
    }
  /* 3 if item is 'finish' return NULL and set flag to ALIVE_DETECTION_FINISHED
   */
  else if (host != NULL && (g_strcmp0 (host, "finish") == 0))
    {
      *flag = ALIVE_DETECTION_FINISHED;
      kb_lnk_reset (main_kb);
      return NULL;
    }
  /* 3 if item is host_str return host_str and set flag to ALIVE_DETECTION_OK */
  else
    {
      *flag = ALIVE_DETECTION_OK;
      kb_lnk_reset (main_kb);
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
    {
      timeout = INT_MAX;
    }

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

/* TODO: */
struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcphdr tcpheader;
};

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

// // copy of function in attack.c
// static void
// fork_sleep (int n)
// {
//   time_t then, now;

//   now = then = time (NULL);
//   while (now - then < n)
//     {
//       waitpid (-1, NULL, WNOHANG);
//       usleep (10000);
//       now = time (NULL);
//     }
// }

void
got_packet (__attribute__ ((unused)) u_char *args,
            __attribute__ ((unused)) const struct pcap_pkthdr *header,
            const u_char *packet)
{
  struct in_addr sniffed_addr;
  /* was +26 originally but was off by 2 somehow */
  memcpy (&sniffed_addr.s_addr, packet + 26 + 2, 4);
  if (g_hash_table_insert (hashtable, inet_ntoa (sniffed_addr), NULL))
    {
      g_message ("%s: Thread sniffed unique address to put on queue: %s",
                 __func__, inet_ntoa (sniffed_addr));
      kb_item_push_str (main_kb, "alive_detection", inet_ntoa (sniffed_addr));
    }
}

static void *
sniffer_thread (__attribute__ ((unused)) void *vargp)
{
  // static kb_t main_kb;
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id);

  int ret;
  /* global hashtable of alive hosts */
  hashtable = g_hash_table_new (g_str_hash, g_str_equal);
  g_message ("%s: start sniffing", __func__);

  /* reads packets until error or pcap_breakloop() */
  if ((ret = pcap_loop (handle, -1, got_packet, NULL)) == PCAP_ERROR)
    g_warning ("%s: pcap_loop error %s", __func__, pcap_geterr (handle));
  else if (ret == 0)
    g_warning ("%s: count of packets is exhausted", __func__);
  else if (ret == PCAP_ERROR_BREAK)
    g_message ("%s: Loop was succesfully broken after call to pcap_breakloop",
               __func__);

  kb_lnk_reset (main_kb);
  pthread_exit (0);
}

/**
 * @brief Create new filter for src host ip addresses given by a gvm_hosts_t
 * list. It can be specified how many ip addresses are used by the filter.
 *
 * makes filter of the form "ip and (src host 192.168.1.2 or 192.168.1.3 or
 * 192.168.1.4)"
 *
 * @param filter  this string is set with the GString to filter for
 * @param hosts   list of hosts to filter for
 * @param from    begin of 'slice' of hosts list we want to filter for
 * @param to     end of 'slice' of hosts list we want to filter for
 *
 */
static void
create_filter (GString *filter, gvm_hosts_t *hosts, int from, int to)
{
  gvm_host_t *host;

  /* save current index of gvm_hosts_t */
  int iter_index = hosts->current;
  /* set iterator to where to start adding hosts to the filter */
  if (from < (int) hosts->count && to < (int) hosts->count)
    hosts->current = from;

  g_string_append (filter, "ip and (src host ");
  char *host_value_str;

  host = gvm_hosts_next (hosts);
  for (; from < to && host; from++)
    {
      host_value_str = gvm_host_value_str (host);
      g_string_append (filter, host_value_str);
      g_free (host_value_str);

      host = gvm_hosts_next (hosts);
      if (host && (from != to - 1))
        g_string_append (filter, " or src host ");
    }
  g_string_append (filter, ")");

  g_message ("%s: new filter: %s", __func__, filter->str);

  /* get iterator into original state */
  hosts->current = iter_index;
}

/**
 * @brief
 * - make pcap filter with all hosts we want to test
 * - start sniffing
 * - send tcp-syn to all those hosts
 * - put answered packets on hashlist
 *
 * @in: gvm_hosts_t structure
 *
 */
int
my_tcp_ping (gvm_hosts_t *hosts)
{
  if (!hosts)
    return -1;

  struct in6_addr dst_p;
  struct in6_addr *dst = &dst_p;
  struct in_addr inaddr;
  struct in_addr src;
  u_char packet[sizeof (struct ip) + sizeof (struct tcphdr)];
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip));
  struct sockaddr_in soca;
  int port = 0;
  int opt = 1;
  int soc;
  int ports[] = {139, 135, 445,  80,    22,   515, 23,  21,  6000, 1025,
                 25,  111, 1028, 9100,  1029, 79,  497, 548, 5000, 1917,
                 53,  161, 9001, 65535, 443,  113, 993, 8080};

  int hosts_tested = 1;
  gvm_host_t *host;
  pthread_t tid;

  /* Get socket descriptor */
  soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    {
      g_critical (
        "%s: failed to set socket options on alive detection socket: %s",
        __func__, strerror (errno));
      return -1;
    }
  if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt, sizeof (opt)) < 0)
    {
      g_critical (
        "%s: failed to set socket options on alive detection socket: %s",
        __func__, strerror (errno));
      return -1;
    }

  /* define filter of hosts in hosts_list */
  GString *filter = g_string_new (NULL);
  create_filter (filter, hosts, 0, hosts->count);

  /* get pcap handle */
  handle = open_live (NULL, filter->str);

  /* start new sniffer thread */
  pthread_create (&tid, NULL, sniffer_thread, NULL);
  // pthread_detach (tid);

  /**
   * For all hosts construct packets an send them.
   * Replies are handled by the sniffer_thread.
   */
  do
    {
      host = gvm_hosts_next (hosts);
      if (!host)
        continue;
      if (gvm_host_get_addr6 (host, dst) < 0)
        g_message ("%s: Some error while gvm_host_get_addr6", __func__);
      if (dst == NULL || (IN6_IS_ADDR_V4MAPPED (dst) != 1))
        {
          g_debug ("%s: is ipv6 addr", __func__);
          /* TODO: ipv6 */
          return -1;
        }
      inaddr.s_addr = dst->s6_addr32[3];

      if (islocalhost (&inaddr) > 0)
        {
          src.s_addr = dst->s6_addr32[3];
        }
      else
        {
          /* check if src addr already set. get host addr if not already set. */
          gvm_source_addr (&src);
          if (src.s_addr)
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
                return -1; // better return value or message
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

                      memcpy (&src, addr, sizeof (src));
                    }
                  /* ipv6 */
                  /* else if (ifa->ifa_addr->sa_family == AF_INET6){} */
                }
            }
          // bzero (&src, sizeof (src));
          // routethrough ( &inaddr, &src); // old function
          // int size = INET_ADDRSTRLEN;
          // char *addr_str = g_malloc0 (size);
          // g_debug ("source address used: %s",
          // inet_ntop (AF_INET, &src, addr_str, INET_ADDRSTRLEN));
        }

      /* send packets in bursts. sleept for 1 sec in between
       * TODO: timing options? */
      if (hosts_tested % 333 == 0)
        {
          g_message (
            "sleep for 1 sec after batch of packets was sent. time: %lu\n",
            (unsigned long) time (NULL));
          /* */
          // fork_sleep (1);
          sleep (1);
          g_message (
            "sleep for 1 sec after batch of packets was sent. time: %lu\n",
            (unsigned long) time (NULL));
        }

      /* for portrange in ports */
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
          ip->ip_dst = inaddr;
          ip->ip_sum = 0;
          ip->ip_sum = np_in_cksum ((u_short *) ip, 20);

          /* TCP */
          tcp->th_sport = htons (rand () % 65535 + 1024);
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

            bzero (&pseudoheader,
                   12 + sizeof (struct tcphdr)); // bzero is deprecated. use
                                                 // memset(3) instead
            pseudoheader.saddr.s_addr = source.s_addr;
            pseudoheader.daddr.s_addr = dest.s_addr;

            pseudoheader.protocol = 6;
            pseudoheader.length = htons (sizeof (struct tcphdr));
            bcopy (
              (char *) tcp,
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
  while (host != NULL);

  g_message ("%s: wait a bit for replies after last batch of packets was sent",
             __func__);
  for (int i = 0; i < 3; i++)
    {
      sleep (1);
    }
  g_message ("%s: waiting for replies is over", __func__);

  /* close everything */
  g_string_free (filter, TRUE);
  /* TODO: may run into problems when calling pcap_breakloop in other thread */
  pcap_breakloop (handle);
  g_message ("%s: break_loop", __func__);
  /* join thread*/
  if (pthread_join (tid, NULL) != 0)
    g_warning ("%s: got error from pthread_join", __func__);
  g_message ("%s: join thread", __func__);
  if (handle != NULL)
    {
      g_message ("%s: close pcap handle", __func__);
      pcap_close (handle);
    }
  close (soc);
  g_message ("%s: close socket ", __func__);

  return 1;
}

/**
 * @brief start the tcp_syn scan of all specified hosts in gvm_hosts_t list.
 * Finish signal is put on Queue if pinger returned.
 *
 * @in: gvm_hosts_t structure
 */
void
start_alive_detection (gvm_hosts_t *hosts)
{
  int err;
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  /* This kb_t is only used once every alive detection process */
  kb_t main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id);

  g_message ("%s: alive detection process started", __func__);
  /* blocks until detection process is finished */
  err = my_tcp_ping (hosts);
  if (err < 0)
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

  return;
}