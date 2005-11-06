#ifndef NESSUS_UDP_H__
#define NESSUS_UDP_H__

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#if !defined(HAVE_STRUCT_UDPHDR) || HAVE_STRUCT_UDPHDR == 0
#define HAVE_STRUCT_UDPHDR 1
struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};
#endif

#if defined(HAVE_STRUCT_UDPHDR) && !defined(HAVE_BSD_STRUCT_UDPHDR)
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#endif
