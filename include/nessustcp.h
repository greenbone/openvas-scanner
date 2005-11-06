#ifndef NESSUS_TCP_H__
#define NESSUS_TCP_H__


#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef _CYGWIN_
#define tcp_seq u_int
#endif


#if !defined(HAVE_STRUCT_TCPHDR) || (HAVE_STRUCT_TCPHDR == 0)
#undef HAVE_TCPHDR_TH_X2_OFF
#undef HAVE_TCPHDR_TH_OFF
#define HAVE_TCPHDR_TH_OFF 1
#define HAVE_STRUCT_TCPHDR 1
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if !WORDS_BIGENDIAN
	u_int	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if WORDS_BIGENDIAN
	u_int	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;

	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

#endif


#ifndef TH_FIN
#define	TH_FIN	0x01
#endif

#ifndef TH_SYN
#define	TH_SYN	0x02
#endif

#ifndef TH_RST
#define	TH_RST	0x04
#endif

#ifndef TH_PUSH
#define	TH_PUSH	0x08
#endif

#ifndef TH_ACK
#define	TH_ACK	0x10
#endif

#ifndef TH_URG
#define	TH_URG	0x20
#endif

#ifndef TH_FLAGS
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG)
#endif
#endif
