#ifndef NESSUS_RAW_H
#define NESSUS_RAW_H
#ifdef __linux__
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#endif

#include <nessusip.h>
#include <nessustcp.h>
#include <nessusudp.h>
#include <nessusicmp.h>

int tcp_ping_host(struct in_addr);
long tcp_timing(struct in_addr, int num_probes, unsigned int port);
#endif
