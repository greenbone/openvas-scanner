#ifndef __ALIVE_SERVICE__
#define __ALIVE_SERVICE__

#include <gvm/base/hosts.h>
#include <gvm/util/kb.h>

/* to how many hosts are packets send to at a time. value <= 0 for no rate limit
 */
#define BURST 100
/* how long (in msec) to wait until new BURST of packets is send */
#define BURST_TIMEOUT 100000
/* how tong (in sec) to wait for replies after last packet was sent */
#define WAIT_FOR_REPLIES_TIMEOUT 5

gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, int timeout);

void *
start_alive_detection (void *hosts);

/**
 * @brief Alive tests.
 *
 * These numbers are used in the database by gvmd, so if the number associated
 * with any symbol changes in gvmd we need to change them here too.
 */
typedef enum
{
  ALIVE_TEST_TCP_ACK_SERVICE = 1,
  ALIVE_TEST_ICMP = 2,
  ALIVE_TEST_ARP = 4,
  ALIVE_TEST_CONSIDER_ALIVE = 8,
  ALIVE_TEST_TCP_SYN_SERVICE = 16
} alive_test_t;

#endif