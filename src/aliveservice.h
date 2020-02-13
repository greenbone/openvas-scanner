#ifndef __ALIVE_SERVICE__
#define __ALIVE_SERVICE__

#include <gvm/base/hosts.h>

/* timeout (in sec) for waiting on queue for new entries. negative value for
 * waiting forever or until error or other stop condition appears */
#define TIMEOUT -1
/* how many hosts packets are sent to at a time. value <= 0 for no rate limit */
#define BURST 1
/* how long (in msec) to wait until new BURST */
#define BURST_TIMEOUT 1000000

gvm_host_t *
get_host_from_queue (int timeout);

void *
start_alive_detection (void *hosts);

/**
 * @brief Alive tests.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
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