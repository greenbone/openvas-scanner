#ifndef __ALIVE_SERVICE__
#define __ALIVE_SERVICE__

#include <gvm/base/hosts.h>

#define TIMEOUT -1

gvm_host_t *
get_host_from_queue (int timeout);

void *
start_alive_detection (void *hosts);

#endif