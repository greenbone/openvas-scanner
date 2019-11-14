#ifndef __ALIVE_SERVICE__
#define __ALIVE_SERVICE__

#include <gvm/base/hosts.h>

#define TIMEOUT -1

gvm_host_t *
get_host_from_queue (int timeout);

void
start_alive_detection (gvm_hosts_t *hosts);

char *
get_alive_host_str (int *flag);

void
kill_alive_detection_process (void);

void
set_alive_detection_pid (int pid);

int
get_alive_detection_pid (void);

int
my_tcp_ping (gvm_hosts_t *hosts);

#endif