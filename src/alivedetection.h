/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ALIVE_DETECTION__
#define __ALIVE_DETECTION__

#include <gvm/base/hosts.h>
#include <gvm/util/kb.h>

/* to how many hosts are packets send to at a time. value <= 0 for no rate limit
 */
#define BURST 100
/* how long (in msec) to wait until new BURST of packets is send */
#define BURST_TIMEOUT 100000
/* how tong (in sec) to wait for replies after last packet was sent */
#define WAIT_FOR_REPLIES_TIMEOUT 5
/* Queue for communicating with openvas main process. */
#define ALIVE_DETECTION_QUEUE "alive_detection"
/* Finish signal to put on ALIVE_DETECTION_QUEUE. */
#define ALIVE_DETECTION_FINISH "finish"

gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, gboolean *alive_detection_finished);

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