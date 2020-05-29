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

#include "alivedetection.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (alivedetection);
BeforeEach (alivedetection)
{
}
AfterEach (alivedetection)
{
}

Ensure (alivedetection, fill_ports_array)
{
  GArray *ports_garray = NULL;
  const gchar *port_list = NULL;
  GPtrArray *portranges_array = NULL;

  /* Port list used in alivedetection.c. */
  port_list = "80,137,587,3128,8081";
  assert_that (validate_port_range (port_list), is_equal_to (0));
  ports_garray = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  portranges_array = port_range_ranges (port_list);
  assert_that (portranges_array, is_not_null);
  /* Fill ports array with ports from the ranges. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, ports_garray);
  array_free (portranges_array);
  assert_that (ports_garray->len, is_equal_to (5));
  assert_that (g_array_index (ports_garray, uint16_t, 0), is_equal_to (80));
  assert_that (g_array_index (ports_garray, uint16_t, 4), is_equal_to (8081));
  g_array_free (ports_garray, TRUE);

  /* Random port list. Duplicates are not removed. */
  /* 1,2,5,6,10,11,12,10,10 */
  port_list = "1-2,T:5-6,U:10-12,T:10,10";
  assert_that (validate_port_range (port_list), is_equal_to (0));
  ports_garray = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  portranges_array = port_range_ranges (port_list);
  assert_that (portranges_array, is_not_null);
  /* Fill ports array with ports from the ranges. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, ports_garray);
  array_free (portranges_array);
  assert_that (ports_garray->len, is_equal_to (9));
  assert_that (g_array_index (ports_garray, uint16_t, 0), is_equal_to (1));
  assert_that (g_array_index (ports_garray, uint16_t, 4), is_equal_to (10));
  assert_that (g_array_index (ports_garray, uint16_t, 7), is_equal_to (10));
  assert_that (g_array_index (ports_garray, uint16_t, 8), is_equal_to (10));
  g_array_free (ports_garray, TRUE);
}

__attribute__ ((weak)) int
__real_socket (__attribute__ ((unused)) int domain,
               __attribute__ ((unused)) int type,
               __attribute__ ((unused)) int protocol);

__attribute__ ((weak)) int
__real_setsockopt (__attribute__ ((unused)) int sockfd,
                   __attribute__ ((unused)) int level,
                   __attribute__ ((unused)) int optname,
                   __attribute__ ((unused)) const void *optval,
                   __attribute__ ((unused)) socklen_t optlen);

bool g_socket_use_real = true;
int
__wrap_socket (__attribute__ ((unused)) int domain,
               __attribute__ ((unused)) int type,
               __attribute__ ((unused)) int protocol)
{
  if (g_socket_use_real)
    return __real_socket (domain, type, protocol);

  return (int) mock (domain, type, protocol);
}

bool g_setsockopt_use_real = true;
int
__wrap_setsockopt (__attribute__ ((unused)) int sockfd,
                   __attribute__ ((unused)) int level,
                   __attribute__ ((unused)) int optname,
                   __attribute__ ((unused)) const void *optval,
                   __attribute__ ((unused)) socklen_t optlen)
{
  if (g_setsockopt_use_real)
    return __real_setsockopt (sockfd, level, optname, optval, optlen);

  return (int) mock (sockfd, level, optname, optval, optlen);
}

Ensure (alivedetection, set_all_needed_sockets)
{
  g_socket_use_real = false;
  g_setsockopt_use_real = false;

  alive_test_t alive_test;

  /* All methods set. */
  alive_test = ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP
               | ALIVE_TEST_CONSIDER_ALIVE | ALIVE_TEST_TCP_SYN_SERVICE;
  expect (__wrap_socket, will_return (5), times (7));
  expect (__wrap_setsockopt, will_return (5), times (9));
  set_all_needed_sockets (alive_test);

  /* Only one method set. */
  alive_test = ALIVE_TEST_TCP_ACK_SERVICE;
  expect (__wrap_socket, will_return (5), times (3));
  expect (__wrap_setsockopt, will_return (5), times (5));
  set_all_needed_sockets (alive_test);

  /* ALIVE_TEST_CONSIDER_ALIVE set. */
  alive_test = ALIVE_TEST_CONSIDER_ALIVE;
  never_expect (__wrap_socket);
  never_expect (__wrap_setsockopt);
  never_expect (set_socket);
  set_all_needed_sockets (alive_test);

  g_socket_use_real = true;
  g_setsockopt_use_real = true;
}

Ensure (alivedetection, set_socket)
{
  g_setsockopt_use_real = false;
  g_socket_use_real = false;
  int socket_location;

  /* socket() successful. */
  expect (__wrap_socket, will_return (5));
  expect (__wrap_setsockopt);
  expect (__wrap_setsockopt);
  assert_that (set_socket (TCPV4, &socket_location), is_equal_to (0));

  /* socket() error. */
  expect (__wrap_socket, will_return (-5));
  never_expect (__wrap_setsockopt);
  assert_that (set_socket (TCPV4, &socket_location),
               is_equal_to (BOREAS_OPENING_SOCKET_FAILED));
  g_socket_use_real = true;
  g_setsockopt_use_real = true;
}

/* If dst for routethrough() is localhost "lo" interface is returned. */
Ensure (alivedetection, routethrough_dst_is_localhost)
{
  /* setup */
  g_socket_use_real = false;
  gchar *interface = NULL;
  gchar *ipv4_str = "127.0.0.1";
  gvm_host_t *gvm_host = NULL;
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  assert_that ((gvm_host = gvm_host_from_str (ipv4_str)), is_not_null);
  assert_that (gvm_host_get_addr6 ((gvm_host_t *) gvm_host, dst6_p),
               is_equal_to (0));
  assert_that (dst6_p, is_not_null);
  dst4.s_addr = dst6_p->s6_addr32[3];

  expect (__wrap_socket, when (domain, is_equal_to (2)),
          when (type, is_equal_to (2)), when (protocol, is_equal_to (0)));

  interface = routethrough (dst4_p, NULL);
  (void) interface;

  /* dependent on local environment */
  // assert_that ((interface = routethrough (dst4_p, NULL)), is_not_null);
  // assert_that (interface, is_equal_to_string ("lo"));
  g_socket_use_real = true;
}

/* If dst is not null for routethrough() then another interface than "lo" is
 * returned. */
Ensure (alivedetection, routethrough_dst_is_not_localhost)
{
  g_socket_use_real = false;
  /* setup */
  gchar *interface = NULL;
  gchar *ipv4_str = "93.184.216.34"; /* example.com */
  gvm_host_t *gvm_host = NULL;
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  assert_that ((gvm_host = gvm_host_from_str (ipv4_str)), is_not_null);
  assert_that (gvm_host_get_addr6 ((gvm_host_t *) gvm_host, dst6_p),
               is_equal_to (0));
  assert_that (dst6_p, is_not_null);
  dst4.s_addr = dst6_p->s6_addr32[3];

  expect (__wrap_socket, when (domain, is_equal_to (2)),
          when (type, is_equal_to (2)), when (protocol, is_equal_to (0)),
          times (2));
  interface = routethrough (dst4_p, NULL);
  assert_that (interface, is_not_equal_to_string ("lo"));
  g_socket_use_real = true;
}

/* If neither dst nor src address are given to routethrough NULL is returned. */
Ensure (alivedetection, routethrough_no_src_dst_given)
{
  gchar *interface = NULL;
  assert_that ((interface = routethrough (NULL, NULL)), is_null);
}

/* If global_source_addr is present then routethrough writes it into src. */
Ensure (alivedetection, routethrough_src_globalsource_set)
{
  /* setup */
  g_socket_use_real = false;
  cgreen_mocks_are (learning_mocks);

  struct in_addr src = {.s_addr = 0}; /* ip src */
  gchar *interface = NULL;
  struct in_addr dst;
  inet_pton (AF_INET, "93.184.216.34", &(dst.s_addr));

  /* global source address set */
  gvm_source_iface_init ("lo"); // lo is set but not really used after being set
  /* expects */
  expect (__wrap_socket, when (domain, is_equal_to (2)),
          when (type, is_equal_to (2)), when (protocol, is_equal_to (0)));
  /* dst not given */
  assert_that ((interface = routethrough (NULL, &src)), is_null);
  assert_that ((src.s_addr == INADDR_ANY));
  /* dst localhost given */
  src.s_addr = 0;

  interface = routethrough (&dst, &src);
  /* dependent on local environment */
  // assert_that ((interface = routethrough (&dst, &src)), is_not_null);
  assert_that (interface, is_not_equal_to_string ("lo"));
  assert_that ((src.s_addr != INADDR_ANY));
  g_socket_use_real = true;
}

/* If global_source_addr is not present then routethrough writes it into src. */
Ensure (alivedetection, routethrough_src_globalsource_not_set)
{
  g_socket_use_real = false;

  struct in_addr src = {.s_addr = 0}; /* ip src */
  gchar *interface = NULL;
  struct in_addr dst;
  inet_pton (AF_INET, "127.0.0.1", &(dst.s_addr));

  /* global source address not set */
  gvm_source_iface_init (NULL);
  expect (__wrap_socket, when (domain, is_equal_to (2)),
          when (type, is_equal_to (2)), when (protocol, is_equal_to (0)));
  /* dst not given */
  assert_that ((interface = routethrough (NULL, &src)), is_null);
  assert_that ((src.s_addr == INADDR_ANY));
  /* dst localhost given */
  src.s_addr = 0;

  interface = routethrough (&dst, &src);
  /* dependent on local environment */
  // assert_that ((interface = routethrough (&dst, &src)), is_not_null);
  // assert_that (interface, is_equal_to_string ("lo"));
  assert_that ((src.s_addr != INADDR_ANY));
  g_socket_use_real = true;
}

Ensure (alivedetection, gvm_source_addr)
{
  struct in_addr src;

  /* global source address not set */
  gvm_source_iface_init (NULL);
  gvm_source_addr (&src);
  assert_that ((src.s_addr == INADDR_ANY));

  /* global source address */
  gvm_source_iface_init ("lo");
  gvm_source_addr (&src);
  assert_that ((src.s_addr != INADDR_ANY));
}

Ensure (alivedetection, v6_islocalhost)
{
  /* IPv4 */
  struct in_addr addr;
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;

  /* example.com */
  inet_pton (AF_INET, "93.184.216.34", &(addr.s_addr));

  /* IPv6 */
  struct in6_addr addr_6;

  inet_pton (AF_INET6, "::FFFF:127.0.0.1", &(addr_6));
  assert_that (v6_islocalhost (&addr_6), is_true);
  inet_pton (AF_INET6, "::FFFF:0.0.0.0", &(addr_6));
  assert_that (v6_islocalhost (&addr_6), is_true);
  inet_pton (AF_INET6, "::FFFF:127.100.5.99", &(addr_6));
  assert_that (v6_islocalhost (&addr_6), is_true);
  /* loopback address */
  inet_pton (AF_INET6, "0:0:0:0:0:0:0:1", &(addr_6));
  assert_that (v6_islocalhost (&addr_6), is_true);

  /* dependent on local environment */
  // inet_pton (AF_INET6, <some local interface address>, &(addr_6));
  // assert_that (v6_islocalhost (&addr_6), is_true);

  /* example.com */
  inet_pton (AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &(addr_6));
  assert_that (v6_islocalhost (&addr_6), is_false);
}

Ensure (alivedetection, islocalhost)
{
  /* IPv4 */
  struct in_addr addr;

  inet_pton (AF_INET, "127.0.0.1", &(addr.s_addr));
  assert_that (islocalhost (&addr), is_true);
  inet_pton (AF_INET, "0.0.0.0", &(addr.s_addr));
  assert_that (islocalhost (&addr), is_true);
  inet_pton (AF_INET, "127.100.5.99", &(addr.s_addr));
  assert_that (islocalhost (&addr), is_true);

  /* dependent on local environment */
  // // inet_pton (AF_INET, <some local interface address>, &(addr));
  // // assert_that (islocalhost (&addr), is_true);

  /* example.com */
  inet_pton (AF_INET, "93.184.216.34", &(addr.s_addr));
  assert_that (islocalhost (&addr), is_false);
}

TestSuite *
openvas_routethrough ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, alivedetection, gvm_source_addr);
  add_test_with_context (suite, alivedetection, routethrough_dst_is_localhost);
  add_test_with_context (suite, alivedetection,
                         routethrough_dst_is_not_localhost);
  add_test_with_context (suite, alivedetection, routethrough_no_src_dst_given);
  add_test_with_context (suite, alivedetection,
                         routethrough_src_globalsource_set);
  add_test_with_context (suite, alivedetection,
                         routethrough_src_globalsource_not_set);
  add_test_with_context (suite, alivedetection, v6_islocalhost);
  add_test_with_context (suite, alivedetection, islocalhost);

  return suite;
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();
  add_suite (suite, openvas_routethrough ());

  add_test_with_context (suite, alivedetection, fill_ports_array);
  add_test_with_context (suite, alivedetection, set_all_needed_sockets);
  add_test_with_context (suite, alivedetection, set_socket);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
