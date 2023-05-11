/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pcap.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <gvm/base/hosts.h>

Describe (pcap);
BeforeEach (pcap)
{
  cgreen_mocks_are (loose_mocks);
}
AfterEach (pcap)
{
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
               __attribute__ ((unused)) int protocol);

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
                   __attribute__ ((unused)) socklen_t optlen);
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

/* If dst for routethrough() is localhost "lo" interface is returned. */
Ensure (pcap, routethrough_dst_is_localhost)
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

  interface = routethrough (dst4_p, NULL);
  (void) interface;

  /* dependent on local environment */
  // assert_that ((interface = routethrough (dst4_p, NULL)), is_not_null);
  // assert_that (interface, is_equal_to_string ("lo"));
  g_socket_use_real = true;
}

/* If dst is not null for routethrough() then another interface than "lo" is
 * returned. */
Ensure (pcap, routethrough_dst_is_not_localhost)
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

  interface = routethrough (dst4_p, NULL);
  assert_that (interface, is_not_equal_to_string ("lo"));
  g_socket_use_real = true;
}

/* If neither dst nor src address are given to routethrough NULL is returned. */
Ensure (pcap, routethrough_no_src_dst_given)
{
  gchar *interface = NULL;
  assert_that ((interface = routethrough (NULL, NULL)), is_null);
}

/* If global_source_addr is present then routethrough writes it into src. */
Ensure (pcap, routethrough_src_globalsource_set)
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
Ensure (pcap, routethrough_src_globalsource_not_set)
{
  g_socket_use_real = false;

  struct in_addr src = {.s_addr = 0}; /* ip src */
  gchar *interface = NULL;
  struct in_addr dst;
  inet_pton (AF_INET, "127.0.0.1", &(dst.s_addr));

  /* global source address not set */
  gvm_source_iface_init (NULL);
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

Ensure (pcap, v6_islocalhost)
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

Ensure (pcap, islocalhost)
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

/**
 * @brief Apply mask to dest addr.
 *
 * @param[out]  network   Masked dest addr.
 * @param[in]   dest      Destination addr.
 * @param[in]   mask      Mask to apply.
 */
static void
apply_ipv6_mask (struct in6_addr *network, struct in6_addr *dest,
                 struct in6_addr *mask)
{
  for (int i = 0; i < (int) sizeof (struct in6_addr); i++)
    network->s6_addr[i] = dest->s6_addr[i] & mask->s6_addr[i];
}

Ensure (pcap, ipv6_prefix_to_mask)
{
  struct in6_addr dest;
  struct in6_addr result;
  struct in6_addr mask;
  struct in6_addr network;
  const uint8_t byte_options[9] = {0xFF, 0x00, 0x80, 0xC0, 0xE0,
                                   0xF0, 0xF8, 0xFC, 0xFE};

  // create dst addr
  const uint8_t addr_in[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy (dest.s6_addr, addr_in, sizeof addr_in);
  // create expected result addr
  const uint8_t result_in[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy (result.s6_addr, result_in, sizeof result_in);

  // check every possible bit mask
  for (int i = 128; i > 0; i--)
    {
      ipv6_prefix_to_mask (i, &mask);
      apply_ipv6_mask (&network, &dest, &mask);
      int byte_to_modify = i / 8;
      if (byte_to_modify != 16)
        result.s6_addr[byte_to_modify] = byte_options[(i % 8) + 1];

      assert_that (IN6_ARE_ADDR_EQUAL (&network, &result));
    }
}

static TestSuite *
openvas_routethrough ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, pcap, routethrough_dst_is_localhost);
  add_test_with_context (suite, pcap, routethrough_dst_is_not_localhost);
  add_test_with_context (suite, pcap, routethrough_no_src_dst_given);
  add_test_with_context (suite, pcap, routethrough_src_globalsource_set);
  add_test_with_context (suite, pcap, routethrough_src_globalsource_not_set);
  add_test_with_context (suite, pcap, v6_islocalhost);
  add_test_with_context (suite, pcap, islocalhost);
  add_test_with_context (suite, pcap, ipv6_prefix_to_mask);

  return suite;
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();
  add_suite (suite, openvas_routethrough ());

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
