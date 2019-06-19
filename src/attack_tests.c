/* Copyright (C) 2019 Greenbone Networks GmbH
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

#include "attack.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (attack);
BeforeEach (attack)
{
}
AfterEach (attack)
{
}

/* comm_send_status */

Ensure (attack, comm_send_status_returns_neg1_for_null_args)
{
  kb_t kb;

  /* Create a dummy kb. */
  kb = NULL;

  assert_that (comm_send_status (NULL, "example", 0, 100), is_equal_to (-1));
  assert_that (comm_send_status (kb, NULL, 0, 100), is_equal_to (-1));
}

Ensure (attack, comm_send_status_error_if_hostname_too_big)
{
  kb_t kb;
  gchar *long_host;
  int index;

  /* Create a dummy kb. */
  kb = NULL;

  long_host = g_malloc (2049);
  for (index = 0; index < 2048; index++)
    long_host[index] = 'a';
  long_host[2048] = '\0';

  assert_that (comm_send_status (kb, long_host, 0, 100), is_equal_to (-1));

  g_free (long_host);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite,
                         attack,
                         comm_send_status_returns_neg1_for_null_args);
  add_test_with_context (suite,
                         attack,
                         comm_send_status_error_if_hostname_too_big);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
