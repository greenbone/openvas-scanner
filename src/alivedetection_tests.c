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

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, alivedetection, fill_ports_array);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
