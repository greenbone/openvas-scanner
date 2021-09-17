/* Copyright (C) 2021 Greenbone Networks GmbH
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

#include "preference_handler.c"

#include <cgreen/cgreen.h>
#include <cgreen/internal/assertions_internal.h>
#include <cgreen/legacy.h>
#include <cgreen/mocks.h>
#include <cgreen/reporter.h>
#include <cgreen/unit.h>
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <json-glib/json-glib.h>
#include <stdio.h>

Describe (Handler);
BeforeEach (Handler)
{
}
AfterEach (Handler)
{
}

/* Json Strings for testing */
static const gchar *g_json_str =
  "{\"ssh\": {\r\n   \"username\": \"some_username\",\r\n   \"password\": "
  "\"super_secret\",\r\n   \"crdential_type\": \"us\",\r\n   \"port\": "
  "22022\r\n   },\r\n \"smb\": {\r\n   \"username\": \"some_username\",\r\n   "
  "\"password\": \"super_secret\"\r\n  }\r\n}";

#define SUCCESS 1
#define FAILURE 0

/* Wrap store_file */
__attribute__ ((weak)) int
__real_store_file (__attribute__ ((unused)) struct scan_globals *globals,
                   __attribute__ ((unused)) const gchar *file,
                   __attribute__ ((unused)) const gchar *uuid);

bool store_file_use_real = true;

int
__wrap_store_file (__attribute__ ((unused)) struct scan_globals *globals,
                   __attribute__ ((unused)) const gchar *file,
                   __attribute__ ((unused)) const gchar *uuid)
{
  return 0;
}

///* Wrap calloc */
__attribute__ ((weak)) void
__real_prefs_store_file (struct scan_globals *globals, const gchar *key_name,
                         const gchar *file);
bool store_prefs_use_real = true;

void
__wrap_prefs_store_file (struct scan_globals *globals, const gchar *key_name,
                         const gchar *file)
{
  if (store_prefs_use_real)
    __real_prefs_store_file (globals, key_name, file);
}

Ensure (Handler, credentials_error)
{
  struct scan_globals *globals = NULL;
  JsonNode *j_node_credentials = NULL;
  JsonReader *cred_reader = NULL;
  store_file_use_real = 0;
  store_prefs_use_real = 0;
  GError *error = NULL;

  j_node_credentials = json_from_string (g_json_str, &error);
  assert_not_equal (j_node_credentials, NULL);

  if (error != NULL)
    {
      fprintf (stderr, "Unable to read file: %s\n", error->message);
      g_error_free (error);
    }
  cred_reader = json_reader_new (j_node_credentials);

  write_json_credentials_to_preferences (globals, cred_reader);

  assert_that (prefs_get ("auth_port_ssh"), is_equal_to_string ("22022"));
}

TestSuite *
handler_preferences_tests ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, Handler, credentials_error);
  return suite;
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();
  add_suite (suite, handler_preferences_tests ());

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
