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

#include "../misc/plugutils.c"
#include "preference_handler.c"

#include <cgreen/cgreen.h>
#include <cgreen/internal/assertions_internal.h>
#include <cgreen/legacy.h>
#include <cgreen/mocks.h>
#include <cgreen/reporter.h>
#include <cgreen/unit.h>
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/util/nvticache.h> // for nvticache_initialized
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
  "\"super_secret\",\r\n   \"credential_type\": \"up\",\r\n   \"port\": "
  "22022\r\n   },\r\n \"smb\": {\r\n   \"username\": \"some_username\",\r\n   "
  "\"password\": \"super_secret\"\r\n  }\r\n}";

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

__attribute__ ((weak)) int
__real_nvticache_initialized (void);
bool nvticache_initialized_real = true;

int
__wrap_nvticache_initialized ()
{
  if (nvticache_initialized_real == true)
    return __real_nvticache_initialized ();

  return 1;
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

Ensure (Handler, credentials_ssh_port_success)
{
  struct scan_globals *globals = NULL;
  JsonParser *parser;
  JsonReader *cred_reader = NULL;

  parser = json_parser_new ();
  json_parser_load_from_data (parser, g_json_str, strlen (g_json_str), NULL);
  cred_reader = json_reader_new (json_parser_get_root (parser));

  assert_true (json_reader_is_object (cred_reader));
  store_file_use_real = 0;
  store_prefs_use_real = 0;

  write_json_credentials_to_preferences (globals, cred_reader);
  assert_that (prefs_get ("auth_port_ssh"), is_equal_to_string ("22022"));
}

Ensure (Handler, credentials_ssh_up)
{
  struct scan_globals *globals = NULL;
  JsonParser *parser;
  JsonReader *cred_reader = NULL;

  parser = json_parser_new ();
  json_parser_load_from_data (parser, g_json_str, strlen (g_json_str), NULL);
  cred_reader = json_reader_new (json_parser_get_root (parser));

  assert_true (json_reader_is_object (cred_reader));
  store_file_use_real = 0;
  store_prefs_use_real = 0;
  nvticache_initialized_real = false;

  write_json_credentials_to_preferences (globals, cred_reader);
  assert_that (prefs_get ("1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login:"),
               is_equal_to_string ("some_username"));

  assert_that (get_plugin_preference ("1.3.6.1.4.1.25623.1.0.103591", NULL, 1),
               is_equal_to_string ("some_username"));
  assert_that (get_plugin_preference ("1.3.6.1.4.1.25623.1.0.103591", NULL, 3),
               is_equal_to_string ("super_secret"));
}

static const gchar *g_json_str_port_error =
  "{\"ssh\": {\r\n   \"username\": \"some_username\",\r\n   \"password\": "
  "\"super_secret\",\r\n   \"credential_type\": \"up\",\r\n   \"port\": "
  "66600\r\n   },\r\n \"smb\": {\r\n   \"username\": \"some_username\",\r\n   "
  "\"password\": \"super_secret\"\r\n  }\r\n}";
Ensure (Handler, ssh_credentials_port_error)
{
  struct scan_globals *globals = NULL;
  JsonParser *parser;
  JsonReader *cred_reader = NULL;

  parser = json_parser_new ();
  json_parser_load_from_data (parser, g_json_str_port_error,
                              strlen (g_json_str_port_error), NULL);
  cred_reader = json_reader_new (json_parser_get_root (parser));

  assert_true (json_reader_is_object (cred_reader));
  store_file_use_real = 0;
  store_prefs_use_real = 0;

  write_json_credentials_to_preferences (globals, cred_reader);
  assert_that (prefs_get ("auth_port_ssh"), is_null);
}

TestSuite *
handler_preferences_tests ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, Handler, credentials_ssh_port_success);
  add_test_with_context (suite, Handler, credentials_ssh_up);
  add_test_with_context (suite, Handler, ssh_credentials_port_error);

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
