/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ipc_openvas.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (ipc_openvas);
BeforeEach (ipc_openvas)
{
}
AfterEach (ipc_openvas)
{
}

Ensure (ipc_openvas, ipc_data_from_json_ua_ok)
{
  ipc_data_t *data_s = NULL;
  ipc_data_t *data_r = NULL;
  gchar *ua = "localhost";

  // Preapre data to be sent
  data_s = g_malloc0 (sizeof (ipc_data_t));
  data_s = ipc_data_type_from_user_agent (ua, strlen (ua));

  const char *json = ipc_data_to_json (data_s);
  ipc_data_destroy (&data_s);
  assert_that (data_s, is_null);

  // Read received data
  data_r = g_malloc0 (sizeof (ipc_data_t));
  data_r = ipc_data_from_json (json, strlen (json));
  assert_that (ipc_get_user_agent_from_data (data_r),
               is_equal_to_string ("localhost"));

  ipc_data_destroy (&data_r);
  assert_that (data_s, is_null);
}

Ensure (ipc_openvas, ipc_data_from_json_hostname_ok)
{
  ipc_data_t *data_s = NULL;
  ipc_data_t *data_r = NULL;
  gchar *hn = "localhost";
  gchar *hns = "TLS certificate";

  // Preapre data to be sent
  data_s = g_malloc0 (sizeof (ipc_data_t));
  data_s = ipc_data_type_from_hostname (hns, strlen (hns), hn, strlen (hn));

  const char *json = ipc_data_to_json (data_s);
  ipc_data_destroy (&data_s);
  assert_that (data_s, is_null);

  // Read received data
  data_r = g_malloc0 (sizeof (ipc_data_t));
  data_r = ipc_data_from_json (json, strlen (json));
  assert_that (ipc_get_hostname_from_data (data_r),
               is_equal_to_string ("localhost"));
  assert_that (ipc_get_hostname_source_from_data (data_r),
               is_equal_to_string ("TLS certificate"));

  ipc_data_destroy (&data_r);
  assert_that (data_r, is_null);
}

Ensure (ipc_openvas, ipc_data_from_json_parse_error)
{
  ipc_data_t *data_r = NULL;
  // malformed json string
  char json_fake[1024] =
    "{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] (X11, U; Greenbone OS "
    "22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] (X11, U; "
    "Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] "
    "(X11, U; Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 "
    "[en] (X11, U; Greenbone OS "
    "22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] (X11, U; "
    "Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] "
    "(X11, U; Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 "
    "[en] (X11, U; Greenbone OS "
    "22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] (X11, U; "
    "Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] "
    "(X11, U; Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 "
    "[en] (X11, U; Greenbone OS "
    "22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] (X11, U; "
    "Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 [en] "
    "(X11, U; Greenbone OS 22.04.4)\"}{\"type\":2,\"user-agent\":\"Mozilla/5.0 "
    "[en] (X11, U; Greenbone OS 22.04.4)\"}{\"type\":";

  // Read received data
  data_r = g_malloc0 (sizeof (ipc_data_t));
  data_r = ipc_data_from_json (json_fake, strlen (json_fake));
  assert_that (ipc_get_hostname_from_data (data_r), is_null);
  assert_that (ipc_get_hostname_source_from_data (data_r), is_null);
  assert_that (data_r, is_null);
}

Ensure (ipc_openvas, ipc_data_from_json_parse_many_objects)
{
  ipc_data_t *data_r = NULL;
  int len = 0;
  int pos = 0;

  // json string with more than one objects
  char json_fake[256] =
    "{\"type\":1,\"source\":\"TLS "
    "certificate\",\"hostname\":\"localhost\"}{\"type\":2,\"user-agent\":"
    "\"Mozilla/5.0 [en] (X11, U; Greenbone OS 22.04.4)\"}";

  for (int i = 0; json_fake[i] != '\0'; i++)
    {
      if (json_fake[i] == '}')
        {
          gchar *message = NULL;
          len = i - pos + 1;

          message = g_malloc0 (sizeof (gchar) * (len + 1));
          memcpy (message, &json_fake[pos], len);
          printf ("\n\nel mensaje %s\n\n", message);
          pos = i + 1;
          len = 0;
          data_r = g_malloc0 (sizeof (ipc_data_t));
          data_r = ipc_data_from_json (message, strlen (message));
          if (ipc_get_data_type_from_data (data_r) == IPC_DT_HOSTNAME)
            {
              assert_that (ipc_get_hostname_from_data (data_r),
                           is_equal_to_string ("localhost"));
              assert_that (ipc_get_hostname_source_from_data (data_r),
                           is_equal_to_string ("TLS certificate"));

              ipc_data_destroy (&data_r);
            }
          else
            {
              assert_that (
                ipc_get_user_agent_from_data (data_r),
                is_equal_to_string (
                  "Mozilla/5.0 [en] (X11, U; Greenbone OS 22.04.4)"));
              ipc_data_destroy (&data_r);
            }
          g_free (message);
        }
    }
  assert_that (data_r, is_null);
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, ipc_openvas, ipc_data_from_json_ua_ok);
  add_test_with_context (suite, ipc_openvas, ipc_data_from_json_hostname_ok);
  add_test_with_context (suite, ipc_openvas, ipc_data_from_json_parse_error);
  add_test_with_context (suite, ipc_openvas,
                         ipc_data_from_json_parse_many_objects);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
