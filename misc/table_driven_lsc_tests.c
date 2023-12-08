/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "table_driven_lsc.c"

#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/mocks.h>
#include <sys/cdefs.h>

Describe (lsc);
BeforeEach (lsc)
{
}
AfterEach (lsc)
{
}

static char *resp_str = "{"
                        "\"1.3.6.1.4.1.25623.1.1.7.2.2023.0988598199100\": ["
                        "{"
                        "\"name\": \"grafana8\","
                        "\"installed_version\": \"8.5.23\","
                        "\"fixed_version\": {"
                        "\"version\": \"8.5.24\","
                        "\"specifier\": \">=\""
                        "}"
                        "},"
                        "{"
                        "\"name\": \"grafana9\","
                        "\"installed_version\": \"9.4.7\","
                        "\"fixed_version\": {"
                        "\"start\": \"9.4.0\","
                        "\"end\": \"9.4.9\""
                        "}"
                        "}"
                        "],"
                        "\"1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100\": ["
                        "{"
                        "\"name\": \"gitlab-ce\","
                        "\"installed_version\": \"16.0.1\","
                        "\"fixed_version\": {"
                        "\"start\": \"16.0.0\","
                        "\"end\": \"16.0.7\""
                        "}"
                        "}"
                        "]"
                        "}";

Ensure (lsc, make_pkg_in_json)
{
  char *pkglist = "pkg1.2.3\npkg4.5.6\nfoo-24\nbar-35";
  char *json = "[\"pkg1.2.3\",\"pkg4.5.6\",\"foo-24\",\"bar-35\"]";

  assert_that (strcmp (make_package_list_as_json_str (pkglist), json),
               is_equal_to (0));
}

Ensure (lsc, process_resp)
{
  advisories_t *advisories = NULL;

  advisories = process_notus_response (resp_str, strlen (resp_str));
  assert_that ((*advisories).count, is_equal_to (2));

  assert_that ((*advisories).advisories[0]->count, is_equal_to (2));
  assert_that ((*advisories).advisories[0]->pkgs[0]->type,
               is_equal_to (SINGLE));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[0]->pkg_name, "grafana8"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[0]->install_version, "8.5.23"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[1]->pkg_name, "grafana9"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[1]->install_version, "9.4.7"),
    is_equal_to (0));

  assert_that ((*advisories).advisories[0]->pkgs[1]->type, is_equal_to (RANGE));

  assert_that ((*advisories).advisories[1]->count, is_equal_to (1));
  assert_that ((*advisories).advisories[0]->pkgs[1]->type, is_equal_to (RANGE));

  advisories_free (advisories);
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, lsc, process_resp);
  add_test_with_context (suite, lsc, make_pkg_in_json);
  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
