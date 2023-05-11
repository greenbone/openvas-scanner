/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "strutils.h"

#include "support.h"

#include <glib.h>

/**
 * @brief Matches a string against a pattern.
 *
 * @param[in] string  String to match.
 * @param[in] pattern Pattern to match against.
 * @param[in] icase   Case insensitivity enabled.
 *
 * @return 1 if it matches. 0 otherwise.
 */
int
str_match (const gchar *string, const gchar *pattern, int icase)
{
  gboolean res;
  GPatternSpec *patt = NULL;

  if (icase)
    {
      patt = g_pattern_spec_new (g_ascii_strdown (pattern, -1));
      res = g_pattern_spec_match_string (patt, g_ascii_strdown (string, -1));
    }
  else
    {
      patt = g_pattern_spec_new (pattern);
      res = g_pattern_spec_match_string (patt, string);
    }
  g_pattern_spec_free (patt);
  return res;
}
