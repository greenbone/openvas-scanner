/* Copyright (C) 2009-2022 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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
