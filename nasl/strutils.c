/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <ctype.h>              /* for tolower */

/**
 * @todo These functions are not necessarily nasl-specific and thus subject to
 *       be moved (e.g. to misc).
 */

/** @todo In parts replacable by g_pattern_match function (when not icase) */
int
str_match (const char *string, const char *pattern, int icase)
{
  while (*pattern != '\0')
    {
      if (*pattern == '?')
        {
          if (*string == '\0')
            return 0;
        }
      else if (*pattern == '*')
        {
          const char *p = string;
          do
            if (str_match (p, pattern + 1, icase))
              return 1;
          while (*p++ != '\0');
          return 0;
        }
      else if ((icase && (tolower (*pattern) != tolower (*string)))
               || (!icase && (*pattern != *string)))
        return 0;
      pattern++;
      string++;
    }
  return *string == '\0';
}
