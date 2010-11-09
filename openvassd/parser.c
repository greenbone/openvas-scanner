/* OpenVAS
* $Id$
* Description: Parses some kind of string containing <|> symbols.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

#include <includes.h>

#include <openvas/misc/system.h>     /* for emalloc */

/** @TODO Contents of this file is duplicate in openvas-scanner/openvassd/parser.c
 *        and openvas-client/openvas/parser.c . Move to libraries and merge, once
 *        openvas-client depends on libraries. */

/**
 * @brief This function returns a pointer to the string after the ' \<|\> '
 * @brief symbol.
 *
 * @param str String that contains \<|\>.
 *
 * @return A pointer into \ref str that points behind the \<|\>, or NULL
 *         if none found.
 */
char *
parse_symbol (char *str)
{
  char *s = str;

  while (s)
    {
      s = strchr (s, '|');
      if (!s)
        return (NULL);
      if ((s[1] == '>') && (s - 1)[0] == '<')
        return (s + 3);
      s++;
    }

  return (NULL);
}

/**
 * @brief In the standard case, returns content between two separators (\<|\>)
 * @brief in a string.
 *
 * Returns a copy of the string between the first two '\<|\>'s.
 * If just one \<|\> is found, returns a copy of the string from the first
 * \<|\> till its end.
 * Returns NULL if str is empty or does not contain a ' <|> '.
 *
 * @param str String to parse.
 *
 * @return Copy of content of string between two separators, see detailed doc
 *         for special cases.
 */
char *
parse_separator (char *str)
{
  char *s_1;
  char *s_2;
  char *ret;
  int len = 0;

  s_1 = parse_symbol (str);
  if (!s_1)
    return (NULL);

  s_2 = parse_symbol (s_1);

  // If no second <|> is found, return everything from first <|> to the end.
  if (!s_2)
    {
      len = strlen (s_1);
      ret = emalloc (len);
      strncpy (ret, s_1, len - 1);
    }
  else
    {
      /** @TODO Instead of modifying s2, length for strncpy could be calculated
       * like (s_2 - s_1). */
      int c;
      s_2 = s_2 - 4;
      c = s_2[0];
      s_2[0] = 0;
      len = strlen (s_1);
      ret = emalloc (len);
      strncpy (ret, s_1, len - 1);
      s_2[0] = c;
    }

#ifdef DEBUGMORE
  fprintf (stderr, "%s:%d got %s returning \"%s\"\n", __FILE__, __LINE__, str,
           ret);
#endif

  return ret;
}
