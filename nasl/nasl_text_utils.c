/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_text_utils.c
 * @brief Functions related to text-related utilities in the NASL functions.
 */

#define _GNU_SOURCE

#include "nasl_text_utils.h"

#include "../misc/strutils.h" /* for str_match */
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <ctype.h>  /* for isspace */
#include <glib.h>   /* for g_free */
#include <regex.h>  /* for regex_t */
#include <string.h> /* for strlen */
#include <string.h> /* for memmem */
#include <unistd.h> /* for getpid */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

tree_cell *
nasl_string (lex_ctxt *lexic)
{
  tree_cell *retc;
  int vi, vn, newlen;
  int sz, typ;
  const char *s, *p1;
  char *p2;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);

  vn = array_max_index (&lexic->ctx_vars);
  for (vi = 0; vi < vn; vi++)
    {
      if ((typ = get_var_type_by_num (lexic, vi)) == VAR2_UNDEF)
        continue;
      s = get_str_var_by_num (lexic, vi);
      if (!s)
        continue;
      sz = get_var_size_by_num (lexic, vi);
      if (sz <= 0)
        sz = strlen (s);

      newlen = retc->size + sz;
      retc->x.str_val = g_realloc (retc->x.str_val, newlen + 1);
      p2 = retc->x.str_val + retc->size;
      p1 = s;
      retc->size = newlen;
      if (typ != VAR2_STRING)
        {
          memcpy (p2, p1, sz);
          p2[sz] = '\0';
        }
      else
        while (*p1 != '\0')
          {
            if (*p1 == '\\' && p1[1] != '\0')
              {
                switch (p1[1])
                  {
                  case 'n':
                    *p2++ = '\n';
                    break;
                  case 't':
                    *p2++ = '\t';
                    break;
                  case 'r':
                    *p2++ = '\r';
                    break;
                  case '\\':
                    *p2++ = '\\';
                    break;
                  case 'x':
                    if (isxdigit (p1[2]) && isxdigit (p1[3]))
                      {
                        *p2++ =
                          16
                            * (isdigit (p1[2]) ? p1[2] - '0'
                                               : 10 + tolower (p1[2]) - 'a')
                          + (isdigit (p1[3]) ? p1[3] - '0'
                                             : 10 + tolower (p1[3]) - 'a');
                        p1 += 2;
                        retc->size -= 2;
                      }
                    else
                      {
                        nasl_perror (lexic,
                                     "Buggy hex value '\\x%c%c' skipped\n",
                                     isprint (p1[2]) ? p1[2] : '.',
                                     isprint (p1[3]) ? p1[3] : '.');
                        /* We do not increment p1 by  4,
                           we may miss the end of the string */
                      }
                    break;
                  default:
                    nasl_perror (lexic,
                                 "Unknown escape sequence '\\%c' in the "
                                 "string '%s'\n",
                                 isprint (p1[1]) ? p1[1] : '.', s);
                    retc->size--;
                    break;
                  }
                p1 += 2;
                retc->size--;
              }
            else
              *p2++ = *p1++;
          }
    }
  retc->x.str_val[retc->size] = '\0';
  return retc;
}

/*---------------------------------------------------------------------*/
#define RAW_STR_LEN 32768
tree_cell *
nasl_rawstring (lex_ctxt *lexic)
{
  tree_cell *retc;
  int vi, vn, i, j, x;
  int sz, typ;
  const char *s;
  int total_len = 0;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 0;
  retc->x.str_val = g_malloc0 (RAW_STR_LEN + 1);

  vn = array_max_index (&lexic->ctx_vars);
  for (vi = 0; vi < vn && total_len < RAW_STR_LEN - 1; vi++)
    {
      if ((typ = get_var_type_by_num (lexic, vi)) == VAR2_UNDEF)
        continue;
      sz = get_var_size_by_num (lexic, vi);

      if (typ == VAR2_INT)
        {
          x = get_int_var_by_num (lexic, vi, 0);
          retc->x.str_val[total_len++] = x;
        }
      else
        {
          int current_len;
          char str[RAW_STR_LEN];

          s = get_str_var_by_num (lexic, vi);
          if (!s)
            continue;
          if (sz <= 0)
            sz = strlen (s);

          if (sz >= RAW_STR_LEN)
            {
              nasl_perror (lexic, "Error. Too long argument in raw_string()\n");
              break;
            }

          /* Should we test if the variable is composed only of digits? */
          if (typ == VAR2_STRING)
            {
              /* TBD:I should decide at last if we keep those "purified"
               * string or not, and if we do, if "CONST_STR" & "VAR2_STR" are
               * "not pure" strings */
              for (i = 0, j = 0; i < sz; i++)
                {
                  if (s[i] == '\\')
                    {
                      if (s[i + 1] == 'n')
                        {
                          str[j++] = '\n';
                          i++;
                        }
                      else if (s[i + 1] == 't')
                        {
                          str[j++] = '\t';
                          i++;
                        }
                      else if (s[i + 1] == 'r')
                        {
                          str[j++] = '\r';
                          i++;
                        }
                      else if (s[i + 1] == 'x' && isxdigit (s[i + 2])
                               && isxdigit (s[i + 3]))
                        {
                          if (isdigit (s[i + 2]))
                            x = (s[i + 2] - '0') * 16;
                          else
                            x = (10 + tolower (s[i + 2]) - 'a') * 16;
                          if (isdigit (s[i + 3]))
                            x += s[i + 3] - '0';
                          else
                            x += tolower (s[i + 3]) + 10 - 'a';
                          str[j++] = x;
                          i += 3;
                        }
                      else if (s[i + 1] == '\\')
                        {
                          str[j++] = s[i];
                          i++;
                        }
                      else
                        i++;
                    }
                  else
                    str[j++] = s[i];
                }
              current_len = j;
            }
          else
            {
              memcpy (str, s, sz);
              str[sz] = '\0';
              current_len = sz;
            }

          if (total_len + current_len > RAW_STR_LEN)
            {
              nasl_perror (lexic, "Error. Too long argument in raw_string()\n");
              break;
            }
          bcopy (str, retc->x.str_val + total_len, current_len);
          total_len += current_len;
        }
    }

  retc->size = total_len;
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_strlen (lex_ctxt *lexic)
{
  int len = get_var_size_by_num (lexic, 0);
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = len;
  return retc;
}

tree_cell *
nasl_strcat (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *s;
  int vi, vn, newlen;
  int sz;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);

  vn = array_max_index (&lexic->ctx_vars);
  for (vi = 0; vi < vn; vi++)
    {
      s = get_str_var_by_num (lexic, vi);
      if (s == NULL)
        continue;
      sz = get_var_size_by_num (lexic, vi);
      if (sz <= 0)
        sz = strlen (s);

      newlen = retc->size + sz;
      retc->x.str_val = g_realloc (retc->x.str_val, newlen + 1);
      memcpy (retc->x.str_val + retc->size, s, sz);
      retc->size = newlen;
    }
  retc->x.str_val[retc->size] = '\0';
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_display (lex_ctxt *lexic)
{
  tree_cell *r, *retc;
  int j;
  char *msg = NULL;
  r = nasl_string (lexic);

  msg = g_malloc0 (r->size + 1);
  for (j = 0; j < r->size; j++)
    msg[j] =
      (isprint (r->x.str_val[j]) || isspace (r->x.str_val[j]) ? r->x.str_val[j]
                                                              : '.');

  g_message ("%s", msg);
  g_free (msg);
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = r->size;
  deref_cell (r);
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_hex (lex_ctxt *lexic)
{
  tree_cell *retc;
  int v = get_int_var_by_num (lexic, 0, -1);
  char ret[7];

  if (v == -1)
    return NULL;

  snprintf (ret, sizeof (ret), "0x%02x", (unsigned char) v);
  retc = alloc_typed_cell (CONST_STR);
  retc->size = strlen (ret);
  retc->x.str_val = g_strdup (ret);

  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_hexstr (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *s = get_str_var_by_num (lexic, 0);
  int len = get_var_size_by_num (lexic, 0);
  char *ret;
  int i;

  if (s == NULL)
    return NULL;

  ret = g_malloc0 (len * 2 + 1);
  for (i = 0; i < len; i++)
    {
      /* if i < len there are at least three chars left in ret + 2 * i */
      snprintf (ret + 2 * i, 3, "%02x", (unsigned char) s[i]);
    }

  retc = alloc_typed_cell (CONST_STR);
  retc->size = strlen (ret);
  retc->x.str_val = ret;

  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_ord (lex_ctxt *lexic)
{
  tree_cell *retc;
  unsigned char *val = (unsigned char *) get_str_var_by_num (lexic, 0);

  if (val == NULL)
    {
      nasl_perror (lexic, "Usage : ord(char). The given char or string "
                          "is NULL\n");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = val[0];
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_tolower (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *str = get_str_var_by_num (lexic, 0), *ret;
  int str_len = get_var_size_by_num (lexic, 0);
  int i;

  if (str == NULL)
    return NULL;

  ret = g_malloc0 (str_len + 1);
  memcpy (ret, str, str_len + 1);

  for (i = 0; i < str_len; i++)
    ret[i] = tolower (ret[i]);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = str_len;
  retc->x.str_val = ret;
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_toupper (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *str = get_str_var_by_num (lexic, 0), *ret;
  int str_len = get_var_size_by_num (lexic, 0);
  int i;

  if (str == NULL)
    return NULL;

  ret = g_malloc0 (str_len + 1);
  memcpy (ret, str, str_len + 1);

  for (i = 0; i < str_len; i++)
    ret[i] = toupper (ret[i]);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = str_len;
  retc->x.str_val = ret;
  return retc;
}

/*---------------------------------------------------------------------*/

/**
 * @brief Matches a string against a regular expression.
 * @naslfn{egrep}
 *
 * @naslnparam
 * - @a string  String to search the pattern in
 * - @a pattern the patern that should be matched
 * - @a icase   case insensitive flag
 * - @a rnul    replace the null char in the string. Default TRUE.
 * - @a multiline Is FALSE by default (string is truncated at the first
 *                “end of line”), and can be set to TRUE for multiline search.
 * @naslret The first found pattern.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_ereg (lex_ctxt *lexic)
{
  char *pattern = get_str_var_by_name (lexic, "pattern");
  char *string = get_str_var_by_name (lexic, "string");
  int icase = get_int_var_by_name (lexic, "icase", 0);
  int multiline = get_int_var_by_name (lexic, "multiline", 0);
  int replace_nul = get_int_var_by_name (lexic, "rnul", 1);
  int max_size = get_var_size_by_name (lexic, "string");
  char *s;
  int copt = 0;
  tree_cell *retc;
  regex_t re;

  if (icase != 0)
    copt = REG_ICASE;

  if (pattern == NULL || string == NULL)
    return NULL;

  if (regcomp (&re, pattern, REG_EXTENDED | REG_NOSUB | copt))
    {
      nasl_perror (lexic, "ereg() : regcomp() failed for pattern '%s'.\n",
                   pattern);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);

  if (replace_nul)
    string = g_regex_escape_nul (string, max_size);
  else
    string = g_strdup (string);

  if (multiline)
    s = NULL;
  else
    s = strchr (string, '\n');
  if (s != NULL)
    s[0] = '\0';
  if (s != string)
    {
      if (regexec (&re, string, 0, NULL, 0) == 0)
        retc->x.i_val = 1;
      else
        retc->x.i_val = 0;
    }
  else
    retc->x.i_val = 0;

  g_free (string);
  regfree (&re);
  return retc;
}

/*---------------------------------------------------------------------*/

#define NS 16
/*
 * Copied from php3
 */
/* this is the meat and potatoes of regex replacement! */
static char *
_regreplace (const char *pattern, const char *replace, const char *string,
             int icase, int extended)
{
  regex_t re;
  regmatch_t subs[NS];

  char *buf,        /* buf is where we build the replaced string */
    *nbuf,          /* nbuf is used when we grow the buffer */
    *walkbuf;       /* used to walk buf when replacing backrefs */
  const char *walk; /* used to walk replacement string for backrefs */
  int buf_len;
  int pos, tmp, string_len, new_l;
  int err, copts = 0;

  string_len = strlen (string);

  if (icase)
    copts = REG_ICASE;
  if (extended)
    copts |= REG_EXTENDED;
  err = regcomp (&re, pattern, copts);
  if (err)
    {
      return NULL;
    }

  /* start with a buffer that is twice the size of the stringo
     we're doing replacements in */
  buf_len = 2 * string_len;
  buf = g_malloc0 (buf_len + 1);

  err = pos = 0;
  buf[0] = '\0';

  while (!err)
    {
      err =
        regexec (&re, &string[pos], (size_t) NS, subs, (pos ? REG_NOTBOL : 0));

      if (err && err != REG_NOMATCH)
        {
          g_free (buf);
          return (NULL);
        }
      if (!err)
        {
          /* backref replacement is done in two passes:
             1) find out how long the string will be, and allocate buf
             2) copy the part before match, replacement and backrefs to buf

             Jaakko Hyv?tti <Jaakko.Hyvatti@iki.fi>
           */

          new_l = strlen (buf) + subs[0].rm_so; /* part before the match */
          walk = replace;
          while (*walk)
            if ('\\' == *walk && '0' <= walk[1] && '9' >= walk[1]
                && subs[walk[1] - '0'].rm_so > -1
                && subs[walk[1] - '0'].rm_eo > -1)
              {
                new_l += subs[walk[1] - '0'].rm_eo - subs[walk[1] - '0'].rm_so;
                walk += 2;
              }
            else
              {
                new_l++;
                walk++;
              }

          if (new_l + 1 > buf_len)
            {
              buf_len = buf_len + 2 * new_l;
              nbuf = g_malloc0 (buf_len + 1);
              strncpy (nbuf, buf, buf_len);
              g_free (buf);
              buf = nbuf;
            }
          tmp = strlen (buf);
          /* copy the part of the string before the match */
          strncat (buf, &string[pos], subs[0].rm_so);

          /* copy replacement and backrefs */
          walkbuf = &buf[tmp + subs[0].rm_so];
          walk = replace;
          while (*walk)
            if ('\\' == *walk && '0' <= walk[1] && '9' >= walk[1]
                && subs[walk[1] - '0'].rm_so > -1
                && subs[walk[1] - '0'].rm_eo > -1)
              {
                tmp = subs[walk[1] - '0'].rm_eo - subs[walk[1] - '0'].rm_so;
                memcpy (walkbuf, &string[pos + subs[walk[1] - '0'].rm_so], tmp);
                walkbuf += tmp;
                walk += 2;
              }
            else
              *walkbuf++ = *walk++;
          *walkbuf = '\0';

          /* and get ready to keep looking for replacements */
          if (subs[0].rm_so == subs[0].rm_eo)
            {
              if (subs[0].rm_so + pos >= string_len)
                break;
              new_l = strlen (buf) + 1;
              if (new_l + 1 > buf_len)
                {
                  buf_len = buf_len + 2 * new_l;
                  nbuf = g_malloc0 (buf_len + 1);
                  strncpy (nbuf, buf, buf_len);
                  g_free (buf);
                  buf = nbuf;
                }
              pos += subs[0].rm_eo + 1;
              buf[new_l - 1] = string[pos - 1];
              buf[new_l] = '\0';
            }
          else
            {
              pos += subs[0].rm_eo;
            }
        }
      else
        { /* REG_NOMATCH */
          new_l = strlen (buf) + strlen (&string[pos]);
          if (new_l + 1 > buf_len)
            {
              buf_len = new_l; /* now we know exactly how long it is */
              nbuf = g_malloc0 (buf_len + 1);
              strncpy (nbuf, buf, buf_len);
              g_free (buf);
              buf = nbuf;
            }
          /* stick that last bit of string on our output */
          strcat (buf, &string[pos]);
        }
    }

  buf[new_l] = '\0';
  regfree (&re);
  /* whew. */
  return (buf);
}

/**
 * @brief Search for a pattern in a string and replace it
 * @naslfn{ereg_replace}
 *
 * @naslnparam
 * - @a string  String to search the pattern in
 * - @a pattern patern to search in the string for
 * - @a replace string to replace the pattern with
 * - @a icase   case insensitive flag
 * - @a rnul    replace the null char in the string. Default TRUE.
 *
 * @naslret The new string with the pattern replaced with replace
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_ereg_replace (lex_ctxt *lexic)
{
  char *pattern = get_str_var_by_name (lexic, "pattern");
  char *replace = get_str_var_by_name (lexic, "replace");
  char *string = get_str_var_by_name (lexic, "string");
  int icase = get_int_var_by_name (lexic, "icase", 0);
  int replace_nul = get_int_var_by_name (lexic, "rnul", 1);
  int max_size = get_var_size_by_name (lexic, "string");

  char *r;
  tree_cell *retc;

  if (pattern == NULL || replace == NULL)
    {
      nasl_perror (lexic,
                   "Usage : ereg_replace(string:<string>, pattern:<pat>, "
                   "replace:<replace>, icase:<TRUE|FALSE>\n");
      return NULL;
    }
  if (string == NULL)
    return NULL;

  if (replace_nul)
    string = g_regex_escape_nul (string, max_size);
  else
    string = g_strdup (string);

  r = _regreplace (pattern, replace, string, icase, 1);
  if (r == NULL)
    return FAKE_CELL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (r);
  retc->x.str_val = r;

  return retc;
}

/*---------------------------------------------------------------------*/

/**
 * @brief looks for a pattern in a string, line by line.
 * @naslfn{egrep}
 *
 * @naslnparam
 * - @a string  String to search the pattern in
 * - @a pattern the patern that should be matched
 * - @a icase   case insensitive flag
 * - @a rnul    replace the null char in the string. Default TRUE.
 *
 * @naslret  The concatenation of all lines that match. Null otherwise.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_egrep (lex_ctxt *lexic)
{
  char *pattern = get_str_var_by_name (lexic, "pattern");
  char *string = get_str_var_by_name (lexic, "string");
  int icase = get_int_var_by_name (lexic, "icase", 0);
  int replace_nul = get_int_var_by_name (lexic, "rnul", 1);
  tree_cell *retc;
  regex_t re;
  regmatch_t subs[NS];
  char *s, *t;
  int copt;
  char *rets;
  int max_size = get_var_size_by_name (lexic, "string");

  if (pattern == NULL || string == NULL)
    return NULL;

  bzero (subs, sizeof (subs));
  bzero (&re, sizeof (re));

  if (icase != 0)
    copt = REG_ICASE;
  else
    copt = 0;

  rets = g_malloc0 (max_size + 2);
  if (replace_nul)
    string = g_regex_escape_nul (string, max_size);
  else
    string = g_strdup (string);

  s = string;
  while (s[0] == '\n')
    s++;

  t = strchr (s, '\n');
  if (t != NULL)
    t[0] = '\0';

  if (s[0] != '\0')
    for (;;)
      {
        bzero (&re, sizeof (re));
        if (regcomp (&re, pattern, REG_EXTENDED | copt))
          {
            nasl_perror (
              lexic, "egrep() : regcomp() failed for pattern '%s'.\n", pattern);
            g_free (rets);
            return NULL;
          }

        if (regexec (&re, s, (size_t) NS, subs, 0) == 0)
          {
            char *rt = strchr (s, '\n');

            if (rt != NULL)
              rt[0] = '\0';

            strcat (rets, s);
            strcat (rets, "\n");
            if (rt != NULL)
              rt[0] = '\n';
          }

        regfree (&re);

        if (t == NULL)
          s = NULL;
        else
          s = &(t[1]);

        if (s != NULL)
          {
            while (s[0] == '\n')
              s++; /* Skip empty lines */
            t = strchr (s, '\n');
          }
        else
          t = NULL;

        if (t != NULL)
          t[0] = '\0';

        if (s == NULL || s[0] == '\0')
          break;
      }
#ifdef I_WANT_MANY_DIRTY_ERROR_MESSAGES
  if (rets[0] == '\0')
    {
      g_free (rets);
      g_free (string);
      return FAKE_CELL;
    }
#endif
  g_free (string);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (rets);
  retc->x.str_val = rets;

  return retc;
}

/*---------------------------------------------------------------------*/

/**
 * @brief Does extended regular expression pattern matching.
 * @naslfn{eregmatch}
 *
 * @nasluparam
 *
 * - @a pattern An regex pattern
 * - @a string A string
 * - @a icase Boolean, for case sensitve
 * - @a find_all Boolean, to find all matches
 * - @a rnul replace the null char in the string. Default TRUE.
 *
 * @naslret An array with the first match (find_all: False)
 *          or an array with all matches (find_all: TRUE).
 *          NULL or empty if no match was found.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 */
tree_cell *
nasl_eregmatch (lex_ctxt *lexic)
{
  char *pattern = get_str_var_by_name (lexic, "pattern");
  char *string = get_str_var_by_name (lexic, "string");
  int icase = get_int_var_by_name (lexic, "icase", 0);
  int find_all = get_int_var_by_name (lexic, "find_all", 0);
  int replace_nul = get_int_var_by_name (lexic, "rnul", 1);
  int max_size = get_var_size_by_name (lexic, "string");
  int copt = 0;
  tree_cell *retc;
  regex_t re;
  regmatch_t subs[NS];
  anon_nasl_var v;
  nasl_array *a;

  if (icase != 0)
    copt = REG_ICASE;

  if (pattern == NULL || string == NULL)
    return NULL;

  if (replace_nul)
    string = g_regex_escape_nul (string, max_size);
  else
    string = g_strdup (string);

  if (regcomp (&re, pattern, REG_EXTENDED | copt))
    {
      nasl_perror (lexic, "regmatch() : regcomp() failed for pattern '%s'.\n",
                   pattern);
      return NULL;
    }
  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  if (find_all == 0)
    {
      if (regexec (&re, string, (size_t) NS, subs, 0) != 0)
        {
          regfree (&re);
          return NULL;
        }

      int i;
      for (i = 0; i < NS; i++)
        if (subs[i].rm_so != -1)
          {
            v.var_type = VAR2_DATA;
            v.v.v_str.s_siz = subs[i].rm_eo - subs[i].rm_so;
            v.v.v_str.s_val = (unsigned char *) string + subs[i].rm_so;
            (void) add_var_to_list (a, i, &v);
          }
    }
  else
    {
      int index = 0;
      char *current_pos;
      current_pos = string;
      while (1)
        {
          if (regexec (&re, current_pos, (size_t) NS, subs, 0) != 0)
            {
              regfree (&re);
              break;
            }

          unsigned int offset = 0, i = 0;
          for (i = 0; i < NS; i++)
            {
              char current_pos_cp[strlen (current_pos) + 1];

              if (subs[i].rm_so == -1)
                break;

              if (i == 0)
                offset = subs[i].rm_eo;

              strcpy (current_pos_cp, current_pos);
              current_pos_cp[subs[i].rm_eo] = 0;
              v.var_type = VAR2_DATA;
              v.v.v_str.s_siz = subs[i].rm_eo - subs[i].rm_so;
              v.v.v_str.s_val =
                (unsigned char *) current_pos_cp + subs[i].rm_so;
              (void) add_var_to_list (a, index, &v);
              index++;
            }
          current_pos += offset;
        }
    }

  regfree (&re);
  return retc;
}

/**
 * Syntax: substr(s, i1) or substr(s, i1, i2)
 * Returns character from string s starting for position i1 till the end or
 * position i2 (start of string is 0)
 */
tree_cell *
nasl_substr (lex_ctxt *lexic)
{
  char *s1;
  int sz1, sz2, i1, i2, typ;
  tree_cell *retc;

  s1 = get_str_var_by_num (lexic, 0);
  sz1 = get_var_size_by_num (lexic, 0);
  typ = get_var_type_by_num (lexic, 0);
  i1 = get_int_var_by_num (lexic, 1, -1);
#ifndef MAX_INT
#define MAX_INT (~(1 << (sizeof (int) * 8 - 1)))
#endif
  i2 = get_int_var_by_num (lexic, 2, MAX_INT);
  if (i2 >= sz1)
    i2 = sz1 - 1;

  if (s1 == NULL)
    {
      nasl_perror (lexic, "Usage: substr(string, idx_start [,idx_end])\n. "
                          "The given string is NULL");
      return NULL;
    }
  if (i1 < 0)
    {
      nasl_perror (lexic,
                   "Usage: substr(string, idx_start [,idx_end]). "
                   "At least idx_start must be given to trim the "
                   "string '%s'.\n",
                   s1);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  if (typ == CONST_STR)
    retc->type = CONST_STR;
  if (i1 > i2)
    {
      retc->x.str_val = g_malloc0 (1);
      retc->size = 0;
      return retc;
    }
  sz2 = i2 - i1 + 1;
  retc->size = sz2;
  retc->x.str_val = g_malloc0 (sz2 + 1);
  memcpy (retc->x.str_val, s1 + i1, sz2);
  return retc;
}

/*---------------------------------------------------------------------*/
/**
 * Syntax: insstr(s1, s2, i1, i2) or insstr(s1, s2, i1)
 * Insert string s2 into slice [i1:i2] of string s1 and returns the result
 * Warning: returns a CONST_DATA!
 */
tree_cell *
nasl_insstr (lex_ctxt *lexic)
{
  char *s1, *s2, *s3;
  int sz1, sz2, sz3, i1, i2;
  tree_cell *retc;

  s1 = get_str_var_by_num (lexic, 0);
  sz1 = get_var_size_by_num (lexic, 0);
  s2 = get_str_var_by_num (lexic, 1);
  sz2 = get_var_size_by_num (lexic, 1);

  i1 = get_int_var_by_num (lexic, 2, -1);
  i2 = get_int_var_by_num (lexic, 3, -1);
  if (i2 > sz1 || i2 == -1)
    i2 = sz1 - 1;

  if (s1 == NULL || s2 == NULL || i1 < 0 || i2 < 0)
    {
      nasl_perror (lexic, "Usage: insstr(str1, str2, idx_start [,idx_end])\n");
      return NULL;
    }

  if (i1 >= sz1)
    {
      nasl_perror (lexic,
                   "insstr: cannot insert string2 after end of string1\n");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);

  if (i1 > i2)
    {
      nasl_perror (lexic,
                   " insstr: warning! 1st index %d greater than 2nd index %d\n",
                   i1, i2);
      sz3 = sz2;
    }
  else
    sz3 = sz1 + i1 - i2 - 1 + sz2;

  s3 = retc->x.str_val = g_malloc0 (sz3 + 1);
  retc->size = sz3;

  if (i1 <= sz1)
    {
      memcpy (s3, s1, i1);
      s3 += i1;
    }
  memcpy (s3, s2, sz2);
  s3 += sz2;
  if (i2 < sz1 - 1)
    memcpy (s3, s1 + i2 + 1, sz1 - 1 - i2);

  return retc;
}

tree_cell *
nasl_match (lex_ctxt *lexic)
{
  char *pattern = get_str_var_by_name (lexic, "pattern");
  char *string = get_str_var_by_name (lexic, "string");
  int icase = get_int_var_by_name (lexic, "icase", 0);
  tree_cell *retc;

  if (pattern == NULL)
    {
      nasl_perror (lexic, "nasl_match: parameter 'pattern' missing\n");
      return NULL;
    }
  if (string == NULL)
    {
      nasl_perror (lexic, "nasl_match: parameter 'string' missing\n");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = str_match (string, pattern, icase);
  return retc;
}

tree_cell *
nasl_split (lex_ctxt *lexic)
{
  tree_cell *retc;
  nasl_array *a;
  char *p, *str, *sep;
  int i, i0, j, len, sep_len = 0, keep = 1;
  anon_nasl_var v;

  str = get_str_var_by_num (lexic, 0);
  if (str == NULL)
    return NULL;
  len = get_var_size_by_num (lexic, 0);
  if (len <= 0)
    len = strlen (str);
  if (len <= 0)
    return NULL;

  sep = get_str_var_by_name (lexic, "sep");
  if (sep != NULL)
    {
      sep_len = get_var_size_by_name (lexic, "sep");
      if (sep_len <= 0)
        sep_len = strlen (sep);
      if (sep_len <= 0)
        {
          nasl_perror (lexic, "split: invalid 'seplen' parameter\n");
          return NULL;
        }
    }

  keep = get_int_var_by_name (lexic, "keep", 1);

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  bzero (&v, sizeof (v));
  v.var_type = VAR2_DATA;

  if (sep != NULL)
    {
      i = 0;
      j = 0;
      for (;;)
        {
          if ((p = memmem (str + i, len - i, sep, sep_len)) == NULL)
            {
              v.v.v_str.s_siz = len - i;
              v.v.v_str.s_val = (unsigned char *) str + i;
              (void) add_var_to_list (a, j++, &v);
              return retc;
            }
          else
            {
              if (keep)
                v.v.v_str.s_siz = (p - (str + i)) + sep_len;
              else
                v.v.v_str.s_siz = p - (str + i);
              v.v.v_str.s_val = (unsigned char *) str + i;
              (void) add_var_to_list (a, j++, &v);
              i = (p - str) + sep_len;
              if (i >= len)
                return retc;
            }
        }
    }

  /* Otherwise, we detect the end of line. A little more subtle. */
  for (i = i0 = j = 0; i < len; i++)
    {
      if (str[i] == '\r' && str[i + 1] == '\n')
        {
          i++;
          if (keep)
            v.v.v_str.s_siz = i - i0 + 1;
          else
            v.v.v_str.s_siz = i - i0 - 1;
          v.v.v_str.s_val = (unsigned char *) str + i0;
          i0 = i + 1;
          (void) add_var_to_list (a, j++, &v);
        }
      else if (str[i] == '\n')
        {
          if (keep)
            v.v.v_str.s_siz = i - i0 + 1;
          else
            v.v.v_str.s_siz = i - i0;
          v.v.v_str.s_val = (unsigned char *) str + i0;
          i0 = i + 1;
          (void) add_var_to_list (a, j++, &v);
        }
    }

  if (i > i0)
    {
      v.v.v_str.s_siz = i - i0;
      v.v.v_str.s_val = (unsigned char *) str + i0;
      (void) add_var_to_list (a, j++, &v);
    }
  return retc;
}

/**
 * @brief  Takes an unnamed string argument and removes any spaces at the end of
           it. "Space" means white space, vertical or horizontal tabulation,
           carriage return or line feed.
 */
tree_cell *
nasl_chomp (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *str;
  int len;

  str = get_str_var_by_num (lexic, 0);
  if (str == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);

  g_strchomp (str);
  len = strlen (str);

  retc->x.str_val = g_malloc0 (len + 1);
  retc->size = len;
  memcpy (retc->x.str_val, str, len);
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_crap (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *data = get_str_var_by_name (lexic, "data");
  int data_len = -1;
  int len = get_int_var_by_name (lexic, "length", -1);
  int len2 = get_int_var_by_num (lexic, 0, -1);

  if (len < 0 && len2 < 0)
    {
      nasl_perror (lexic, "crap: invalid or missing 'length' argument\n");
      return NULL;
    }
  if (len >= 0 && len2 >= 0)
    {
      nasl_perror (lexic, "crap: cannot set both unnamed and named 'length'\n");
      return NULL;
    }
  if (len < 0)
    len = len2;

  if (len == 0)
    return FAKE_CELL;

  if (data != NULL)
    {
      data_len = get_var_size_by_name (lexic, "data");
      if (data_len == 0)
        {
          nasl_perror (lexic, "crap: invalid null 'data' parameter\n");
          return NULL;
        }
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_malloc0 (len + 1);
  retc->size = len;
  if (data == NULL)
    memset (retc->x.str_val, 'X', len);
  else
    {
      int i, r;
      for (i = 0; i < len - data_len; i += data_len)
        memcpy (retc->x.str_val + i, data, data_len);

      if (data_len != 1)
        {
          if ((r = (len % data_len)) > 0)
            memcpy (retc->x.str_val + (len - r), data, r);
          else
            memcpy (retc->x.str_val + (len - data_len), data, data_len);
        }
      else
        retc->x.str_val[len - 1] = data[0];
    }
  retc->x.str_val[len] = '\0';
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_strstr (lex_ctxt *lexic)
{
  char *a = get_str_var_by_num (lexic, 0);
  char *b = get_str_var_by_num (lexic, 1);
  int sz_a = get_var_size_by_num (lexic, 0);
  int sz_b = get_var_size_by_num (lexic, 1);

  char *c;
  tree_cell *retc;

  if (a == NULL || b == NULL)
    return NULL;

  if (sz_b > sz_a)
    return NULL;

  c = memmem (a, sz_a, b, sz_b);
  if (c == NULL)
    return FAKE_CELL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = sz_a - (c - a);

  retc->x.str_val = g_malloc0 (retc->size + 1);
  memcpy (retc->x.str_val, c, retc->size + 1);

  return retc;
}

/**
 * @brief Returns index of a substring.
 *
 * Returning NULL for "not found" is dangerous as automatic conversion to
 * to integer would change it into 0.
 * So we return (-1).
 *
 * @return -1 if string not found, otherwise index of substring.
 *
 * @see strstr
 */
tree_cell *
nasl_stridx (lex_ctxt *lexic)
{
  char *a = get_str_var_by_num (lexic, 0);
  int sz_a = get_var_size_by_num (lexic, 0);
  char *b = get_str_var_by_num (lexic, 1);
  int sz_b = get_var_size_by_num (lexic, 1);
  char *c;
  int start = get_int_var_by_num (lexic, 2, 0);
  tree_cell *retc = alloc_typed_cell (CONST_INT);

  retc->x.i_val = -1;
  if (a == NULL || b == NULL)
    {
      nasl_perror (lexic, "stridx(string, substring [, start])\n");
      return retc;
    }

  if (start < 0 || start > sz_a)
    {
      nasl_perror (lexic, "stridx(string, substring [, start])\n");
      return retc;
    }

  if ((sz_a == start) || (sz_b > sz_a + start))
    return retc;

  c = memmem (a + start, sz_a - start, b, sz_b);
  if (c != NULL)
    retc->x.i_val = c - a;
  return retc;
}

/**
 * str_replace(string: s, find: f, replace: r [,count: n])
 */
tree_cell *
nasl_str_replace (lex_ctxt *lexic)
{
  char *a, *b, *r, *s, *c;
  int sz_a, sz_b, sz_r, count;
  int i1, i2, sz2, n, l;
  tree_cell *retc = NULL;

  a = get_str_var_by_name (lexic, "string");
  b = get_str_var_by_name (lexic, "find");
  r = get_str_var_by_name (lexic, "replace");
  sz_a = get_var_size_by_name (lexic, "string");
  sz_b = get_var_size_by_name (lexic, "find");
  sz_r = get_var_size_by_name (lexic, "replace");
  count = get_int_var_by_name (lexic, "count", 0);

  if (a == NULL || b == NULL)
    {
      nasl_perror (lexic, "Missing argument: str_replace(string: s, find: f, "
                          "replace: r [,count: c])\n");
      return NULL;
    }

  if (sz_b == 0)
    {
      nasl_perror (lexic, "str_replace: illegal 'find' argument value\n");
      return NULL;
    }

  if (r == NULL)
    {
      r = "";
      sz_r = 0;
    }

  retc = alloc_typed_cell (CONST_DATA);
  s = g_malloc0 (1);
  sz2 = 0;
  n = 0;
  for (i1 = i2 = 0; i1 <= sz_a - sz_b;)
    {
      c = memmem (a + i1, sz_a - i1, b, sz_b);
      if (c == NULL)
        break;
      l = (c - a) - i1;
      sz2 += sz_r + l;
      s = g_realloc (s, sz2 + 1);
      s[sz2] = '\0';
      if (c - a > i1)
        {
          memcpy (s + i2, a + i1, l);
          i2 += l;
        }
      if (sz_r > 0)
        {
          memcpy (s + i2, r, sz_r);
          i2 += sz_r;
        }
      i1 += l + sz_b;
      n++;
      if (count > 0 && n >= count)
        break;
    }

  if (i1 < sz_a)
    {
      sz2 += (sz_a - i1);
      s = g_realloc (s, sz2 + 1);
      s[sz2] = '\0';
      memcpy (s + i2, a + i1, sz_a - i1);
    }

  retc->x.str_val = s;
  retc->size = sz2;
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_int (lex_ctxt *lexic)
{
  long int r = get_int_var_by_num (lexic, 0, 0);
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = r;

  return retc;
}

/*EOF*/
