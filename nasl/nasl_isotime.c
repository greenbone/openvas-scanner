/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998, 2002, 2007, 2011 Free Software Foundation, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This code is based on code from GnuPG 2.x, file common/gettime.c,
   commit id 76055d4.  The copyright was LGPLv3+ or GPLv2+; we chose
   GPLv2+.  The only author of that code is Werner Koch; who assigned
   the copyright to the FSF.  */

/**
 * @file nasl_isotime.c
 *
 * @brief Implementation of an API for ISOTIME values
 *
 * This file contains the implementation of the isotime_* NASL builtin
 * functions.
 *
 * @par Background:
 *
 * Most 32 bit systems use a signed 32 bit time_t to represent the
 * system time. The problem is that in 2038 this time type will
 * overflow.  However, we sometimes need to compute dates in the
 * future; for example some certificates are (for whatever reasons)
 * valid for 30 years.  To solve this problem in a platform
 * independent way, we represent the time as a string and provide
 * functions to work with them.  This is not an elegant solution, but
 * all proposed new time APIs have never been implemented on main
 * stream systems - we can't expect that this will happen any time
 * soon.
 */

#include "nasl_isotime.h"

#include "nasl_debug.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <ctype.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

#ifndef DIM
#define DIM(v) (sizeof (v) / sizeof ((v)[0]))
#define DIMof(type, member) DIM (((type *) 0)->member)
#endif

/* The type used to represent the time here is a string with a fixed
   length.  */
#define ISOTIME_SIZE 16
typedef char my_isotime_t[ISOTIME_SIZE];

/* Correction used to map to real Julian days. */
#define JD_DIFF 1721060L

/* Useful helper macros to avoid problems with locales.  */
#define spacep(p) (*(p) == ' ' || *(p) == '\t')
#define digitp(p) (*(p) >= '0' && *(p) <= '9')

/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p) (*(p) - '0')
#define atoi_2(p) ((atoi_1 (p) * 10) + atoi_1 ((p) + 1))
#define atoi_4(p) ((atoi_2 (p) * 100) + atoi_2 ((p) + 2))

/* Convert an Epoch time to an ISO timestamp. */
static void
epoch2isotime (my_isotime_t timebuf, time_t atime)
{
  if (atime == (time_t) (-1))
    *timebuf = 0;
  else
    {
      struct tm tp;

      gmtime_r (&atime, &tp);
      if (snprintf (timebuf, ISOTIME_SIZE, "%04d%02d%02dT%02d%02d%02d",
                    1900 + tp.tm_year, tp.tm_mon + 1, tp.tm_mday, tp.tm_hour,
                    tp.tm_min, tp.tm_sec)
          < 0)
        {
          *timebuf = '\0';
          return;
        }
    }
}

/* Return the current time in ISO format. */
static void
get_current_isotime (my_isotime_t timebuf)
{
  epoch2isotime (timebuf, time (NULL));
}

/* Check that the 15 bytes in ATIME represent a valid ISO timestamp.
   Returns 0 if ATIME has a valid format.  Note that this function
   does not expect a string but a check just the plain 15 bytes of the
   the buffer without looking at the string terminator.  */
static int
check_isotime (const my_isotime_t atime)
{
  int i;
  const char *s;

  if (!*atime)
    return 1;

  for (s = atime, i = 0; i < 8; i++, s++)
    if (!digitp (s))
      return 1;
  if (*s != 'T')
    return 1;
  for (s++, i = 9; i < 15; i++, s++)
    if (!digitp (s))
      return 1;
  return 0;
}

/* Return true if STRING holds an isotime string.  The expected format is
     yyyymmddThhmmss
   optionally terminated by white space, comma, or a colon.
 */
static int
isotime_p (const char *string)
{
  const char *s;
  int i;

  if (!*string)
    return 0;
  for (s = string, i = 0; i < 8; i++, s++)
    if (!digitp (s))
      return 0;
  if (*s != 'T')
    return 0;
  for (s++, i = 9; i < 15; i++, s++)
    if (!digitp (s))
      return 0;
  if (!(!*s || (isascii (*s) && isspace (*s)) || *s == ':' || *s == ','))
    return 0; /* Wrong delimiter.  */

  return 1;
}

/* Scan a string and return true if the string represents the human
   readable format of an ISO time.  This format is:
      yyyy-mm-dd[ hh[:mm[:ss]]]
   Scanning stops at the second space or at a comma.  */
static int
isotime_human_p (const char *string)
{
  const char *s;
  int i;

  if (!*string)
    return 0;
  for (s = string, i = 0; i < 4; i++, s++)
    if (!digitp (s))
      return 0;
  if (*s != '-')
    return 0;
  s++;
  if (!digitp (s) || !digitp (s + 1) || s[2] != '-')
    return 0;
  i = atoi_2 (s);
  if (i < 1 || i > 12)
    return 0;
  s += 3;
  if (!digitp (s) || !digitp (s + 1))
    return 0;
  i = atoi_2 (s);
  if (i < 1 || i > 31)
    return 0;
  s += 2;
  if (!*s || *s == ',')
    return 1; /* Okay; only date given.  */
  if (!spacep (s))
    return 0;
  s++;
  if (spacep (s))
    return 1; /* Okay, second space stops scanning.  */
  if (!digitp (s) || !digitp (s + 1))
    return 0;
  i = atoi_2 (s);
  if (i < 0 || i > 23)
    return 0;
  s += 2;
  if (!*s || *s == ',')
    return 1; /* Okay; only date and hour given.  */
  if (*s != ':')
    return 0;
  s++;
  if (!digitp (s) || !digitp (s + 1))
    return 0;
  i = atoi_2 (s);
  if (i < 0 || i > 59)
    return 0;
  s += 2;
  if (!*s || *s == ',')
    return 1; /* Okay; only date, hour and minute given.  */
  if (*s != ':')
    return 0;
  s++;
  if (!digitp (s) || !digitp (s + 1))
    return 0;
  i = atoi_2 (s);
  if (i < 0 || i > 60)
    return 0;
  s += 2;
  if (!*s || *s == ',' || spacep (s))
    return 1; /* Okay; date, hour and minute and second given.  */

  return 0; /* Unexpected delimiter.  */
}

/* Convert a standard isotime or a human readable variant into an
   isotime structure.  The allowed formats are those described by
   isotime_p and isotime_human_p.  The function returns 0 on failure
   or the length of the scanned string on success.  */
static int
string2isotime (my_isotime_t atime, const char *string)
{
  my_isotime_t dummyatime;

  if (!atime)
    atime = dummyatime;

  memset (atime, '\0', sizeof (my_isotime_t));
  atime[0] = 0;
  if (isotime_p (string))
    {
      memcpy (atime, string, 15);
      atime[15] = 0;
      return 15;
    }
  if (!isotime_human_p (string))
    return 0;
  atime[0] = string[0];
  atime[1] = string[1];
  atime[2] = string[2];
  atime[3] = string[3];
  atime[4] = string[5];
  atime[5] = string[6];
  atime[6] = string[8];
  atime[7] = string[9];
  atime[8] = 'T';
  if (!spacep (string + 10))
    return 10;
  if (spacep (string + 11))
    return 11; /* As per def, second space stops scanning.  */
  atime[9] = string[11];
  atime[10] = string[12];
  if (string[13] != ':')
    {
      atime[11] = '0';
      atime[12] = '0';
      atime[13] = '0';
      atime[14] = '0';
      return 13;
    }
  atime[11] = string[14];
  atime[12] = string[15];
  if (string[16] != ':')
    {
      atime[13] = '0';
      atime[14] = '0';
      return 16;
    }
  atime[13] = string[17];
  atime[14] = string[18];
  return 19;
}

/* Helper for jd2date.  */
static int
days_per_year (int y)
{
  int s;

  s = !(y % 4);
  if (!(y % 100))
    if ((y % 400))
      s = 0;
  return s ? 366 : 365;
}

/* Helper for jd2date.  */
static int
days_per_month (int y, int m)
{
  int s;

  switch (m)
    {
    case 1:
    case 3:
    case 5:
    case 7:
    case 8:
    case 10:
    case 12:
      return 31;
    case 2:
      s = !(y % 4);
      if (!(y % 100))
        if ((y % 400))
          s = 0;
      return s ? 29 : 28;
    case 4:
    case 6:
    case 9:
    case 11:
      return 30;
    default:
      abort ();
    }
}

/* Convert YEAR, MONTH and DAY into the Julian date.  We assume that
   it is already noon.  We do not support dates before 1582-10-15. */
static unsigned long
date2jd (int year, int month, int day)
{
  unsigned long jd;

  jd = 365L * year + 31 * (month - 1) + day + JD_DIFF;
  if (month < 3)
    year--;
  else
    jd -= (4 * month + 23) / 10;

  jd += year / 4 - ((year / 100 + 1) * 3) / 4;

  return jd;
}

/* Convert a Julian date back to YEAR, MONTH and DAY.  Return day of
   the year or 0 on error.  This function uses some more or less
   arbitrary limits, most important is that days before 1582-10-15 are
   not supported. */
static int
jd2date (unsigned long jd, int *year, int *month, int *day)
{
  int y, m, d;
  long delta;

  if (!jd)
    return 0;
  if (jd < 1721425 || jd > 2843085)
    return 0;

  y = (jd - JD_DIFF) / 366;
  d = m = 1;

  while ((delta = jd - date2jd (y, m, d)) > days_per_year (y))
    y++;

  m = (delta / 31) + 1;
  while ((delta = jd - date2jd (y, m, d)) > days_per_month (y, m))
    if (++m > 12)
      {
        m = 1;
        y++;
      }

  d = delta + 1;
  if (d > days_per_month (y, m))
    {
      d = 1;
      m++;
    }
  if (m > 12)
    {
      m = 1;
      y++;
    }

  if (year)
    *year = y;
  if (month)
    *month = m;
  if (day)
    *day = d;

  return (jd - date2jd (y, 1, 1)) + 1;
}

/* Add SECONDS to ATIME.  SECONDS may not be negative and is limited
   to about the equivalent of 62 years which should be more then
   enough for our purposes.  Returns 0 on success.  */
static int
add_seconds_to_isotime (my_isotime_t atime, int nseconds)
{
  int year, month, day, hour, minute, sec, ndays;
  unsigned long jd;

  if (check_isotime (atime))
    return 1;

  if (nseconds < 0 || nseconds >= (0x7fffffff - 61))
    return 1;

  year = atoi_4 (atime + 0);
  month = atoi_2 (atime + 4);
  day = atoi_2 (atime + 6);
  hour = atoi_2 (atime + 9);
  minute = atoi_2 (atime + 11);
  sec = atoi_2 (atime + 13);

  /* The julian date functions don't support this. */
  if (year < 1582 || (year == 1582 && month < 10)
      || (year == 1582 && month == 10 && day < 15))
    return 1;

  sec += nseconds;
  minute += sec / 60;
  sec %= 60;
  hour += minute / 60;
  minute %= 60;
  ndays = hour / 24;
  hour %= 24;

  jd = date2jd (year, month, day) + ndays;
  jd2date (jd, &year, &month, &day);

  if (year > 9999 || month > 12 || day > 31 || year < 0 || month < 1 || day < 1)
    return 1;

  if (snprintf (atime, ISOTIME_SIZE, "%04d%02d%02dT%02d%02d%02d", year, month,
                day, hour, minute, sec)
      < 0)
    return 1;

  return 0;
}

/* Add NDAYS to ATIME.  Returns 0 on success.  */
static int
add_days_to_isotime (my_isotime_t atime, int ndays)
{
  int year, month, day, hour, minute, sec;
  unsigned long jd;

  if (check_isotime (atime))
    return 1;

  if (ndays < 0 || ndays >= 9999 * 366)
    return 1;

  year = atoi_4 (atime + 0);
  month = atoi_2 (atime + 4);
  day = atoi_2 (atime + 6);
  hour = atoi_2 (atime + 9);
  minute = atoi_2 (atime + 11);
  sec = atoi_2 (atime + 13);

  /* The julian date functions don't support this. */
  if (year < 1582 || (year == 1582 && month < 10)
      || (year == 1582 && month == 10 && day < 15))
    return 1;

  jd = date2jd (year, month, day) + ndays;
  jd2date (jd, &year, &month, &day);

  if (year > 9999 || month > 12 || day > 31 || year < 0 || month < 1 || day < 1)
    return 1;

  if (snprintf (atime, ISOTIME_SIZE, "%04d%02d%02dT%02d%02d%02d", year, month,
                day, hour, minute, sec)
      < 0)
    return 1;
  return 0;
}

/* Add NYEARS to ATIME.  Returns 0 on success.  */
static int
add_years_to_isotime (my_isotime_t atime, int nyears)
{
  int year, month, day, hour, minute, sec;
  unsigned long jd;

  if (check_isotime (atime))
    return 1;

  if (nyears < 0 || nyears >= 9999)
    return 1;

  year = atoi_4 (atime + 0);
  month = atoi_2 (atime + 4);
  day = atoi_2 (atime + 6);
  hour = atoi_2 (atime + 9);
  minute = atoi_2 (atime + 11);
  sec = atoi_2 (atime + 13);

  /* The julian date functions don't support this. */
  if (year < 1582 || (year == 1582 && month < 10)
      || (year == 1582 && month == 10 && day < 15))
    return 1;

  jd = date2jd (year + nyears, month, day);
  jd2date (jd, &year, &month, &day);

  if (year > 9999 || month > 12 || day > 31 || year < 0 || month < 1 || day < 1)
    return 1;

  if (snprintf (atime, ISOTIME_SIZE, "%04d%02d%02dT%02d%02d%02d", year, month,
                day, hour, minute, sec)
      < 0)
    return 1;

  return 0;
}

/**
 * @brief Return the current time in ISO format
 * @naslfn{isotime_now}
 *
 * @nasluparam
 *
 * - None
 *
 * @naslret A string with the ISO time.  If the current time is not
 *          available an empty string is returned.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_isotime_now (lex_ctxt *lexic)
{
  tree_cell *retc;
  my_isotime_t timebuf;

  (void) lexic;
  get_current_isotime (timebuf);

  retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = g_strdup (timebuf);
  retc->size = strlen (timebuf);
  return retc;
}

/**
 * @brief Check whether an ISO time string is valid
 * @naslfn{isotime_is_valid}
 *
 *
 * @nasluparam
 *
 * - A string.  Both, the standard 15 byte string and the better human
 *   readable up to 19 byte format are accepted here.  If a plain data
 *   type is is provided only the 15 byte format is accepted.
 *
 * @naslret True is this is an ISO string; false if not.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_isotime_is_valid (lex_ctxt *lexic)
{
  int result = 0;
  tree_cell *retc;
  my_isotime_t timebuf;
  const char *string;
  int datalen;

  string = get_str_var_by_num (lexic, 0);
  if (string)
    {
      switch (get_var_type_by_num (lexic, 0))
        {
        case VAR2_DATA:
          datalen = get_var_size_by_num (lexic, 0);
          if (datalen < ISOTIME_SIZE - 1)
            break; /* Too short */
          memcpy (timebuf, string, ISOTIME_SIZE - 1);
          timebuf[ISOTIME_SIZE - 1] = 0;
          string = timebuf;
          /* FALLTHRU */
        case VAR2_STRING:
          if (isotime_p (string) || isotime_human_p (string))
            result = 1;
          break;
        default:
          break;
        }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result;
  return retc;
}

/**
 * @brief Convert a string into an ISO time string.
 * @naslfn{isotime_scan}
 *
 *
 * @nasluparam
 *
 * - A string
 *
 * @naslret A ISO time string on success or NULL on error.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_isotime_scan (lex_ctxt *lexic)
{
  tree_cell *retc;
  my_isotime_t timebuf;
  int datalen;
  const char *string;

  *timebuf = 0;
  string = get_str_var_by_num (lexic, 0);
  if (!string)
    return NULL;
  switch (get_var_type_by_num (lexic, 0))
    {
    case VAR2_DATA:
      datalen = get_var_size_by_num (lexic, 0);
      if (datalen < ISOTIME_SIZE - 1)
        return NULL; /* Too short */
      memcpy (timebuf, string, ISOTIME_SIZE - 1);
      timebuf[ISOTIME_SIZE - 1] = 0;
      string = timebuf;
      /* FALLTHRU */
    case VAR2_STRING:
      if (!string2isotime (timebuf, string))
        return NULL;
      break;
    default:
      return NULL;
    }

  retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = g_strdup (timebuf);
  retc->size = strlen (timebuf);
  return retc;
}

/**
 * @brief Convert an SIO time string into a better readable string
 * @naslfn{isotime_print}
 *
 * @nasluparam
 *
 * - An ISO time string.
 *
 * @naslret A string in the format "YYYY-MM-DD HH:MM:SS" or "[none]"
 *          if the provided time string is not valid.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_isotime_print (lex_ctxt *lexic)
{
  tree_cell *retc;
  const char *string;
  char helpbuf[20];

  string = get_str_var_by_num (lexic, 0);
  if (!string || get_var_size_by_num (lexic, 0) < 15 || check_isotime (string))
    strcpy (helpbuf, "[none]");
  else
    snprintf (helpbuf, sizeof helpbuf, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s", string,
              string + 4, string + 6, string + 9, string + 11, string + 13);
  retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = g_strdup (helpbuf);
  retc->size = strlen (helpbuf);
  return retc;
}

/**
 * @brief Add days or seconds to an ISO time string.
 * @naslfn{isotime_add}
 *
 * This function adds days or seconds to an ISO time string and
 * returns the resulting time string.  The number of days or seconds
 * are given using the named parameters; if none are given nothing is
 * added; if both are given both additions are performed.  This
 * function won't work for dates before the Gregorian calendar switch.
 *
 * @nasluparam
 *
 * - An ISO time string
 *
 * @naslnparam
 *
 * - @a years An integer with the number of years to add to the timestamp.
 *
 * - @a days An integer with the number of days to add to the timestamp.
 *
 * - @a seconds An integer with the number of seconds to add to the
 *              timestamp.
 *
 * @naslret The resulting ISO time string or NULL if the provided ISO
 *          time string is not valid or the result would overflow
 *          (i.e. year > 9999).
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
nasl_isotime_add (lex_ctxt *lexic)
{
  tree_cell *retc;
  my_isotime_t timebuf;
  const char *string;
  int nyears, ndays, nseconds;

  string = get_str_var_by_num (lexic, 0);
  if (!string || get_var_size_by_num (lexic, 0) < ISOTIME_SIZE - 1
      || check_isotime (string))
    return NULL;
  memcpy (timebuf, string, ISOTIME_SIZE - 1);
  timebuf[ISOTIME_SIZE - 1] = 0;

  nyears = get_int_var_by_name (lexic, "years", 0);
  ndays = get_int_var_by_name (lexic, "days", 0);
  nseconds = get_int_var_by_name (lexic, "seconds", 0);

  if (nyears && add_years_to_isotime (timebuf, nyears))
    return NULL;
  if (ndays && add_days_to_isotime (timebuf, ndays))
    return NULL;
  if (nseconds && add_seconds_to_isotime (timebuf, nseconds))
    return NULL;
  /* If nothing was added, explicitly add 0 years.  */
  if (!nyears && !ndays && !nseconds && add_years_to_isotime (timebuf, 0))
    return NULL;

  retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = g_strdup (timebuf);
  retc->size = strlen (timebuf);
  return retc;
}
