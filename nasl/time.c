/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2007 Jeremy Allison
 * SPDX-FileCopyrightText: 2002 Stefan (metze) Metzmacher
 * SPDX-FileCopyrightText: 1992-2004 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file time.c
 * @brief Unix SMB/CIFS implementation.  time handling functions
 */

/*MODIFICATION: minor changes for OpenVAS*/

#include "byteorder.h"
#include "proto.h"
#include "smb.h"

#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <utime.h>

#ifndef uint32
#define uint32 uint32_t
#endif

/**
 * @file
 * @brief time handling functions
 */

#ifndef TIME_T_MIN
#define TIME_T_MIN                       \
  ((time_t) 0 < (time_t) -1 ? (time_t) 0 \
                            : ~(time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX LONG_MAX
#endif

#define NTTIME_INFINITY (NTTIME) 0x8000000000000000LL

#define TIME_FIXUP_CONSTANT_INT 11644473600LL

/****************************************************************************
 *  Put a 8 byte filetime from a struct timespec. Uses GMT.
 *  ****************************************************************************/

static void
unix_timespec_to_nt_time_ntlmssp (NTTIME *nt, struct timespec ts)
{
  uint64_t d;

  if (ts.tv_sec == 0 && ts.tv_nsec == 0)
    {
      *nt = 0;
      return;
    }
  if (ts.tv_sec == TIME_T_MAX)
    {
      *nt = 0x7fffffffffffffffLL;
      return;
    }
  if (ts.tv_sec == (time_t) -1)
    {
      *nt = (uint64_t) -1;
      return;
    }

  d = ts.tv_sec;
  d += (uint64_t) TIME_FIXUP_CONSTANT_INT;
  d *= 1000 * 1000 * 10;
  /* d is now in 100ns units. */
  d += (ts.tv_nsec / 100);

  *nt = d;
}

/****************************************************************************
 *  Convert a normalized timespec to a timeval.
 *  ****************************************************************************/

/***************************************************************************
 A gettimeofday wrapper.
****************************************************************************/

void
GetTimeOfDay_ntlmssp (struct timeval *tval)
{
  gettimeofday (tval, NULL);
}

/****************************************************************************
 Take a Unix time and convert to an NTTIME structure and place in buffer
 pointed to by p.
****************************************************************************/

static void
put_long_date_timespec_ntlmssp (char *p, struct timespec ts)
{
  NTTIME nt;
  unix_timespec_to_nt_time_ntlmssp (&nt, ts);
  SIVAL (p, 0, nt & 0xFFFFFFFF);
  SIVAL (p, 4, nt >> 32);
}

void
put_long_date_ntlmssp (char *p, time_t t)
{
  struct timespec ts;
  ts.tv_sec = t;
  ts.tv_nsec = 0;
  put_long_date_timespec_ntlmssp (p, ts);
}
