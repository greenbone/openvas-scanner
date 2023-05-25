/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002 Jelmer Vernooij
 * SPDX-FileCopyrightText: 2001 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file charset.h
 * @brief Unix SMB/CIFS implementation. charset defines
 */

/* MODIFICATION: This has only those functions that cater to the requirements of
 * OpenVAS, remaining functions are removed*/
#ifndef NASL_CHARSET_H
#define NASL_CHARSET_H

#include "smb.h"

#include <string.h>

/* this defines the charset types used in samba */
typedef enum
{
  CH_UTF16LE = 0,
  CH_UTF16 = 0,
  CH_UNIX = 1,
  CH_DISPLAY = 2,
  CH_DOS = 3,
  CH_UTF8 = 4,
  CH_UTF16BE = 5
} charset_t;

#define NUM_CHARSETS 6
/*
 *   for each charset we have a function that pushes from that charset to a ucs2
 *   buffer, and a function that pulls from ucs2 buffer to that  charset.
 */

struct charset_functions_ntlmssp
{
  const char *name;
  size_t (*pull) (void *, const char **inbuf, size_t *inbytesleft,
                  char **outbuf, size_t *outbytesleft);
  size_t (*push) (void *, const char **inbuf, size_t *inbytesleft,
                  char **outbuf, size_t *outbytesleft);
  struct charset_functions_ntlmssp *prev, *next;
};
#endif
