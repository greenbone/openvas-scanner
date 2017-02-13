/*
   Unix SMB/CIFS implementation.
   charset defines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jelmer Vernooij 2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/* MODIFICATION: This has only those functions that cater to the requirements of OpenVAS, remaining functions are removed*/
#ifndef __CHARSET_H__
#define __CHARSET_H__

#include "smb.h"


/* this defines the charset types used in samba */
typedef enum {CH_UTF16LE=0, CH_UTF16=0, CH_UNIX=1, CH_DISPLAY=2, CH_DOS=3, CH_UTF8=4, CH_UTF16BE=5} charset_t;

#define NUM_CHARSETS 6
/*
 *   for each charset we have a function that pushes from that charset to a ucs2
 *   buffer, and a function that pulls from ucs2 buffer to that  charset.
 */

struct charset_functions_ntlmssp {
  const char *name;
  size_t (*pull)(void *, const char **inbuf, size_t *inbytesleft,
  char **outbuf, size_t *outbytesleft);
  size_t (*push)(void *, const char **inbuf, size_t *inbytesleft,
  char **outbuf, size_t *outbytesleft);
  struct charset_functions_ntlmssp *prev, *next;
};
#endif
