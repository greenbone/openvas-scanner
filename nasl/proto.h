/* Copyright (C) 2010-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include <sys/param.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/time.h>
#endif
#include "smb.h"
/*implemented in genrand.c*/
void
generate_random_buffer_ntlmssp (unsigned char *out, int len);
/*implemented in time.c*/
void
put_long_date_ntlmssp (char *p, time_t t);
void
GetTimeOfDay_ntlmssp (struct timeval *tval);
/*implemented in iconv.c*/
size_t
smb_iconv_ntlmssp (smb_iconv_t cd, const char **inbuf, size_t *inbytesleft,
                   char **outbuf, size_t *outbytesleft);
smb_iconv_t
smb_iconv_open_ntlmssp (const char *tocode, const char *fromcode);
int
smb_iconv_close_ntlmssp (smb_iconv_t cd);
/*implemented in arc4.c*/
void
smb_arc4_init_ntlmssp (unsigned char arc4_state_out[258],
                       const unsigned char *key, size_t keylen);
void
smb_arc4_crypt_ntlmssp (unsigned char arc4_state_inout[258],
                        unsigned char *data, size_t len);
/*implemented in charcnv.c*/
void
lazy_initialize_conv_ntlmssp (void);
void
init_iconv_ntlmssp (void);
