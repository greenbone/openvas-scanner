/*
   Unix SMB/CIFS implementation.
   Interface header: Scheduler service
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Andrew Tridgell 1992-1999

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

#ifndef _HMAC_MD5_H
#define _HMAC_MD5_H

#include "md5.h"

#ifndef uchar
#define uchar unsigned char
#endif

/* zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

typedef struct
{
        struct MD5Context ctx;
        uchar k_ipad[65];
        uchar k_opad[65];

} HMACMD5Context;

#ifndef SAFE_FREE
/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#endif

/*
 * Note we duplicate the size tests in the unsigned
 * case as int16 may be a typedef from rpc/rpc.h
 */

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

/*
 * SMB UCS2 (16-bit unicode) internal type.
 */
typedef uint16 smb_ucs2_t;

#ifdef WORDS_BIGENDIAN
#define UCS2_SHIFT 8
#else
#define UCS2_SHIFT 0
#endif

/* turn a 7 bit character into a ucs2 character */
#define UCS2_CHAR(c) ((c) << UCS2_SHIFT)
void hmac_md5_init_limK_to_64(const uchar* key, int key_len, HMACMD5Context *ctx);

void hmac_md5_update(const uchar* text, int text_len, HMACMD5Context *ctx);
void hmac_md5_final(uchar *digest, HMACMD5Context *ctx);

void hmac_md5( uchar key[16], uchar* data, int data_len, uchar* digest);

#endif /* _HMAC_MD5_H */
