/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1996-1999 Luke Kenneth Casson Leighton
 * SPDX-FileCopyrightText: 1992-1999 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file hmacmd5.h
 * @brief Unix SMB/CIFS implementation. HMAC MD5 code for use in NTLMv2
 *
 * taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 */

#ifndef NASL_HMACMD5_H
#define NASL_HMACMD5_H

#include "md5.h"

#ifndef uchar
#define uchar unsigned char
#endif

/* zero a structure */
#define ZERO_STRUCT(x) memset ((char *) &(x), 0, sizeof (x))

typedef struct
{
  struct MD5Context ctx;
  uchar k_ipad[65];
  uchar k_opad[65];

} HMACMD5Context;

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
void
hmac_md5_init_limK_to_64 (const uchar *key, int key_len, HMACMD5Context *ctx);

void
hmac_md5_update (const uchar *text, int text_len, HMACMD5Context *ctx);
void
hmac_md5_final (uchar *digest, HMACMD5Context *ctx);

void
hmac_md5 (uchar key[16], uchar *data, int data_len, uchar *digest);

#endif /* NASL_HMACMD5_H */
