/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1996-2000 Luke Kenneth Casson Leighton
 * SPDX-FileCopyrightText: 1992-2000 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file hmacmd5.c
 * @brief Unix SMB/CIFS implementation. HMAC MD5 code for use in NTLMv2
 *
 * taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 */

#include "hmacmd5.h"

#include <string.h> /* for memset */

/**
 * @brief The microsoft version of hmac_md5 initialisation.
 */
void
hmac_md5_init_limK_to_64 (const uchar *key, int key_len, HMACMD5Context *ctx)
{
  int i;

  /* if key is longer than 64 bytes truncate it */
  if (key_len > 64)
    {
      key_len = 64;
    }

  /* start out by storing key in pads */
  ZERO_STRUCT (ctx->k_ipad);
  ZERO_STRUCT (ctx->k_opad);
  memcpy (ctx->k_ipad, key, key_len);
  memcpy (ctx->k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i = 0; i < 64; i++)
    {
      ctx->k_ipad[i] ^= 0x36;
      ctx->k_opad[i] ^= 0x5c;
    }

  MD5Init (&ctx->ctx);
  MD5Update (&ctx->ctx, ctx->k_ipad, 64);
}

/**
 * @brief Update hmac_md5 "inner" buffer.
 */
void
hmac_md5_update (const uchar *text, int text_len, HMACMD5Context *ctx)
{
  MD5Update (&ctx->ctx, text, text_len); /* then text of datagram */
}

/**
 * @brief Finish off hmac_md5 "inner" buffer and generate outer one.
 */
void
hmac_md5_final (uchar *digest, HMACMD5Context *ctx)

{
  struct MD5Context ctx_o;

  MD5Final (digest, &ctx->ctx);

  MD5Init (&ctx_o);
  MD5Update (&ctx_o, ctx->k_opad, 64);
  MD5Update (&ctx_o, digest, 16);
  MD5Final (digest, &ctx_o);
}

/**
 * @brief Function to calculate an HMAC MD5 digest from data.
 * Use the microsoft hmacmd5 init method because the key is 16 bytes.
 */
void
hmac_md5 (uchar key[16], uchar *data, int data_len, uchar *digest)
{
  HMACMD5Context ctx;
  hmac_md5_init_limK_to_64 (key, 16, &ctx);
  if (data_len != 0)
    {
      hmac_md5_update (data, data_len, &ctx);
    }
  hmac_md5_final (digest, &ctx);
}
