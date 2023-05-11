/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_CRYPTO_HELPER_H
#define NASL_NASL_CRYPTO_HELPER_H

#include "nasl_lex_ctxt.h"

#include <gpg-error.h>
void *
hmac_md5_for_prf (const void *key, int keylen, const void *buf, int buflen);

void *
hmac_sha1 (const void *key, int keylen, const void *buf, int buflen);

void *
hmac_sha256 (const void *key, int keylen, const void *buf, int buflen);

void *
hmac_sha384 (const void *key, int keylen, const void *buf, int buflen);

tree_cell *
nasl_smb_sign (const int algo, lex_ctxt *lexic);

gpg_err_code_t
mac (const char *key, const size_t key_len, const char *data,
     const size_t data_len, const char *iv, const size_t iv_len, int algo,
     int flags, char **out, size_t *out_len);
#endif
