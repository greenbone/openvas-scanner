/* Based on work Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#ifndef NASL_CRYPTO_HELPER_H
#define NASL_CRYPTO_HELPER_H

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
