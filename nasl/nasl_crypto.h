/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * MODIFICATION: added definitions for implementing NTLMSSP features
 */

#ifndef NASL_NASL_CRYPTO_H
#define NASL_NASL_CRYPTO_H

#include "nasl_lex_ctxt.h"

#define MD4_DIGEST_LENGTH 16

tree_cell *
nasl_md2 (lex_ctxt *);

tree_cell *
nasl_md4 (lex_ctxt *);

tree_cell *
nasl_md5 (lex_ctxt *);

tree_cell *
nasl_sha (lex_ctxt *);

tree_cell *
nasl_sha1 (lex_ctxt *);

tree_cell *
nasl_sha256 (lex_ctxt *);

tree_cell *
nasl_sha512 (lex_ctxt *);

tree_cell *
nasl_ripemd160 (lex_ctxt *);

tree_cell *
nasl_hmac_md2 (lex_ctxt *);

tree_cell *
nasl_hmac_md5 (lex_ctxt *);

tree_cell *
nasl_hmac_sha1 (lex_ctxt *);

tree_cell *
nasl_hmac_sha256 (lex_ctxt *);

tree_cell *
nasl_hmac_sha384 (lex_ctxt *);

tree_cell *
nasl_hmac_sha512 (lex_ctxt *);

tree_cell *
nasl_hmac_dss (lex_ctxt *);

tree_cell *
nasl_hmac_ripemd160 (lex_ctxt *);

tree_cell *
nasl_prf_sha256 (lex_ctxt *);

tree_cell *
nasl_prf_sha384 (lex_ctxt *);

tree_cell *
nasl_tls1_prf (lex_ctxt *);

tree_cell *
nasl_ntlmv1_hash (lex_ctxt *);

tree_cell *
nasl_nt_owf_gen (lex_ctxt *);

tree_cell *
nasl_lm_owf_gen (lex_ctxt *);

tree_cell *
nasl_ntv2_owf_gen (lex_ctxt *);

tree_cell *
nasl_ntlmv2_hash (lex_ctxt *);

tree_cell *
nasl_ntlmv2_response (lex_ctxt *lexic);

tree_cell *
nasl_ntlm2_response (lex_ctxt *lexic);

tree_cell *
nasl_ntlm_response (lex_ctxt *lexic);

tree_cell *
nasl_keyexchg (lex_ctxt *lexic);

tree_cell *
nasl_insert_hexzeros (lex_ctxt *lexic);

tree_cell *
nasl_get_password (lex_ctxt *lexic);

tree_cell *
nasl_get_sign (lex_ctxt *lexic);

tree_cell *
nasl_get_smb2_sign (lex_ctxt *lexic);

tree_cell *
nasl_smb_cmac_aes_sign (lex_ctxt *lexic);

tree_cell *
nasl_smb_gmac_aes_sign (lex_ctxt *lexic);

tree_cell *
nasl_hmac_sha256 (lex_ctxt *lexic);

tree_cell *
nasl_cipher_des (lex_ctxt *);

#endif
