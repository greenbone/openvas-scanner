/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_CRYPTO2_H
#define NASL_NASL_CRYPTO2_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_bn_random (lex_ctxt *);

tree_cell *
nasl_dh_generate_key (lex_ctxt *);

tree_cell *
nasl_bn_cmp (lex_ctxt *);

tree_cell *
nasl_dh_compute_key (lex_ctxt *);

tree_cell *
nasl_rsa_public_encrypt (lex_ctxt *);

tree_cell *
nasl_rsa_private_decrypt (lex_ctxt *);

tree_cell *
nasl_open_rc4_cipher (lex_ctxt *);

tree_cell *
nasl_close_stream_cipher (lex_ctxt *);

tree_cell *
nasl_rsa_public_decrypt (lex_ctxt *);

tree_cell *
nasl_bf_cbc_encrypt (lex_ctxt *);

tree_cell *
nasl_bf_cbc_decrypt (lex_ctxt *);

tree_cell *
nasl_dsa_do_verify (lex_ctxt *lexic);

tree_cell *
nasl_pem_to_rsa (lex_ctxt *lexic);

tree_cell *
nasl_pem_to_dsa (lex_ctxt *lexic);

tree_cell *
nasl_rsa_sign (lex_ctxt *lexic);

tree_cell *
nasl_dsa_do_sign (lex_ctxt *lexic);

tree_cell *
nasl_rc4_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_cbc_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes_mac_cbc (lex_ctxt *lexic);

tree_cell *
nasl_aes_mac_gcm (lex_ctxt *lexic);

tree_cell *
nasl_aes256_cbc_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_ctr_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes256_ctr_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_des_ede_cbc_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_gcm_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_gcm_encrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes128_gcm_decrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_gcm_decrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes256_gcm_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes256_gcm_encrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes256_gcm_decrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes256_gcm_decrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes128_ccm_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_ccm_encrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes128_ccm_decrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes128_ccm_decrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes256_ccm_encrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes256_ccm_encrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_aes256_ccm_decrypt (lex_ctxt *lexic);

tree_cell *
nasl_aes256_ccm_decrypt_auth (lex_ctxt *lexic);

tree_cell *
nasl_smb3kdf (lex_ctxt *lexic);

int
generate_script_signature (char *);
#endif
