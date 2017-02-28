/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * MODIFICATION: added definitions for implemention NTLMSSP features
 */
#ifndef NASL_CRYPTO_H
#define NASL_CRYPTO_H

#define MD4_DIGEST_LENGTH 16

tree_cell *nasl_md2 (lex_ctxt *);
tree_cell *nasl_md4 (lex_ctxt *);
tree_cell *nasl_md5 (lex_ctxt *);
tree_cell *nasl_sha (lex_ctxt *);
tree_cell *nasl_sha1 (lex_ctxt *);
tree_cell *nasl_sha256 (lex_ctxt *);
tree_cell *nasl_ripemd160 (lex_ctxt *);
tree_cell *nasl_hmac_md2 (lex_ctxt *);
tree_cell *nasl_hmac_md5 (lex_ctxt *);
tree_cell *nasl_hmac_sha1 (lex_ctxt *);
tree_cell *nasl_hmac_sha256 (lex_ctxt *);
tree_cell *nasl_hmac_sha384 (lex_ctxt *);
tree_cell *nasl_hmac_sha512 (lex_ctxt *);
tree_cell *nasl_hmac_dss (lex_ctxt *);
tree_cell *nasl_hmac_ripemd160 (lex_ctxt *);
tree_cell *nasl_prf_sha256 (lex_ctxt *);
tree_cell *nasl_prf_sha384 (lex_ctxt *);
tree_cell *nasl_tls1_prf (lex_ctxt *);
tree_cell *nasl_ntlmv1_hash (lex_ctxt *);
tree_cell *nasl_nt_owf_gen (lex_ctxt *);
tree_cell *nasl_lm_owf_gen (lex_ctxt *);
tree_cell *nasl_ntv2_owf_gen (lex_ctxt *);
tree_cell *nasl_ntlmv2_hash (lex_ctxt *);
tree_cell *nasl_ntlmv2_response (lex_ctxt * lexic);
tree_cell *nasl_ntlm2_response (lex_ctxt * lexic);
tree_cell *nasl_ntlm_response (lex_ctxt * lexic);
tree_cell *nasl_keyexchg (lex_ctxt * lexic);
tree_cell *nasl_insert_hexzeros (lex_ctxt * lexic);
tree_cell *nasl_get_password (lex_ctxt * lexic);
tree_cell *nasl_get_sign (lex_ctxt * lexic);
tree_cell *nasl_get_smb2_sign (lex_ctxt * lexic);
tree_cell *nasl_hmac_sha256 (lex_ctxt * lexic);
tree_cell *nasl_cipher_des (lex_ctxt *);
#endif
