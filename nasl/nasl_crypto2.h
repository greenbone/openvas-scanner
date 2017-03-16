/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
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
 */

#ifndef NASL_CRYPTO2_H
#define NASL_CRYPTO2_H

tree_cell *nasl_bn_random (lex_ctxt *);
tree_cell *nasl_dh_generate_key (lex_ctxt *);
tree_cell *nasl_bn_cmp (lex_ctxt *);
tree_cell *nasl_dh_compute_key (lex_ctxt *);
tree_cell *nasl_rsa_public_encrypt (lex_ctxt *);
tree_cell *nasl_rsa_private_decrypt (lex_ctxt *);
tree_cell *nasl_rsa_public_decrypt (lex_ctxt *);
tree_cell *nasl_bf_cbc_encrypt (lex_ctxt *);
tree_cell *nasl_bf_cbc_decrypt (lex_ctxt *);
tree_cell *nasl_dsa_do_verify (lex_ctxt * lexic);
tree_cell *nasl_pem_to_rsa (lex_ctxt * lexic);
tree_cell *nasl_pem_to_dsa (lex_ctxt * lexic);
tree_cell *nasl_rsa_sign (lex_ctxt * lexic);
tree_cell *nasl_dsa_do_sign (lex_ctxt * lexic);
tree_cell *nasl_rc4_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes128_cbc_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes256_cbc_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes128_ctr_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes256_ctr_encrypt (lex_ctxt * lexic);
tree_cell *nasl_des_ede_cbc_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes128_gcm_encrypt (lex_ctxt * lexic);
tree_cell *nasl_aes256_gcm_encrypt (lex_ctxt * lexic);


int generate_script_signature (char *);
#endif
