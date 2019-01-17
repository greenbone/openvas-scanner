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

/**
 * @file ntlmssp.c
 * @brief Functions to support Authentication(type3 message) for NTLMSSP (NTLMv2, NTLM2, NTLM, KEY GEN)
 */

#include <glib.h>

#include "ntlmssp.h"

#define NTLMSSP_NEGOTIATE_LM_KEY  0x00000080

void ntlmssp_genauth_ntlmv2(char* user, char *domain, char* address_list, int address_list_len, char *challenge_data, uint8_t *lm_response,
                            uint8_t *nt_response, uint8_t* session_key, unsigned char* ntlmv2_hash)
{
  SMBNTLMv2encrypt_hash_ntlmssp(user, domain, ntlmv2_hash, challenge_data, address_list, address_list_len, lm_response, nt_response, session_key);
}

void ntlmssp_genauth_ntlm2 (char *password, uint8_t pass_len,
                           uint8_t *lm_response, uint8_t *nt_response,
                           uint8_t *session_key, char *challenge_data,
                           unsigned char* nt_hash)
{
  unsigned char lm_hash[16];

  E_deshash_ntlmssp (password, pass_len, lm_hash);

  struct MD5Context md5_session_nonce_ctx;
  uchar session_nonce_hash[16];
  uchar session_nonce[16];
  uchar user_session_key[16];

  generate_random_buffer_ntlmssp(lm_response, 8);
  memset(lm_response+8, 0, 16);

  memcpy(session_nonce, challenge_data, 8);
  memcpy(&session_nonce[8], lm_response, 8);

  MD5Init(&md5_session_nonce_ctx);
  MD5Update(&md5_session_nonce_ctx, (unsigned char const*)challenge_data, 8);
  MD5Update(&md5_session_nonce_ctx, (unsigned char const*)lm_response, 8);
  MD5Final(session_nonce_hash, &md5_session_nonce_ctx);

  SMBNTencrypt_hash_ntlmssp(nt_hash,
           session_nonce_hash,
           nt_response);
  SMBsesskeygen_ntv1_ntlmssp(nt_hash, NULL, user_session_key);
                hmac_md5(user_session_key, session_nonce, sizeof(session_nonce), session_key);
}


void ntlmssp_genauth_ntlm (char *password, uint8_t pass_len,
                          uint8_t *lm_response, uint8_t *nt_response,
                          uint8_t *session_key, char *challenge_data,
                          unsigned char* nt_hash, int neg_flags)
{
  unsigned char lm_hash[16];

  E_deshash_ntlmssp (password, pass_len, lm_hash);

  SMBencrypt_hash_ntlmssp(lm_hash, (const uchar*)challenge_data, lm_response);
  SMBNTencrypt_hash_ntlmssp(nt_hash, (uchar*)challenge_data, nt_response);

  if (neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) {
    SMBsesskeygen_lm_sess_key_ntlmssp(lm_hash, lm_response, session_key);
  } else {
    SMBsesskeygen_ntv1_ntlmssp(nt_hash, NULL, session_key);
  }
}

uint8_t * ntlmssp_genauth_keyexchg(uint8_t *session_key, char *challenge_data, unsigned char* nt_hash, uint8_t *new_sess_key)
{
  /* Make up a new session key */
  uint8 client_session_key[16];

  (void) challenge_data;
  (void) nt_hash;
  generate_random_buffer_ntlmssp(client_session_key, sizeof(client_session_key));
  /* Encrypt the new session key with the old one */

  size_t length = sizeof(client_session_key);
  uint8_t * encrypted_session_key = g_malloc0 (length);

  memcpy(encrypted_session_key, client_session_key, length);
  SamOEMhash(encrypted_session_key, session_key, length);
  memcpy(new_sess_key, client_session_key, 16);
  return encrypted_session_key;
}
