/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2000 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file smb_crypt.h
 * @brief Unix SMB/Netbios implementation. Version 1.9.
 *
 * a partial implementation of DES designed for use in the
 * SMB authentication protocol
 */

#ifndef NASL_SMB_CRYPT_H
#define NASL_SMB_CRYPT_H
#include "byteorder.h"
#include "charset.h"
#include "hmacmd5.h"
#include "md4.h"
#include "md5.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

typedef unsigned int bool;
#define False 0
#define True 1

void
E_P24 (const uchar *p21, const uchar *c8, uchar *p24);
void
E_P16 (uchar *p14, uchar *p16);

int
strupper_w (smb_ucs2_t *s); /*implemented in smb_crypt2.c*/

void
SMBsesskeygen_lm_sess_key_ntlmssp (const uchar lm_hash[16],
                                   const uchar lm_resp[24], uint8 sess_key[16]);

void
SMBsesskeygen_ntv1_ntlmssp (const uchar kr[16], const uchar *nt_resp,
                            uint8 sess_key[16]);

void
SMBOWFencrypt_ntlmssp (const uchar passwd[16], const uchar *c8, uchar p24[24]);

void
SMBencrypt_hash_ntlmssp (const uchar lm_hash[16], const uchar *c8,
                         uchar p24[24]);

void
SMBNTencrypt_hash_ntlmssp (const uchar nt_hash[16], uchar *c8, uchar *p24);

bool
E_deshash_ntlmssp (const char *passwd, uint8_t pass_len, uchar p16[16]);

void
SamOEMhash (uchar *data, const uchar *key, int val);

/* Does the md5 encryption from the Key Response for NTLMv2. */
void
SMBOWFencrypt_ntv2_ntlmssp (const uchar *kr, const uint8_t *srv_chal,
                            int srv_chal_len, const uint8_t *cli_chal,
                            int cli_chal_len, uchar resp_buf[16]);

void
SMBsesskeygen_ntv2_ntlmssp (const uchar kr[16], const uchar *nt_resp,
                            uint8 sess_key[16]);

uint8_t *
NTLMv2_generate_client_data_ntlmssp (const char *addr_list,
                                     int address_list_len);

void
NTLMv2_generate_response_ntlmssp (const uchar ntlm_v2_hash[16],
                                  const char *server_chal,
                                  const char *address_list,
                                  int address_list_len, uint8_t *nt_response);

void
LMv2_generate_response_ntlmssp (const uchar ntlm_v2_hash[16],
                                const char *server_chal, uint8_t *lm_response);

void
SMBNTLMv2encrypt_hash_ntlmssp (const char *user, const char *domain,
                               uchar ntlm_v2_hash[16], const char *server_chal,
                               const char *address_list, int address_list_len,
                               unsigned char *lm_response,
                               unsigned char *nt_response,
                               unsigned char *user_session_key);

#endif
