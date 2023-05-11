/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file ntlmssp.h
 * @brief Functions to support Authentication(type3 message) for NTLMSSP
 * (NTLMv2, NTLM2, NTLM, KEY GEN)
 */

#ifndef NASL_NTLMSSP_H
#define NASL_NTLMSSP_H
#include "byteorder.h"
#include "hmacmd5.h"
#include "md5.h"
#include "proto.h"
#include "smb_crypt.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void
ntlmssp_genauth_ntlmv2 (char *user, char *domain, char *address_list,
                        int address_list_len, char *challenge_data,
                        uint8_t *lm_response, uint8_t *nt_response,
                        uint8_t *session_key, unsigned char *ntlmv2_hash);
void
ntlmssp_genauth_ntlm2 (char *password, uint8_t pass_len, uint8_t *lm_response,
                       uint8_t *nt_response, uint8_t *session_key,
                       char *challenge_data, unsigned char *nt_hash);

void
ntlmssp_genauth_ntlm (char *password, uint8_t pass_len, uint8_t *lm_response,
                      uint8_t *nt_response, uint8_t *session_key,
                      char *challenge_data, unsigned char *nt_hash,
                      int neg_flags);
uint8_t *
ntlmssp_genauth_keyexchg (uint8_t *session_key, char *challenge_data,
                          unsigned char *nt_hash, uint8_t *new_sess_key);

#endif
