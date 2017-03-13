/* OpenVAS
 *
 * $Id$
 * Description: Implementation for NTLMSSP support
 *
 * Author:
 * Preeti Subramanian <spreeti@secpod.com>
 *
 * Copyright:
 * Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Functions to support Authentication(type3 message) for NTLMSSP (NTLMv2, NTLM2, NTLM, KEY GEN)
 */
#ifndef _NTLMSSP_H_
#define _NTLMSSP_H_
#include "md5.h"
#include "proto.h"
#include "hmacmd5.h"
#include "byteorder.h"
#include "smb_crypt.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void ntlmssp_genauth_ntlmv2(char* user, char *domain, char* address_list, int address_list_len, char *challenge_data, uint8_t *lm_response,
                            uint8_t *nt_response, uint8_t* session_key, unsigned char* ntlmv2_hash);
void ntlmssp_genauth_ntlm2 (char *password, uint8_t pass_len,
                            uint8_t *lm_response, uint8_t *nt_response,
                            uint8_t *session_key, char *challenge_data,
                            unsigned char* nt_hash);

void ntlmssp_genauth_ntlm (char *password, uint8_t pass_len,
                           uint8_t *lm_response, uint8_t *nt_response,
                           uint8_t *session_key, char *challenge_data,
                           unsigned char* nt_hash, int neg_flags);
uint8_t* ntlmssp_genauth_keyexchg(uint8_t *session_key, char *challenge_data, unsigned char* nt_hash, uint8_t *new_sess_key);

#endif
