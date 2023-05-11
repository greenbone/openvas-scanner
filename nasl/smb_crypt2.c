/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Andrew Bartlett <abartlet@samba.org>
 * SPDX-FileCopyrightText: 1996-2000 Luke Kennethc Casson Leighton
 * SPDX-FileCopyrightText: 1995-2000 Jeremy Allison
 * SPDX-FileCopyrightText: 1992-1998 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file smb_crypt2.c
 * @brief Unix SMB/CIFS implementation. SMB parameters and setup
 */

#include "hmacmd5.h"
#include "smb_crypt.h"

#include <ctype.h>

/*******************************************************************
 Convert a wchar to upper case.
********************************************************************/

static smb_ucs2_t
toupper_w (smb_ucs2_t val)
{
  return UCS2_CHAR (islower (val) ? toupper (val) : val);
}

/*******************************************************************
 Convert a string to upper case.
 return True if any char is converted
********************************************************************/
int
strupper_w (smb_ucs2_t *s)
{
  int ret = 0;
  while (*s)
    {
      smb_ucs2_t v = toupper_w (*s);
      if (v != *s)
        {
          *s = v;
          ret = 1;
        }
      s++;
    }
  return ret;
}

/* Does the md5 encryption from the NT hash for NTLMv2. */
void
SMBOWFencrypt_ntv2_ntlmssp (const uchar *kr, const uchar *srv_chal_data,
                            int srv_chal_len, const uchar *cli_chal_data,
                            int cli_chal_len, uchar resp_buf[16])
{
  HMACMD5Context ctx;

  hmac_md5_init_limK_to_64 (kr, 16, &ctx);
  hmac_md5_update (srv_chal_data, srv_chal_len, &ctx);
  hmac_md5_update (cli_chal_data, cli_chal_len, &ctx);
  hmac_md5_final (resp_buf, &ctx);
}

/* Example:

-smb_session_setup_NTLMv1()

-	if(pawword)
-	{
-	NT_H = nt_owf_gen(password);
-	LM_H = lm_owf_gen(password);
-
-	lm = NTLMv1_HASH(cryptkey:cs, passhash:LM_H);
-	nt = NTLMv1_HASH(cryptkey:cs, passhash:NT_H);

+smb_session_setup_NTLMv2()

+	if(password) {
+		nt_hash = nt_owf_gen(password);
+		ntlm_v2_hash =
ntv2_owf_gen(owf:nt_hash,login:login,domain:domain); +		lm=
NTLMv2_HASH(cryptkey:cs, passhash:ntlm_v2_hash, length:8); +		nt=
NTLMv2_HASH(cryptkey:cs, passhash:ntlm_v2_hash, length:64); +	}

*/
