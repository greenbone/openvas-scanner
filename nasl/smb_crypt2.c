/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   Copyright (C) Jeremy Allison 1995-2000.
   Copyright (C) Luke Kennethc Casson Leighton 1996-2000.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <ctype.h>

#include "hmacmd5.h"

/*******************************************************************
 Convert a wchar to upper case.
********************************************************************/

smb_ucs2_t toupper_w(smb_ucs2_t val)
{
	return UCS2_CHAR(islower(val)?toupper(val):val);
}

/*******************************************************************
 Convert a string to upper case.
 return True if any char is converted
********************************************************************/
int strupper_w(smb_ucs2_t *s)
{
	int ret = 0;
	while (*s) {
		smb_ucs2_t v = toupper_w(*s);
		if (v != *s) {
			*s = v;
			ret = 1;
		}
		s++;
	}
	return ret;
}

/* Does the md5 encryption from the NT hash for NTLMv2. */
void SMBOWFencrypt_ntv2_ntlmssp(const uchar* kr,
			const uchar* srv_chal_data,
			int srv_chal_len,
			const uchar* cli_chal_data,
			int cli_chal_len,
			uchar resp_buf[16])
{
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(kr, 16, &ctx);
	hmac_md5_update(srv_chal_data, srv_chal_len, &ctx);
	hmac_md5_update(cli_chal_data, cli_chal_len, &ctx);
	hmac_md5_final(resp_buf, &ctx);
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
+		ntlm_v2_hash = ntv2_owf_gen(owf:nt_hash,login:login,domain:domain);
+		lm= NTLMv2_HASH(cryptkey:cs, passhash:ntlm_v2_hash, length:8);
+		nt= NTLMv2_HASH(cryptkey:cs, passhash:ntlm_v2_hash, length:64);
+	}

*/
