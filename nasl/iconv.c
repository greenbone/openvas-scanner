/*
   Unix SMB/CIFS implementation.
   minimal iconv implementation
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jelmer Vernooij 2002,2003

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
/* Modified by Preeti Subramanian <spreeti@secpod.com>
 * Modifications:
 * 	*Some functions removed which are not required for Openvas
 * 	*In smb_iconv_open function, check for module available to
 * 	 do the conversion is not required(removed)
 */

#include "iconv.h"
#include "charset.h"
#include "smb.h"

typedef unsigned int bool;

static size_t iconv_copy_ntlmssp(void *,const char **, size_t *, char **, size_t *);

static struct charset_functions_ntlmssp *charsets = NULL;

static struct charset_functions_ntlmssp *find_charset_functions_ntlmssp(const char *name)
{
        struct charset_functions_ntlmssp *c = charsets;

        while(c) {
                if (strcasecmp(name, c->name) == 0) {
                        return c;
                }
                c = c->next;
        }

        return NULL;
}

/**
 * This is a simple portable iconv() implementaion.
 *
 * It only knows about a very small number of character sets - just
 * enough that Samba works on systems that don't have iconv.
 **/

size_t smb_iconv_ntlmssp(smb_iconv_t cd,
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft)
{
	char cvtbuf[2048];
	char *bufp = cvtbuf;
	size_t bufsize;

	/* in many cases we can go direct */
	if (cd->direct) {
		return cd->direct(cd->cd_direct,
				  inbuf, inbytesleft, outbuf, outbytesleft);
	}


	/* otherwise we have to do it chunks at a time */
	while (*inbytesleft > 0) {
		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf);

		if (cd->pull(cd->cd_pull,
			     inbuf, inbytesleft, &bufp, &bufsize) == (size_t) -1
		    && errno != E2BIG) return -1;

		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf) - bufsize;

		if (cd->push(cd->cd_push,
			     (const char **)&bufp, &bufsize,
			     outbuf, outbytesleft) == (size_t) -1)
                  return -1;
	}

	return 0;
}


static bool is_utf16_ntlmssp(const char *name)
{
	return strcasecmp(name, "UCS-2LE") == 0 ||
		strcasecmp(name, "UTF-16LE") == 0;
}


/*
  simple iconv_open() wrapper
 */
smb_iconv_t smb_iconv_open_ntlmssp(const char *tocode, const char *fromcode)
{
	smb_iconv_t ret;
	struct charset_functions_ntlmssp *from, *to;

	ret = SMB_MALLOC_P(struct _smb_iconv_t);
	if (!ret) {
		errno = ENOMEM;
		return (smb_iconv_t)-1;
	}
	memset(ret, 0, sizeof(struct _smb_iconv_t));

	ret->from_name = SMB_STRDUP(fromcode);
	ret->to_name = SMB_STRDUP(tocode);

	/* check for the simplest null conversion */
	if (strcasecmp(fromcode, tocode) == 0) {
		ret->direct = iconv_copy_ntlmssp;
		return ret;
	}

	/* check if we have a builtin function for this conversion */
	from = find_charset_functions_ntlmssp(fromcode);
	if(from)ret->pull = from->pull;

	to = find_charset_functions_ntlmssp(tocode);
	if(to)ret->push = to->push;

	/* check if we can use iconv for this conversion */
#ifdef HAVE_NATIVE_ICONV
	if (!ret->pull) {
		ret->cd_pull = iconv_open("UTF-16LE", fromcode);
		if (ret->cd_pull == (iconv_t)-1)
			ret->cd_pull = iconv_open("UCS-2LE", fromcode);
		if (ret->cd_pull != (iconv_t)-1)
			ret->pull = sys_iconv;
	}

	if (!ret->push) {
		ret->cd_push = iconv_open(tocode, "UTF-16LE");
		if (ret->cd_push == (iconv_t)-1)
			ret->cd_push = iconv_open(tocode, "UCS-2LE");
		if (ret->cd_push != (iconv_t)-1)
			ret->push = sys_iconv;
	}
#endif

	if (!ret->push || !ret->pull) {
		SAFE_FREE(ret->from_name);
		SAFE_FREE(ret->to_name);
		SAFE_FREE(ret);
		errno = EINVAL;
		return (smb_iconv_t)-1;
	}

	/* check for conversion to/from ucs2 */
	if (is_utf16_ntlmssp(fromcode) && to) {
		ret->direct = to->push;
		ret->push = ret->pull = NULL;
		return ret;
	}

	if (is_utf16_ntlmssp(tocode) && from) {
		ret->direct = from->pull;
		ret->push = ret->pull = NULL;
		return ret;
	}

	/* Check if we can do the conversion direct */
#ifdef HAVE_NATIVE_ICONV
	if (is_utf16(fromcode)) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_push;
		ret->cd_push = NULL;
		return ret;
	}
	if (is_utf16(tocode)) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_pull;
		ret->cd_pull = NULL;
		return ret;
	}
#endif

	return ret;
}

/*
  simple iconv_close() wrapper
*/
int smb_iconv_close_ntlmssp(smb_iconv_t cd)
{
#ifdef HAVE_NATIVE_ICONV
	if (cd->cd_direct) iconv_close((iconv_t)cd->cd_direct);
	if (cd->cd_pull) iconv_close((iconv_t)cd->cd_pull);
	if (cd->cd_push) iconv_close((iconv_t)cd->cd_push);
#endif

	SAFE_FREE(cd->from_name);
	SAFE_FREE(cd->to_name);

	memset(cd, 0, sizeof(*cd));
	SAFE_FREE(cd);
	return 0;
}

static size_t iconv_copy_ntlmssp(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int n;

	n = MIN(*inbytesleft, *outbytesleft);

        (void) cd;
	memmove(*outbuf, *inbuf, n);

	(*inbytesleft) -= n;
	(*outbytesleft) -= n;
	(*inbuf) += n;
	(*outbuf) += n;

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}

	return 0;
}


