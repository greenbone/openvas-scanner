/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2003 Martin Pool
 * SPDX-FileCopyrightText: 2001 Simo Sorce
 * SPDX-FileCopyrightText: 2001 Andrew Tridgell
 * SPDX-FileCopyrightText: 2001 Igor Vergeichik <iverg@mail.ru>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file charcnv.c
 * @brief Unix SMB/CIFS implementation: Character set conversion Extensions
 *
 * MODIFICATIONS: only those functions that are required for OpenVAS are
 * retained, others are removed Modified By Preeti Subramanian
 * <spreeti@secpod.com>
 * 1. init_valid_table taken from samba/<source>/lib/util_unistr.c, using a
 * dynamically created valid table only
 * 2. valid_table taken from samba/<source>/lib/util_unistr.c
 * 3. valid_table_use_unmap taken from samba/<source>/lib/util_unistr.c, BOOL is
 * changed to bool
 * 4. check_dos_char_slowly taken from samba/<source>/lib/util_unistr.c,
 * smb_ucs2_t is changed to uint16
 * 5. strlen_w taken from samba/<source>/lib/util_unistr.c, smb_ucs2_t is
 * changed to uint16
 * 6. strupper_m taken from samba/source/lib/util_str.c, and modified for
 * OpenVAS
 * 7. charset_name function changed for OpenVAS
 * 8. in lazy_initialize_conv function, loading or generating the case handling
 * tables removed
 * 9. in init_iconv, init_doschar_table not required(removed)
 */
#include "byteorder.h"
#include "iconv.h"
#include "proto.h"
#include "smb.h"

#include <gvm/base/logging.h>

#ifndef SMB_STRDUP
#define SMB_STRDUP(s) strdup (s)
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

#ifndef uint16
#define uint16 uint16_t
#endif

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

typedef unsigned int bool;
#define False 0
#define True 1

static uint8 *valid_table_ntlmssp;
static bool valid_table_use_unmap_ntlmssp;
size_t
convert_string_ntlmssp (charset_t from, charset_t to, void const *src,
                        size_t srclen, void *dest, size_t destlen,
                        bool allow_badcharcnv);
static int
check_dos_char_slowly_ntlmssp (uint16 c)
{
  char buf[10];
  uint16_t c2 = 0;
  size_t len1, len2;

  len1 = convert_string_ntlmssp (CH_UTF16LE, CH_DOS, &c, 2, buf, sizeof (buf),
                                 False);

  /* convert_string_ntlmssp returns a size_t value, and uses
   * (size_t) -1 as error code */
  if (len1 == 0 || len1 == (size_t) -1)
    {
      return 0;
    }
  len2 = convert_string_ntlmssp (CH_DOS, CH_UTF16LE, buf, len1, &c2, 2, False);
  if (len2 != 2)
    {
      return 0;
    }
  return (c == c2);
}

/* We can parameterize this if someone complains.... JRA. */

static char
lp_failed_convert_char_ntlmssp (void)
{
  return '_';
}

/**
 * @file
 *
 * @brief Character-set conversion routines built on our iconv.
 *
 * @note Samba's internal character set (at least in the 3.0 series)
 * is always the same as the one for the Unix filesystem.  It is
 * <b>not</b> necessarily UTF-8 and may be different on machines that
 * need i18n filenames to be compatible with Unix software.  It does
 * have to be a superset of ASCII.  All multibyte sequences must start
 * with a byte with the high bit set.
 *
 * @sa lib/iconv.c
 */

static smb_iconv_t conv_handles_ntlmssp[NUM_CHARSETS][NUM_CHARSETS];
static bool
  conv_silent_ntlmssp; /* Should we do a debug if the conversion fails ? */

static void
init_valid_table_ntlmssp (void)
{
  static int mapped_file;
  int i;
  const char *allowed = ".!#$%&'()_-@^`~";

  if (mapped_file)
    {
      /* Can't unmap files, so stick with what we have */
      return;
    }

  /* we're using a dynamically created valid_table.
   * It might need to be regenerated if the code page changed.
   * We know that we're not using a mapped file, so we can
   * free() the old one. */

  /* use free rather than unmap */
  valid_table_use_unmap_ntlmssp = False;

  valid_table_ntlmssp = (uint8 *) SMB_MALLOC (0x10000);
  for (i = 0; i < 128; i++)
    {
      valid_table_ntlmssp[i] = isalnum (i) || strchr (allowed, i);
    }

  lazy_initialize_conv_ntlmssp ();

  for (; i < 0x10000; i++)
    {
      uint16_t c;
      SSVAL (&c, 0, i);
      valid_table_ntlmssp[i] = check_dos_char_slowly_ntlmssp (c);
    }
}

/*******************************************************************
 *  Count the number of characters in a uint16_t string.
 *  ********************************************************************/

static size_t
strlen_w_ntlmssp (const uint16 *src)
{
  size_t len;
  uint16 c;

  for (len = 0; *(COPY_UCS2_CHAR (&c, src)); src++, len++)
    {
      ;
    }

  return len;
}

/**
 *  * Return the name of a charset to give to iconv().
 *   **/
static const char *
charset_name_ntlmssp (charset_t ch)
{
  const char *ret = NULL;

  if (ch == CH_UTF16LE)
    ret = "UTF-16LE";
  else if (ch == CH_UTF16BE)
    ret = "UTF-16BE";
  else if (ch == CH_UTF8)
    ret = "UTF8";

#if defined(HAVE_NL_LANGINFO) && defined(CODESET)
  if (ret && !strcmp (ret, "LOCALE"))
    {
      const char *ln = NULL;

#ifdef HAVE_SETLOCALE
      setlocale (LC_ALL, "");
#endif
      ln = nl_langinfo (CODESET);
      if (ln)
        {
          /* Check whether the charset name is supported
          by iconv */
          smb_iconv_t handle = smb_iconv_open_ntlmssp (ln, "UCS-2LE");
          if (handle == (smb_iconv_t) -1)
            {
              ln = NULL;
            }
          else
            {
              smb_iconv_close_ntlmssp (handle);
            }
        }
      ret = ln;
    }
#endif

  if (!ret || !*ret)
    ret = "ASCII";
  return ret;
}

void
lazy_initialize_conv_ntlmssp (void)
{
  static int initialized = False;

  if (!initialized)
    {
      initialized = True;
      init_iconv_ntlmssp ();
    }
}

/**
 * Initialize iconv conversion descriptors.
 *
 * This is called the first time it is needed, and also called again
 * every time the configuration is reloaded, because the charset or
 * codepage might have changed.
 **/
void
init_iconv_ntlmssp (void)
{
  int c1, c2;
  bool did_reload = False;

  /* so that charset_name() works we need to get the UNIX<->UCS2 going
   first */
  if (!conv_handles_ntlmssp[CH_UNIX][CH_UTF16LE])
    conv_handles_ntlmssp[CH_UNIX][CH_UTF16LE] =
      smb_iconv_open_ntlmssp (charset_name_ntlmssp (CH_UTF16LE), "ASCII");

  if (!conv_handles_ntlmssp[CH_UTF16LE][CH_UNIX])
    conv_handles_ntlmssp[CH_UTF16LE][CH_UNIX] =
      smb_iconv_open_ntlmssp ("ASCII", charset_name_ntlmssp (CH_UTF16LE));

  for (c1 = 0; c1 < NUM_CHARSETS; c1++)
    {
      for (c2 = 0; c2 < NUM_CHARSETS; c2++)
        {
          const char *n1 = charset_name_ntlmssp ((charset_t) c1);
          const char *n2 = charset_name_ntlmssp ((charset_t) c2);
          if (conv_handles_ntlmssp[c1][c2]
              && strcmp (n1, conv_handles_ntlmssp[c1][c2]->from_name) == 0
              && strcmp (n2, conv_handles_ntlmssp[c1][c2]->to_name) == 0)
            continue;

          did_reload = True;

          if (conv_handles_ntlmssp[c1][c2])
            smb_iconv_close_ntlmssp (conv_handles_ntlmssp[c1][c2]);

          conv_handles_ntlmssp[c1][c2] = smb_iconv_open_ntlmssp (n2, n1);
          if (conv_handles_ntlmssp[c1][c2] == (smb_iconv_t) -1)
            {
              if (c1 != CH_UTF16LE && c1 != CH_UTF16BE)
                {
                  n1 = "ASCII";
                }
              if (c2 != CH_UTF16LE && c2 != CH_UTF16BE)
                {
                  n2 = "ASCII";
                }
              conv_handles_ntlmssp[c1][c2] = smb_iconv_open_ntlmssp (n2, n1);
              if (!conv_handles_ntlmssp[c1][c2])
                {
                  g_message ("init_iconv_ntlmssp: conv_handle"
                             " initialization failed");
                }
            }
        }
    }

  if (did_reload)
    {
      /* XXX: Does this really get called every time the dos
       * codepage changes? */
      /* XXX: Is the did_reload test too strict? */
      conv_silent_ntlmssp = True;
      init_valid_table_ntlmssp ();
      conv_silent_ntlmssp = False;
    }
}

/**
 * Convert string from one encoding to another, making error checking etc
 * Slow path version - uses (slow) iconv.
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @param allow_bad_conv determines if a "best effort" conversion is acceptable
 *(never returns errors)
 * @returns the number of bytes occupied in the destination
 *
 * Ensure the srclen contains the terminating zero.
 *
 **/

static size_t
convert_string_internal_ntlmssp (charset_t from, charset_t to, void const *src,
                                 size_t srclen, void *dest, size_t destlen,
                                 bool allow_bad_conv)
{
  size_t i_len, o_len;
  size_t retval;
  const char *inbuf = (const char *) src;
  char *outbuf = (char *) dest;
  smb_iconv_t descriptor;

  lazy_initialize_conv_ntlmssp ();

  descriptor = conv_handles_ntlmssp[from][to];

  if (srclen == (size_t) -1)
    {
      if (from == CH_UTF16LE || from == CH_UTF16BE)
        {
          srclen = (strlen_w_ntlmssp ((const uint16 *) src) + 1) * 2;
        }
      else
        {
          srclen = strlen ((const char *) src) + 1;
        }
    }

  if (descriptor == (smb_iconv_t) -1 || descriptor == (smb_iconv_t) 0)
    return (size_t) -1;

  i_len = srclen;
  o_len = destlen;

again:

  retval = smb_iconv_ntlmssp (descriptor, &inbuf, &i_len, &outbuf, &o_len);
  if (retval == (size_t) -1)
    {
      switch (errno)
        {
        case EINVAL:
          /* Incomplete multibyte sequence */
          if (!conv_silent_ntlmssp)
            if (allow_bad_conv)
              goto use_as_is;
          return (size_t) -1;
        case E2BIG:
          /* No more room */
          break;
        case EILSEQ:
          /* Illegal multibyte sequence */
          if (allow_bad_conv)
            goto use_as_is;

          return (size_t) -1;
        default:
          /* unknown error */
          return (size_t) -1;
        }
    }
  return destlen - o_len;

use_as_is:

  /*
   * Conversion not supported. This is actually an error, but there are so
   * many misconfigured iconv systems and smb.conf's out there we can't just
   * fail. Do a very bad conversion instead.... JRA.
   */

  {
    if (o_len == 0 || i_len == 0)
      return destlen - o_len;

    if (((from == CH_UTF16LE) || (from == CH_UTF16BE))
        && ((to != CH_UTF16LE) && (to != CH_UTF16BE)))
      {
        /* Can't convert from utf16 any endian to multibyte.
           Replace with the default fail char.
         */
        if (i_len < 2)
          return destlen - o_len;
        if (i_len >= 2)
          {
            *outbuf = lp_failed_convert_char_ntlmssp ();

            outbuf++;
            o_len--;

            inbuf += 2;
            i_len -= 2;
          }

        if (o_len == 0 || i_len == 0)
          return destlen - o_len;

        /* Keep trying with the next char... */
        goto again;
      }
    else if (from != CH_UTF16LE && from != CH_UTF16BE && to == CH_UTF16LE)
      {
        /* Can't convert to UTF16LE - just widen by adding the
           default fail char then zero.
         */
        if (o_len < 2)
          return destlen - o_len;

        outbuf[0] = lp_failed_convert_char_ntlmssp ();
        outbuf[1] = '\0';

        inbuf++;
        i_len--;

        outbuf += 2;
        o_len -= 2;

        if (o_len == 0 || i_len == 0)
          return destlen - o_len;

        /* Keep trying with the next char... */
        goto again;
      }
    else if (from != CH_UTF16LE && from != CH_UTF16BE && to != CH_UTF16LE
             && to != CH_UTF16BE)
      {
        /* Failed multibyte to multibyte. Just copy the default fail char and
           try again. */
        outbuf[0] = lp_failed_convert_char_ntlmssp ();

        inbuf++;
        i_len--;

        outbuf++;
        o_len--;

        if (o_len == 0 || i_len == 0)
          return destlen - o_len;

        /* Keep trying with the next char... */
        goto again;
      }
    else
      {
        /* Keep compiler happy.... */
        return destlen - o_len;
      }
  }
}

/**
 * Convert string from one encoding to another, making error checking etc
 * Fast path version - handles ASCII first.
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes, or -1 for nul terminated.
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string - *NEVER* -1.
 * @param allow_bad_conv determines if a "best effort" conversion is acceptable
 *(never returns errors)
 * @returns the number of bytes occupied in the destination.
 * On error (size_t) -1 as error code.
 *
 * Ensure the srclen contains the terminating zero.
 *
 * This function has been hand-tuned to provide a fast path.
 * Don't change unless you really know what you are doing. JRA.
 **/

size_t
convert_string_ntlmssp (charset_t from, charset_t to, void const *src,
                        size_t srclen, void *dest, size_t destlen,
                        bool allow_bad_conv)
{
  /*
   * NB. We deliberately don't do a strlen here if srclen == -1.
   * This is very expensive over millions of calls and is taken
   * care of in the slow path in convert_string_internal. JRA.
   */

  if (srclen == 0)
    return 0;

  if (from != CH_UTF16LE && from != CH_UTF16BE && to != CH_UTF16LE
      && to != CH_UTF16BE)
    {
      const unsigned char *p = (const unsigned char *) src;
      unsigned char *q = (unsigned char *) dest;
      size_t slen = srclen;
      size_t dlen = destlen;
      unsigned char lastp = '\0';
      size_t retval = 0;

      /* If all characters are ascii, fast path here. */
      while (slen && dlen)
        {
          if ((lastp = *p) <= 0x7f)
            {
              *q++ = *p++;
              if (slen != (size_t) -1)
                {
                  slen--;
                }
              dlen--;
              retval++;
              if (!lastp)
                break;
            }
          else
            {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
              goto general_case;
#else
              size_t ret = convert_string_internal_ntlmssp (
                from, to, p, slen, q, dlen, allow_bad_conv);
              if (ret == (size_t) -1)
                {
                  return ret;
                }
              return retval + ret;
#endif
            }
        }
      if (!dlen)
        {
          /* Even if we fast path we should note if we ran out of room. */
          if (((slen != (size_t) -1) && slen)
              || ((slen == (size_t) -1) && lastp))
            {
              errno = E2BIG;
            }
        }
      return retval;
    }
  else if (from == CH_UTF16LE && to != CH_UTF16LE)
    {
      const unsigned char *p = (const unsigned char *) src;
      unsigned char *q = (unsigned char *) dest;
      size_t retval = 0;
      size_t slen = srclen;
      size_t dlen = destlen;
      unsigned char lastp = '\0';

      /* If all characters are ascii, fast path here. */
      while (((slen == (size_t) -1) || (slen >= 2)) && dlen)
        {
          if (((lastp = *p) <= 0x7f) && (p[1] == 0))
            {
              *q++ = *p;
              if (slen != (size_t) -1)
                {
                  slen -= 2;
                }
              p += 2;
              dlen--;
              retval++;
              if (!lastp)
                break;
            }
          else
            {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
              goto general_case;
#else
              return retval
                     + convert_string_internal_ntlmssp (from, to, p, slen, q,
                                                        dlen, allow_bad_conv);
#endif
            }
        }
      if (!dlen)
        {
          /* Even if we fast path we should note if we ran out of room. */
          if (((slen != (size_t) -1) && slen)
              || ((slen == (size_t) -1) && lastp))
            {
              errno = E2BIG;
            }
        }
      return retval;
    }
  else if (from != CH_UTF16LE && from != CH_UTF16BE && to == CH_UTF16LE)
    {
      const unsigned char *p = (const unsigned char *) src;
      unsigned char *q = (unsigned char *) dest;
      size_t retval = 0;
      size_t slen = srclen;
      size_t dlen = destlen;
      unsigned char lastp = '\0';

      /* If all characters are ascii, fast path here. */
      while (slen && (dlen >= 2))
        {
          if ((lastp = *p) <= 0x7F)
            {
              *q++ = *p++;
              *q++ = '\0';
              if (slen != (size_t) -1)
                {
                  slen--;
                }
              dlen -= 2;
              retval += 2;
              if (!lastp)
                break;
            }
          else
            {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
              goto general_case;
#else
              return retval
                     + convert_string_internal_ntlmssp (from, to, p, slen, q,
                                                        dlen, allow_bad_conv);
#endif
            }
        }
      if (!dlen)
        {
          /* Even if we fast path we should note if we ran out of room. */
          if (((slen != (size_t) -1) && slen)
              || ((slen == (size_t) -1) && lastp))
            {
              errno = E2BIG;
            }
        }
      return retval;
    }

#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
general_case:
#endif
  return convert_string_internal_ntlmssp (from, to, src, srclen, dest, destlen,
                                          allow_bad_conv);
}
