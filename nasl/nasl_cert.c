/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_cert.c
 *
 * @brief Implementation of an API for X.509 certificates
 *
 * This file contains the implementation of the cert_* NASL builtin
 * functions.
 */

#ifdef HAVE_LIBKSBA
#include "nasl_cert.h"

#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <errno.h>
#include <gcrypt.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gvm/base/logging.h>
#include <ksba.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

#ifndef DIM
#define DIM(v) (sizeof (v) / sizeof ((v)[0]))
#define DIMof(type, member) DIM (((type *) 0)->member)
#endif

/* Useful helper macros to avoid problems with locales.  */
#define spacep(p) (*(p) == ' ' || *(p) == '\t')
#define digitp(p) (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) \
  (digitp (a) || (*(a) >= 'A' && *(a) <= 'F') || (*(a) >= 'a' && *(a) <= 'f'))

/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p) (*(p) - '0')
#define atoi_2(p) ((atoi_1 (p) * 10) + atoi_1 ((p) + 1))
#define atoi_4(p) ((atoi_2 (p) * 100) + atoi_2 ((p) + 2))
#define xtoi_1(p)                    \
  (*(p) <= '9'   ? (*(p) - '0')      \
   : *(p) <= 'F' ? (*(p) - 'A' + 10) \
                 : (*(p) - 'a' + 10))
#define xtoi_2(p)                              \
  ((xtoi_1 ((const unsigned char *) (p)) * 16) \
   + xtoi_1 ((const unsigned char *) (p) + 1))

/* Convert N to a hex digit.  N must be in the range 0..15.  */
#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) -10) + 'A'))

/* This object is used to keep track of KSBA certificate objects.
   Because they are pointers they can't be mapped easily to the NASL
   type system.  Our solution is to track those objects here and clean
   up any left over context at the end of a script run.  We could use
   the undocumented "on_exit" feature but that one is not well
   implemented; thus we use explicit code in the interpreter for the
   cleanup.  The scripts are expected to close the objects, but as
   long as they don't open too many of them, the system will take care
   of it at script termination time.

   We associate each object with an object id, which is a global
   counter of this process.  An object id of 0 marks an unused table
   entry.
 */
struct object_desc_s;
typedef struct object_desc_s *object_desc_t;
struct object_desc_s
{
  object_desc_t next;
  int object_id;
  ksba_cert_t cert;
};

/* A linked list of all used certificate objects.  */
static object_desc_t object_list;

/* Return the next object id.  */
static int
next_object_id (void)
{
  static int last;
  static int wrapped;

again:
  last++;
  /* Because we don't have an unsigned type, it is better to avoid
     negative values.  Thus if LAST turns negative we wrap around to
     the 1; this also avoids the verboten zero.  */
  if (last <= 0)
    {
      last = 1;
      wrapped = 1;
    }

  /* If the counter wrapped we need to check that we do not return an
     object id still in use.  We use a stupid simple retry algorithm;
     this could be improved, for example, by remembering gaps in the
     list of used ids.  This code part is anyway not easy to test
     unless we implement a test feature for this function.  */
  if (wrapped)
    {
      object_desc_t obj;

      for (obj = object_list; obj; obj = obj->next)
        if (obj->object_id == last)
          goto again;
    }
  return last;
}

/**
 * @brief Create a certificate object.
 * @naslfn{cert_open}
 *
 * Takes a string/data as unnamed argument and returns an identifier
 * used with the other cert functions.  The data is usually the BER
 * encoded certificate but the function will also try a PEM encoding
 * on failure to parse BER encoded one.
 *
 * @nasluparam
 *
 * - String/data object with the certificate.  Either binary or
 *   PEM encoded.
 *
 * @naslnparam
 *
 * - @a errorvar Name of a variable used on error to return an error
 *               description.
 *
 * @naslret An integer used as an id for the certificate; on error 0
 *          is returned.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return On success the function returns a tree-cell with a non-zero
 *         object identifier for use with other cert functions; zero is
 *         returned on error.
 */
tree_cell *
nasl_cert_open (lex_ctxt *lexic)
{
  gpg_error_t err;
  tree_cell *retc;
  const char *data;
  int datalen;
  ksba_reader_t reader;
  ksba_cert_t cert;
  object_desc_t obj;

  data = get_str_var_by_num (lexic, 0);
  if (!data || !(datalen = get_var_size_by_num (lexic, 0)))
    {
      g_message ("No certificate passed to cert_open");
      return NULL;
    }

  err = ksba_reader_new (&reader);
  if (err)
    {
      g_message ("Opening reader object failed: %s", gpg_strerror (err));
      return NULL;
    }
  err = ksba_reader_set_mem (reader, data, datalen);
  if (err)
    {
      g_message ("ksba_reader_set_mem failed: %s", gpg_strerror (err));
      ksba_reader_release (reader);
      return NULL;
    }

  err = ksba_cert_new (&cert);
  if (err)
    {
      g_message ("ksba_cert_new failed: %s", gpg_strerror (err));
      ksba_reader_release (reader);
      return NULL;
    }

  err = ksba_cert_read_der (cert, reader);
  if (err)
    {
      g_message ("Certificate parsing failed: %s", gpg_strerror (err));
      /* FIXME: Try again this time assuming a PEM certificate.  */
      ksba_reader_release (reader);
      ksba_cert_release (cert);
      return NULL;
    }
  ksba_reader_release (reader);

  obj = g_try_malloc (sizeof *obj);
  if (!obj)
    {
      g_message ("malloc failed in %s", __func__);
      ksba_cert_release (cert);
      return NULL;
    }
  obj->object_id = next_object_id ();
  obj->cert = cert;
  obj->next = object_list;
  object_list = obj;

  /* Return the session id.  */
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = obj->object_id;
  return retc;
}

/**
 * @brief Release a certificate object.
 * @naslfn{cert_close}
 *
 * Takes a cert identifier as returned by cert_open and releases the
 * associated resources.

 * @nasluparam
 *
 * - Object id of the certificate.  0 acts as a NOP.
 *
 * @naslret none
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return none
 */
tree_cell *
nasl_cert_close (lex_ctxt *lexic)
{
  int object_id;
  object_desc_t prevobj, obj;

  object_id = get_int_var_by_num (lexic, 0, -1);
  if (!object_id)
    return FAKE_CELL;
  if (object_id < 0)
    {
      g_message ("Bad object id %d passed to cert_close", object_id);
      return FAKE_CELL;
    }

  for (prevobj = NULL, obj = object_list; obj; prevobj = obj, obj = obj->next)
    if (obj->object_id == object_id)
      break;
  if (!obj)
    {
      g_message ("Unused object id %d passed to cert_close", object_id);
      return FAKE_CELL;
    }

  if (prevobj)
    prevobj->next = obj->next;
  else
    object_list = obj->next;

  ksba_cert_release (obj->cert);
  g_free (obj);

  return FAKE_CELL;
}

/* Helper to get the value of the Common Name part.  */
static const char *
parse_dn_part_for_CN (const char *string, char **r_value)
{
  const char *s, *s1;
  size_t n;
  char *p = NULL;
  int found;

  *r_value = NULL;

  /* Parse attributeType */
  for (s = string + 1; *s && *s != '='; s++)
    ;
  if (!*s)
    return NULL; /* Error */
  n = s - string;
  if (!n)
    return NULL; /* Empty key */

  found = (n == 2 && string[0] == 'C' && string[1] == 'N');
  string = s + 1;

  if (*string == '#') /* Hex encoded value.  */
    {
      string++;
      for (s = string; hexdigitp (s); s++)
        s++;
      n = s - string;
      if (!n || (n & 1))
        return NULL; /* No or odd number of digits. */
      n /= 2;
      if (found)
        *r_value = p = g_malloc0 (n + 1);

      for (s1 = string; n; s1 += 2, n--, p++)
        {
          if (found)
            {
              *(unsigned char *) p = xtoi_2 (s1);
              if (!*p)
                *p = 0x01; /* Better return a wrong value than
                              truncate the string. */
            }
        }
      if (found)
        *p = 0;
    }
  else /* Regular V3 quoted string */
    {
      for (n = 0, s = string; *s; s++)
        {
          if (*s == '\\') /* Pair */
            {
              s++;
              if (*s == ',' || *s == '=' || *s == '+' || *s == '<' || *s == '>'
                  || *s == '#' || *s == ';' || *s == '\\' || *s == '\"'
                  || *s == ' ')
                n++;
              else if (hexdigitp (s) && hexdigitp (s + 1))
                {
                  s++;
                  n++;
                }
              else
                return NULL; /* Invalid escape sequence. */
            }
          else if (*s == '\"')
            return NULL; /* Invalid encoding.  */
          else if (*s == ',' || *s == '=' || *s == '+' || *s == '<' || *s == '>'
                   || *s == ';')
            break; /* End of that part.  */
          else
            n++;
        }

      if (found)
        *r_value = p = g_malloc0 (n + 1);

      for (s = string; n; s++, n--)
        {
          if (*s == '\\')
            {
              s++;
              if (hexdigitp (s))
                {
                  if (found)
                    {
                      *(unsigned char *) p = xtoi_2 (s);
                      if (!*p)
                        *p = 0x01; /* Better return a wrong value than
                                      truncate the string. */
                      p++;
                    }
                  s++;
                }
              else if (found)
                *p++ = *s;
            }
          else if (found)
            *p++ = *s;
        }
      if (found)
        *p = 0;
    }
  return s;
}

/* Parse a DN and return the value of the CommonName.  Note that this
   is not a validating parser and it does not support any old-stylish
   syntax; this is not a problem because KSBA will always return
   RFC-2253 compatible strings.  The caller must use free to free the
   returned value. */
static char *
parse_dn_for_CN (const char *string)
{
  char *value = NULL;

  while (*string && !value)
    {
      while (*string == ' ')
        string++;
      if (!*string)
        break; /* ready */
      string = parse_dn_part_for_CN (string, &value);
      if (!string)
        goto failure;
      while (*string == ' ')
        string++;
      if (*string && *string != ',' && *string != ';' && *string != '+')
        goto failure; /* Invalid delimiter.  */
      if (*string == '+')
        goto failure; /* A multivalued CN is not supported.  */
      if (*string)
        string++;
    }
  return value;

failure:
  g_free (value);
  return NULL;
}

/* Given a CERT object, build an array with all hostnames identified
   by the certificate.  */
static tree_cell *
build_hostname_list (ksba_cert_t cert)
{
  tree_cell *retc;
  char *name, *value;
  int arridx;
  int idx;
  nasl_array *a;
  anon_nasl_var v;

  name = ksba_cert_get_subject (cert, 0);
  if (!name)
    return NULL; /* No valid subject.  */

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof *a);
  arridx = 0;

  value = parse_dn_for_CN (name);
  ksba_free (name);

  /* Add the CN to the array even if it doesn't look like a hostname. */
  if (value)
    {
      memset (&v, 0, sizeof v);
      v.var_type = VAR2_DATA;
      v.v.v_str.s_val = (unsigned char *) value;
      v.v.v_str.s_siz = strlen (value);
      add_var_to_list (a, arridx++, &v);
    }
  g_free (value);
  value = NULL;

  for (idx = 1; (name = ksba_cert_get_subject (cert, idx)); idx++)
    {
      /* Poor man's s-expression parser.  Despite it simple code, it
         is correct in this case because ksba will always return a
         valid s-expression.  */
      if (*name == '(' && name[1] == '8' && name[2] == ':'
          && !memcmp (name + 3, "dns-name", 8))
        {
          char *endp;
          unsigned long n = strtoul (name + 11, &endp, 10);

          if (*endp != ':')
            {
              ksba_free (name);
              return NULL;
            }
          endp++;
          memset (&v, 0, sizeof v);
          v.var_type = VAR2_DATA;
          v.v.v_str.s_val = (unsigned char *) endp;
          v.v.v_str.s_siz = n;
          add_var_to_list (a, arridx++, &v);
        }
      ksba_free (name);
    }

  return retc;
}

/**
 * @brief Convert a memory buffer to a tree cell with a hex string
 *
 */
static tree_cell *
make_hexstring (const void *buffer, size_t length)
{
  const unsigned char *s;
  tree_cell *retc;
  char *p;

  retc = alloc_typed_cell (CONST_STR);
  retc->size = length * 2;
  retc->x.str_val = p = g_malloc0 (length * 2 + 1);

  for (s = buffer; length; length--, s++)
    {
      *p++ = tohex ((*s >> 4) & 15);
      *p++ = tohex (*s & 15);
    }
  *p = 0;

  return retc;
}

/**
 * @brief Take a certificate object and return its fingerprint.
 *
 * @param cert  A KSBA certificate object.
 * @param algo  Either GCRY_MD_SHA1 or GCRY_MD_SHA256
 *
 * @return A new tree cell with an all uppercase hex string
 *         representing the fingerprint or NULL on error.
 */
static tree_cell *
get_fingerprint (ksba_cert_t cert, int algo)
{
  int dlen;
  const unsigned char *der;
  size_t derlen;
  unsigned char digest[32];

  dlen = gcry_md_get_algo_dlen (algo);
  if (dlen != 20 && dlen != 32)
    return NULL; /* We only support SHA-1 and SHA-256.  */

  der = ksba_cert_get_image (cert, &derlen);
  if (!der)
    return NULL;
  gcry_md_hash_buffer (algo, digest, der, derlen);

  return make_hexstring (digest, dlen);
}

/*
 * @brief Return algorithm name from its OID.
 *
 * param[in]    oid     Algorithm ID.
 *
 * @return Algorithm name or NULL.
 */
static const char *
get_oid_name (const char *oid)
{
  /* Initial list from Wireshark. See epan/dissectors/packet-pkcs1.c */
  if (!strcmp ("1.2.840.10040.4.1", oid))
    return "id-dsa";
  else if (!strcmp ("1.2.840.10046.2.1", oid))
    return "dhpublicnumber";
  else if (!strcmp ("2.16.840.1.101.2.1.1.22", oid))
    return "id-keyExchangeAlgorithm";
  else if (!strcmp ("1.2.840.10045.1.1", oid))
    return "prime-field";
  else if (!strcmp ("1.2.840.10045.2.1", oid))
    return "id-ecPublicKey";
  else if (!strcmp ("1.2.840.10045.4.1", oid))
    return "ecdsa-with-SHA1";
  else if (!strcmp ("1.2.840.10045.4.3.1", oid))
    return "ecdsa-with-SHA224";
  else if (!strcmp ("1.2.840.10045.4.3.2", oid))
    return "ecdsa-with-SHA256";
  else if (!strcmp ("1.2.840.10045.4.3.3", oid))
    return "ecdsa-with-SHA384";
  else if (!strcmp ("1.2.840.10045.4.3.4", oid))
    return "ecdsa-with-SHA512";
  else if (!strcmp ("1.3.132.1.12", oid))
    return "id-ecDH";
  else if (!strcmp ("1.2.840.10045.2.13", oid))
    return "id-ecMQV";
  else if (!strcmp ("1.2.840.113549.1.1.10", oid))
    return "id-RSASSA-PSS";
  else if (!strcmp ("1.2.840.113549.1.1.11", oid))
    return "sha256WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.12", oid))
    return "sha384WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.13", oid))
    return "sha512WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.14", oid))
    return "sha224WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.8", oid))
    return "id-mgf1";
  else if (!strcmp ("1.2.840.113549.2.2", oid))
    return "md2";
  else if (!strcmp ("1.2.840.113549.2.4", oid))
    return "md4";
  else if (!strcmp ("1.2.840.113549.2.5", oid))
    return "md5";
  else if (!strcmp ("1.2.840.113549.1.1.1", oid))
    return "rsaEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.2", oid))
    return "md2WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.3", oid))
    return "md4WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.4", oid))
    return "md5WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.5", oid))
    return "sha1WithRSAEncryption";
  else if (!strcmp ("1.2.840.113549.1.1.6", oid))
    return "rsaOAEPEncryptionSET";
  else if (!strcmp ("1.2.840.10045.3.1.1", oid))
    return "secp192r1";
  else if (!strcmp ("1.3.132.0.1", oid))
    return "sect163k1";
  else if (!strcmp ("1.3.132.0.15", oid))
    return "sect163r2";
  else if (!strcmp ("1.3.132.0.33", oid))
    return "secp224r1";
  else if (!strcmp ("1.3.132.0.26", oid))
    return "sect233k1";
  else if (!strcmp ("1.3.132.0.27", oid))
    return "sect233r1";
  else if (!strcmp ("1.2.840.10045.3.1.7", oid))
    return "secp256r1";
  else if (!strcmp ("1.3.132.0.16", oid))
    return "sect283k1";
  else if (!strcmp ("1.3.132.0.17", oid))
    return "sect283r1";
  else if (!strcmp ("1.3.132.0.34", oid))
    return "secp384r1";
  else if (!strcmp ("1.3.132.0.36", oid))
    return "sect409k1";
  else if (!strcmp ("1.3.132.0.37", oid))
    return "sect409r1";
  else if (!strcmp ("1.3.132.0.35", oid))
    return "sect521r1";
  else if (!strcmp ("1.3.132.0.38", oid))
    return "sect571k1";
  else if (!strcmp ("1.3.132.0.39", oid))
    return "sect571r1";
  else if (!strcmp ("2.16.840.1.101.3.4.3.1", oid))
    return "id-dsa-with-sha224";
  else if (!strcmp ("2.16.840.1.101.3.4.3.2", oid))
    return "id-dsa-with-sha256";
  else if (!strcmp ("2.16.840.1.101.3.4.2.1", oid))
    return "sha256";
  else if (!strcmp ("2.16.840.1.101.3.4.2.2", oid))
    return "sha384";
  else if (!strcmp ("2.16.840.1.101.3.4.2.3", oid))
    return "sha512";
  else if (!strcmp ("2.16.840.1.101.3.4.2.4", oid))
    return "sha224";
  else
    return NULL;
}

/**
 * @brief Helper to convert a RFC-2253 string to a tree cell.
 *
 * This function also takes care of the special formats the
 * ksba_get_subjscte uses.
 */
static tree_cell *
get_name (const char *string)
{
  tree_cell *retc;

  if (*string == '(')
    {
      /* This is an s-expression in canonical format.  We convert it
         to advanced format.  */
      gcry_sexp_t sexp;
      size_t len;
      char *buffer;

      len = gcry_sexp_canon_len ((const unsigned char *) string, 0, NULL, NULL);
      if (gcry_sexp_sscan (&sexp, NULL, string, len))
        return NULL; /* Invalid encoding.  */
      len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
      if (!len)
        return NULL;
      buffer = g_malloc0 (len);
      len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buffer, len);
      if (!len)
        return NULL;
      len = strlen (buffer);
      /* Strip a trailing linefeed.  */
      if (len && buffer[len - 1] == '\n')
        buffer[--len] = 0;
      gcry_sexp_release (sexp);
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = buffer;
      retc->size = len;
    }
  else
    {
      /* RFC-2822 style mailboxes or RFC-2253 strings are returned
         verbatim.  */
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = g_strdup (string);
      retc->size = strlen (retc->x.str_val);
    }

  return retc;
}

/**
 * @brief Query a certificate object.
 * @naslfn{cert_query}
 *
 * Takes a cert identifier as first unnamed argument and a command
 * string as second argument.  That command is used to select specific
 * information from the certificate.  For certain commands the named
 * argument @a idx is used as well.  Depending on this command the
 * return value may be a number, a string, or an array of strings.
 * Supported commands are:
 *
 * - @a serial The serial number of the certificate as a hex string.
 *
 * - @a issuer Returns the issuer.  The returned value is a string in
 *             rfc-2253 format.

 * - @a subject Returns the subject. The returned value is a string in
 *              rfc-2253 format.  To query the subjectAltName the
 *              named parameters @a idx with values starting at 1 can
 *              be used. In this case the format is either an rfc2253
 *              string as used above, an rfc2822 mailbox name
 *              indicated by the first character being a left angle
 *              bracket or an S-expression in advanced format for all
 *              other types of subjectAltnames which is indicated by
 *              an opening parentheses.
 *
 * - @a not-before The notBefore time as UTC value in ISO time format
 *                 (e.g. "20120930T143521").
 *
 * - @a not-after  The notAfter time as UTC value in ISO time format
 *                 (e.g. "20280929T143520").
 *
 * - @a all Return all available information in a human readable
 *          format.  Not yet implemented.
 *
 * - @a hostnames Return an array with all hostnames listed in the
 *   certificates, i.e. the CN part of the subject and all dns-name
 *   type subjectAltNames.
 *
 * - @a fpr-sha-256 The SHA-256 fingerprint of the certificate.  The
 *                  fingerprint is, as usual, computed over the entire
 *                  DER encode certificate.
 *
 * - @a fpr-sha-1   The SHA-1 fingerprint of the certificate.  The
 *                  fingerprint is, as usual, computed over the entire
 *                  DER encode certificate.
 *
 * - @a image       Return the entire certificate as binary data.
 *
 * - @a algorithm-name  Same as signature-algorithm-name. TODO: Remove it and
 *                      leave only signature-algorithm-name.
 *
 * - @a signature-algorithm-name  Return the algorithm name used to sign the
 *                                certificate. Get the OID of the digest
 *                                algorithm and translated to a name from a
 *                                list from Wireshark.
 *                                See epan/dissectors/packet-pkcs1.c
 *
 * - @a public-key-algorithm-name  Return the algorithm name of the public key.
 *
 * - @a modulus      Return the RSA public key's modulus found in the
 *                   structure of the given cert.
 *
 * - @a exponent    Return the RSA public key's exponent found in
 *                  the structure of the given cert.
 *
 * - @a key-size    Return the size to hold the parameters size in bits.
 *                  For RSA the bits returned is the modulus.
 *                  For DSA the bits returned are of the public exponent.
 *
 * @nasluparam
 *
 * - Object id of the certificate.
 *
 * - A string with the command to select what to return; see above.
 *
 * @naslnparam
 *
 * - @a idx Used by certain commands to select the n-th value of a set
 *    of values.  If not given 0 is assumed.
 *
 * @naslret A NASL type depending on the used command.  NULL is
 *          returned on error.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return none
 */
tree_cell *
nasl_cert_query (lex_ctxt *lexic)
{
  int object_id;
  object_desc_t obj;
  const char *command;
  int cmdidx;
  char *result;
  ksba_isotime_t isotime;
  ksba_sexp_t sexp;
  tree_cell *retc;

  object_id = get_int_var_by_num (lexic, 0, -1);
  if (object_id <= 0)
    {
      g_message ("Bad object id %d passed to cert_query", object_id);
      return NULL;
    }

  for (obj = object_list; obj; obj = obj->next)
    if (obj->object_id == object_id)
      break;
  if (!obj)
    {
      g_message ("Unused object id %d passed to cert_query", object_id);
      return NULL;
    }

  /* Check that the command is a string.  */
  command = get_str_var_by_num (lexic, 1);
  if (!command || get_var_type_by_num (lexic, 1) != VAR2_STRING)
    {
      g_message ("No proper command passed to cert_query");
      return NULL;
    }

  /* Get the index which defaults to 0.  */
  cmdidx = get_int_var_by_name (lexic, "idx", 0);

  /* Command dispatcher.  */
  retc = NULL;
  if (!strcmp (command, "serial"))
    {
      const unsigned char *s;
      char *endp;
      unsigned long n;

      sexp = ksba_cert_get_serial (obj->cert);
      s = sexp;
      if (!s || *s != '(')
        return NULL; /* Ooops.  */
      s++;
      n = strtoul ((const char *) s, &endp, 10);
      s = (const unsigned char *) endp;
      if (*s == ':')
        {
          s++;
          retc = make_hexstring (s, n);
        }
      ksba_free (sexp);
    }
  else if (!strcmp (command, "issuer"))
    {
      result = ksba_cert_get_issuer (obj->cert, cmdidx);
      if (!result)
        return NULL;

      retc = get_name (result);
      ksba_free (result);
    }
  else if (!strcmp (command, "subject"))
    {
      result = ksba_cert_get_subject (obj->cert, cmdidx);
      if (!result)
        return NULL;

      retc = get_name (result);
      ksba_free (result);
    }
  else if (!strcmp (command, "not-before"))
    {
      ksba_cert_get_validity (obj->cert, 0, isotime);
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = g_strdup (isotime);
      retc->size = strlen (isotime);
    }
  else if (!strcmp (command, "not-after"))
    {
      ksba_cert_get_validity (obj->cert, 1, isotime);
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = g_strdup (isotime);
      retc->size = strlen (isotime);
    }
  else if (!strcmp (command, "fpr-sha-256"))
    {
      retc = get_fingerprint (obj->cert, GCRY_MD_SHA256);
    }
  else if (!strcmp (command, "fpr-sha-1"))
    {
      retc = get_fingerprint (obj->cert, GCRY_MD_SHA1);
    }
  else if (!strcmp (command, "all"))
    {
      /* FIXME */
    }
  else if (!strcmp (command, "hostnames"))
    {
      retc = build_hostname_list (obj->cert);
    }
  else if (!strcmp (command, "image"))
    {
      const unsigned char *der;
      size_t derlen;

      der = ksba_cert_get_image (obj->cert, &derlen);
      if (der && derlen)
        {
          retc = alloc_typed_cell (CONST_DATA);
          retc->size = derlen;
          retc->x.str_val = g_malloc0 (derlen);
          memcpy (retc->x.str_val, der, derlen);
        }
    }
  else if (!strcmp (command, "algorithm-name")
           || !strcmp (command, "signature-algorithm-name"))
    {
      const char *digest = ksba_cert_get_digest_algo (obj->cert);
      if (digest)
        {
          const char *name = get_oid_name (digest);
          if (!name)
            name = digest;
          retc = alloc_typed_cell (CONST_STR);
          retc->x.str_val = g_strdup (name);
          retc->size = strlen (name);
        }
    }
  else if (!strcmp (command, "public-key-algorithm-name"))
    {
      gnutls_datum_t datum;
      gnutls_x509_crt_t cert = NULL;
      int algo;
      char *algo_name;

      datum.data =
        (void *) ksba_cert_get_image (obj->cert, (size_t *) &datum.size);
      if (!datum.data)
        return NULL;
      if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER)
          != GNUTLS_E_SUCCESS)
        return NULL;
      if ((algo = gnutls_x509_crt_get_pk_algorithm (cert, NULL)) < 0)
        {
          g_message ("%s: Error getting the public key algorithm name.",
                     __func__);
          return NULL;
        }
      algo_name = gnutls_pk_algorithm_get_name (algo)
                    ? g_strdup (gnutls_pk_algorithm_get_name (algo))
                    : g_strdup ("unknown");
      retc = alloc_typed_cell (CONST_DATA);
      retc->size = strlen (algo_name);
      retc->x.str_val = algo_name;
    }
  else if (!strcmp (command, "modulus"))
    {
      gnutls_datum_t datum, m, e;
      gnutls_x509_crt_t cert = NULL;

      datum.data =
        (void *) ksba_cert_get_image (obj->cert, (size_t *) &datum.size);
      if (!datum.data)
        return NULL;
      if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER)
          != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_get_pk_rsa_raw (cert, &m, &e) != GNUTLS_E_SUCCESS)
        return NULL;

      retc = alloc_typed_cell (CONST_DATA);
      retc->size = m.size;
      retc->x.str_val = g_malloc0 (m.size);
      memcpy (retc->x.str_val, m.data, m.size);

      gnutls_free (m.data);
      gnutls_free (e.data);
      gnutls_x509_crt_deinit (cert);
    }
  else if (!strcmp (command, "exponent"))
    {
      gnutls_datum_t datum, m, e;
      gnutls_x509_crt_t cert = NULL;

      datum.data =
        (void *) ksba_cert_get_image (obj->cert, (size_t *) &datum.size);
      if (!datum.data)
        return NULL;
      if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER)
          != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_get_pk_rsa_raw (cert, &m, &e) != GNUTLS_E_SUCCESS)
        return NULL;

      retc = alloc_typed_cell (CONST_DATA);
      retc->size = e.size;
      retc->x.str_val = g_malloc0 (e.size);
      memcpy (retc->x.str_val, e.data, e.size);

      gnutls_free (m.data);
      gnutls_free (e.data);
      gnutls_x509_crt_deinit (cert);
    }
  else if (!strcmp (command, "key-size"))
    {
      gnutls_datum_t datum;
      gnutls_x509_crt_t cert = NULL;
      unsigned int bits = 0;

      datum.data =
        (void *) ksba_cert_get_image (obj->cert, (size_t *) &datum.size);
      if (!datum.data)
        return NULL;
      if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS)
        return NULL;
      if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER)
          != GNUTLS_E_SUCCESS)
        return NULL;
      gnutls_x509_crt_get_pk_algorithm (cert, &bits);
      gnutls_x509_crt_deinit (cert);

      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = bits;
    }
  else
    {
      g_message ("Unknown command '%s' passed to cert_query", command);
    }

  return retc;
}

#endif /* HAVE_LIBKSBA */
