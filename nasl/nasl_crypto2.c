/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_crypto2.c
 * @brief This file contains all the crypto functionality needed by the SSH
 * protocol
 */

#include "nasl_crypto2.h"

#include "../misc/strutils.h"
#include "nasl_crypto_helper.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_misc_funcs.h"
#include "nasl_packet_forgery.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <arpa/inet.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gpg-error.h>
#include <gvm/base/logging.h>
#include <stddef.h>
#include <stdlib.h>

#define INTBLOB_LEN 20
#define SIGBLOB_LEN (2 * INTBLOB_LEN)
#define MAX_CIPHER_ID 32
#define NASL_ENCRYPT 0
#define NASL_DECRYPT 1
#define NASL_AAD 2

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/**
 * @brief List of open cipher handler.
 */
static GList *cipher_table = NULL;

/**
 * @brief Struct holding a cipher handler.
 */
struct cipher_table_item
{
  gcry_cipher_hd_t hd;
  int id;
};

/* Type definitions */
typedef struct cipher_table_item cipher_table_item_t;

/**
 * @brief Prints a GnuTLS error.
 *
 * The parameter err should be the GnuTLS error code
 */
static void
print_tls_error (lex_ctxt *lexic, char *txt, int err)
{
  nasl_perror (lexic, "%s: %s (%d)\n", txt, gnutls_strerror (err), err);
}

/**
 * @brief Prints a libgcrypt error.
 *
 * The parameter err should be the libgcrypt error code
 */
static void
print_gcrypt_error (lex_ctxt *lexic, char *function, int err)
{
  nasl_perror (lexic, "%s failed: %s/%s\n", function, gcry_strsource (err),
               gcry_strerror (err));
}

/**
 * @brief Helper function to find cipher id in the table
 *
 * @return 0 if the cipher id exits/is in used. -1 otherwise.
 */
static int
find_cipher_hd (cipher_table_item_t *cipher_elem, int *id)
{
  if (cipher_elem->id == *id)
    return 0;

  return -1;
}

/**
 * @brief Helper function to get a free id for a new cipher.
 *
 * @return Id for the new cipher.
 */
static int
get_new_cipher_id (void)
{
  int cipher_id;

  for (cipher_id = 0; cipher_id < MAX_CIPHER_ID; cipher_id++)
    {
      if (g_list_find_custom (cipher_table, &cipher_id,
                              (GCompareFunc) find_cipher_hd)
          == NULL)
        return cipher_id;
    }

  return -1;
}

/**
 * @brief Helper function to validate the cipher id.
 *
 * @param[in] cipher_id The cipher ID to validate.
 * @return Handler on success, Null on error.
 */
static gcry_cipher_hd_t
verify_cipher_id (lex_ctxt *lexic, int cipher_id)
{
  cipher_table_item_t *hd;
  GList *hd_aux;

  hd_aux = g_list_find_custom (cipher_table, &cipher_id,
                               (GCompareFunc) find_cipher_hd);
  if (!hd_aux)
    {
      nasl_perror (lexic, "Cipher handle %d not found.\n", cipher_id);
      return NULL;
    }
  hd = (cipher_table_item_t *) hd_aux->data;

  return hd->hd;
}

/**
 * @brief Create a new cipher handler item parameter.
 *
 * @return New cipher handler item.
 */
static cipher_table_item_t *
cipher_table_item_new (void)
{
  return g_malloc0 (sizeof (cipher_table_item_t));
}

/**
 * @brief Free and remove a cipher handler from the cipher table.
 *
 * @param[in] cipher_id ID of the cipher handler to free and remove.
 * @return 0 on success, -1 on error.
 */
static void
delete_cipher_item (int cipher_id)
{
  GList *hd_item;
  cipher_table_item_t *hd;

  hd_item = g_list_find_custom (cipher_table, &cipher_id,
                                (GCompareFunc) find_cipher_hd);
  hd = (cipher_table_item_t *) hd_item->data;
  gcry_cipher_close ((gcry_cipher_hd_t) hd->hd);
  cipher_table = g_list_remove (cipher_table, hd_item->data);
  g_free (hd_item->data);
}

/**
 * @brief Converts a string to a gcry_mpi_t.
 *
 * The string of len bytes at data
 * should contain the MPI as an unsigned int in bigendian form
 * (libgcrypt's GCRYMPI_FMT_USG).  The new MPI object is stored in dest.
 * The parameters function and parameter are used in error messages to
 * indicate the nasl function and nasl parameter name of the MPI.  The
 * lexic parameter is passed through to the error reporting functions.
 *
 * The function return 0 on success and -1 on failure.
 */
static int
mpi_from_string (lex_ctxt *lexic, gcry_mpi_t *dest, void *data, size_t len,
                 const char *parameter, const char *function)
{
  gcry_error_t err;
  unsigned char *buffer = data;

  err = gcry_mpi_scan (dest, GCRYMPI_FMT_USG, buffer, len, NULL);
  if (err)
    {
      nasl_perror (lexic, "%s(): gcry_mpi_scan failed for %s: %s/%s\n",
                   function, parameter, gcry_strsource (err),
                   gcry_strerror (err));
      return -1;
    }

  return 0;
}

/**
 * @brief Converts a named nasl parameter to a gcry_mpi_t.
 *
 * The new MPI object
 * is stored in dest.  The parameter parameter is the name of the
 * parameter to be taken from lexic.  The parameter function is used in
 * error messages to indicate the name of the nasl function.
 *
 * @return 0 on success and -1 on failure.
 */
static int
mpi_from_named_parameter (lex_ctxt *lexic, gcry_mpi_t *dest,
                          const char *parameter, const char *function)
{
  long size;
  char *s;

  s = get_str_var_by_name (lexic, parameter);
  size = get_var_size_by_name (lexic, parameter);

  if (!s)
    return -1;

  return mpi_from_string (lexic, dest, s, size, parameter, function);
}

/**
 * @brief Sets the return value in retc from the MPI mpi.
 *
 * The MPI is converted to a byte string as an unsigned int in bigendian form
 * (libgcrypts GCRYMPI_FMT_USG format).
 *
 * In an earlier implementation of this function, if first byte in the string
 * had it's most significant bit set, i.e. if it would be considered negative
 * when interpreted as two's-complement representation, a null-byte was
 * prepended to make sure the number is always considered positive.
 *
 * However, this behavior caused problems during certain SSH operations because
 * the buffer returned by this function would be one byte larger than expected.
 * For now, the str_val of retc will always have the content and size returned
 * by gcry_mpi_aprint ().
 *
 * @return 0 on success and -1 on failure.
 */
static int
set_mpi_retc (tree_cell *retc, gcry_mpi_t mpi)
{
  unsigned char *buffer = NULL;
  size_t size;

  gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &size, mpi);
  if (!buffer)
    return -1;

  retc->x.str_val = g_malloc0 (size);
  memcpy (retc->x.str_val, buffer, size);
  retc->size = size;

  gcry_free (buffer);

  return 0;
}

/**
 * nasl function
 *
 *   bn_cmp(key1:MPI1, key2:MPI2)
 *
 * Compares the MPIs key1 and key2 (given as binary strings).  Returns
 * -1 if key1 < key2, 0 if key1 == key2 and +1 if key1 > key2.
 */
tree_cell *
nasl_bn_cmp (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t key1 = NULL, key2 = NULL;

  retc = g_malloc0 (sizeof (tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_INT;
  retc->x.i_val = 1;

  if (mpi_from_named_parameter (lexic, &key1, "key1", "nasl_bn_cmp") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &key2, "key2", "nasl_bn_cmp") < 0)
    goto fail;

  retc->x.i_val = gcry_mpi_cmp (key1, key2);

  /* make sure the return value is one of -1, 0, +1 */
  if (retc->x.i_val > 0)
    retc->x.i_val = 1;
  if (retc->x.i_val < 0)
    retc->x.i_val = -1;

fail:
  gcry_mpi_release (key1);
  gcry_mpi_release (key2);
  return retc;
}

/**
 * nasl function
 *
 *   bn_random(need:numBits)
 *
 * @return An MPI as a string with need bits of random data.
 */
tree_cell *
nasl_bn_random (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t key = NULL;
  long need;

  retc = alloc_typed_cell (CONST_DATA);

  /* number of random bits */
  need = get_int_var_by_name (lexic, "need", 0);

  key = gcry_mpi_new (0);
  if (!key)
    goto fail;

  gcry_mpi_randomize (key, need, GCRY_STRONG_RANDOM);

  if (set_mpi_retc (retc, key) >= 0)
    goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_mpi_release (key);
  return retc;
}

/**
 * @brief Loads a private key from a string.
 *
 * The string is taken from the nasl
 * parameter whose name is given by priv_name.  The passphrase_name is
 * the name of the parameter holding the passphrase if any.  The string
 * with the key must be in PEM format.
 *
 * @return The GnuTLS private key object on success, NULL on failure.
 */
static gnutls_x509_privkey_t
nasl_load_privkey_param (lex_ctxt *lexic, const char *priv_name,
                         const char *passphrase_name)
{
  char *priv = NULL, *passphrase = NULL;
  long privlen;
  gnutls_x509_privkey_t privkey = NULL;
  gnutls_datum_t pem;
  int err;

  /* PEM encoded privkey */
  priv = get_str_var_by_name (lexic, priv_name);
  privlen = get_var_size_by_name (lexic, priv_name);

  /* passphrase */
  passphrase = get_str_var_by_name (lexic, passphrase_name);
  pem.data = (unsigned char *) priv;
  pem.size = privlen;

  err = gnutls_x509_privkey_init (&privkey);
  if (err)
    {
      print_tls_error (lexic, "gnutls_x509_privkey_init", err);
      goto fail;
    }

  if (passphrase && !*passphrase)
    passphrase = NULL;
  err =
    gnutls_x509_privkey_import2 (privkey, &pem, GNUTLS_X509_FMT_PEM, passphrase,
                                 passphrase ? 0 : GNUTLS_PKCS_PLAIN);
  if (err)
    {
      print_tls_error (lexic, "gnutls_x509_privkey_import_pkcs8", err);
      goto fail;
    }
  return privkey;

fail:
  gnutls_x509_privkey_deinit (privkey);
  return NULL;
}

/**
 * @brief Implements the nasl functions pem_to_rsa and pem_to_dsa.
 */
static tree_cell *
nasl_pem_to (lex_ctxt *lexic, int type)
{
  tree_cell *retc = NULL;
  gnutls_x509_privkey_t privkey = NULL;
  gcry_mpi_t key = NULL;
  int err;

  retc = alloc_typed_cell (CONST_DATA);

  privkey = nasl_load_privkey_param (lexic, "priv", "passphrase");
  if (!privkey)
    goto fail;

  if (!type)
    {
      gnutls_datum_t m, e, d, p, q, u;
      err =
        gnutls_x509_privkey_export_rsa_raw (privkey, &m, &e, &d, &p, &q, &u);
      if (err)
        {
          print_tls_error (lexic, "gnutls_x509_privkey_export_rsa_raw", err);
          goto fail;
        }

      err =
        mpi_from_string (lexic, &key, d.data, d.size, "rsa d", "nasl_pem_to");
      gnutls_free (m.data);
      gnutls_free (e.data);
      gnutls_free (d.data);
      gnutls_free (p.data);
      gnutls_free (q.data);
      gnutls_free (u.data);

      if (err < 0)
        goto fail;
    }
  else
    {
      gnutls_datum_t p, q, g, y, x;
      err = gnutls_x509_privkey_export_dsa_raw (privkey, &p, &q, &g, &y, &x);
      if (err)
        {
          print_tls_error (lexic, "gnutls_x509_privkey_export_dsa_raw", err);
          goto fail;
        }

      err =
        mpi_from_string (lexic, &key, x.data, x.size, "dsa x", "nasl_pem_to");

      gnutls_free (p.data);
      gnutls_free (q.data);
      gnutls_free (g.data);
      gnutls_free (y.data);
      gnutls_free (x.data);

      if (err < 0)
        goto fail;
    }

  if (set_mpi_retc (retc, key) >= 0)
    goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_mpi_release (key);
  gnutls_x509_privkey_deinit (privkey);
  return retc;
}

/**
 * nasl function
 *
 *   pem_to_rsa(priv:PEM, passphrase:PASSPHRASE)
 *
 * Reads the private key from the string priv which contains a private
 * RSA key in PEM format.  Passphrase is the passphrase needed to
 * decrypt the private key.  The function returns the parameter "d" of
 * the RSA key as an MPI.
 */
tree_cell *
nasl_pem_to_rsa (lex_ctxt *lexic)
{
  return nasl_pem_to (lexic, 0);
}

/**
 * nasl function
 *
 *   pem_to_dsa(priv:PEM, passphrase:PASSPHRASE)
 *
 * Reads the private key from the string priv which contains a private
 * DSA key in PEM format.  Passphrase is the passphrase needed to
 * decrypt the private key.  The function returns the parameter "x" of
 * the DSA key as an MPI.
 */
tree_cell *
nasl_pem_to_dsa (lex_ctxt *lexic)
{
  return nasl_pem_to (lexic, 1);
}

/**
 * @brief compute the diffie hellman public key.
 *
 * Neither GnuTLS nor Libgcrypt
 * contain a direct counterpart to OpenSSL's DH_generate_key, so we
 * implement it ourselves.  This function was copied from from gnutls
 * and adapted to use gcrypt directly and to use a private key given as
 * parameter to the function.
 *
 * @return The key on success and NULL on failure.
 */
static gcry_mpi_t
calc_dh_public (gcry_mpi_t g, gcry_mpi_t prime, gcry_mpi_t priv)
{
  gcry_mpi_t e;

  e = gcry_mpi_new (gcry_mpi_get_nbits (prime));
  if (e == NULL)
    {
      return NULL;
    }

  gcry_mpi_powm (e, g, priv, prime);

  return e;
}

/**
 * @brief Compute the diffie hellman shared secret key.
 *
 * Neither GnuTLS nor
 * libgcrypt contain a direct counterpart to OpenSSL's DH_compute_key,
 * so we implement it ourselves.  This function was copied from from
 * gnutls and adapted to use gcrypt directly and to use a private key
 * given as parameter to the function.
 *
 * @return The key on success and NULL on failure.
 */
static gcry_mpi_t
calc_dh_key (gcry_mpi_t pub, gcry_mpi_t prime, gcry_mpi_t priv)
{
  gcry_mpi_t e;

  e = gcry_mpi_new (gcry_mpi_get_nbits (prime));
  if (e == NULL)
    {
      return NULL;
    }

  gcry_mpi_powm (e, pub, priv, prime);

  return e;
}

/**
 * nasl function
 *
 *    dh_generate_key(p:mpi_p, g:mpi_g, priv:mpi_priv)
 *
 * Generates a Diffie-Hellman public key from the shared parameters p
 * and g and the private parameter priv.  The return value is the public
 * key as an MPI.
 */
tree_cell *
nasl_dh_generate_key (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t p = NULL, g = NULL, priv = NULL, pub_mpi = NULL;

  retc = alloc_typed_cell (CONST_DATA);

  if (mpi_from_named_parameter (lexic, &p, "p", "nasl_dh_generate_key") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &g, "g", "nasl_dh_generate_key") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &priv, "priv", "nasl_dh_generate_key")
      < 0)
    goto fail;

  pub_mpi = calc_dh_public (g, p, priv);
  if (pub_mpi == NULL)
    goto fail;

  if (set_mpi_retc (retc, pub_mpi) >= 0)
    goto ret;

fail:
  retc->x.str_val = g_malloc0 (1);
  retc->size = 0;
ret:
  gcry_mpi_release (p);
  gcry_mpi_release (g);
  gcry_mpi_release (priv);
  gcry_mpi_release (pub_mpi);
  return retc;
}

/**
 * nasl function
 *
 *    dh_compute_key(p:mpi_p, g:mpi_g, dh_server_pub:mpi_server_pub,
 *                   pub_key:mpi_client_pub, priv_key:mpi_client_priv)
 *
 * Computes the Diffie-Hellman shared secret key from the shared
 * parameters p and g, the server's public key dh_server_pub and the
 * client's public and private keys pub_key an priv_key.  The return
 * value is the shared secret key as an MPI.
 */
tree_cell *
nasl_dh_compute_key (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t p = NULL, g = NULL, dh_server_pub = NULL;
  gcry_mpi_t pub_key = NULL, priv_key = NULL;
  gcry_mpi_t shared = NULL;

  retc = alloc_typed_cell (CONST_DATA);

  if (mpi_from_named_parameter (lexic, &p, "p", "nasl_dh_compute_key") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &g, "g", "nasl_dh_compute_key") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &dh_server_pub, "dh_server_pub",
                                "nasl_dh_compute_key")
      < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &pub_key, "pub_key",
                                "nasl_dh_compute_key")
      < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &priv_key, "priv_key",
                                "nasl_dh_compute_key")
      < 0)
    goto fail;

  shared = calc_dh_key (dh_server_pub, p, priv_key);

  if (set_mpi_retc (retc, shared) >= 0)
    goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_mpi_release (p);
  gcry_mpi_release (g);
  gcry_mpi_release (dh_server_pub);
  gcry_mpi_release (priv_key);
  gcry_mpi_release (pub_key);
  gcry_mpi_release (shared);
  return retc;
}

/**
 * @brief Extracts an MPI value from a libgcryt s-expression.
 *
 * The return value
 * is the cadr of the subexpression whose car is given by token.  The
 * function returns NULL if the token doesn't occur in the expression or
 * on other errors.
 */
static gcry_mpi_t
extract_mpi_from_sexp (gcry_sexp_t sexp, const char *token)
{
  gcry_sexp_t child = NULL;
  gcry_mpi_t mpi = NULL;

  child = gcry_sexp_find_token (sexp, token, strlen (token));
  if (!child)
    {
      g_message ("set_retc_from_sexp: no subexpression with token <%s>", token);
    }
  else
    {
      mpi = gcry_sexp_nth_mpi (child, 1, GCRYMPI_FMT_USG);
    }

  gcry_sexp_release (child);

  return mpi;
}

/**
 * @brief Sets the return value in retc from an sexpression.
 *
 * The function uses
 * extract_mpi_from_sexp to extract an MPI from the sexpression sexp and
 * the subexpression given by token.
 * The function return 1 on success
 * and 0 on failure.
 */
static int
set_retc_from_sexp (tree_cell *retc, gcry_sexp_t sexp, const char *token)
{
  int ret = 0;
  gcry_mpi_t mpi = extract_mpi_from_sexp (sexp, token);
  if (mpi)
    {
      ret = set_mpi_retc (retc, mpi);

      gcry_mpi_release (mpi);
    }

  return ret;
}

/**
 * @brief Strips PKCS#1 padding from the string in retc.
 */
static int
strip_pkcs1_padding (tree_cell *retc)
{
  char *p;

  if (retc->x.str_val == NULL || retc->size < 1)
    return -1;

  /* Find type of padding. PKCS#1 padding normally starts with a 0 byte.
   * However, due to the way the value in retc has been created, any
   * leading zeros have already been stripped.  So the byte that
   * describes the type of padding is the first byte in str_val.  Also,
   * the only padding types we can actually find are 1 and 2.  padding
   * type 0 means that the padding is done with zeros and those will
   * have been already stripped too. */
  p = retc->x.str_val;
  if (p[0] == 1 || p[0] == 2)
    {
      /* for padding type 1 and 2 we simply have to strip all non-zero
       * bytes at the beginning of the value */
      int i = 0;
      char *temp;
      while (i < retc->size && p[i])
        i++;
      /* skip the zero byte */
      i++;
      if (i <= retc->size)
        {
          int rest = retc->size - i;
          temp = g_malloc0 (rest);
          memcpy (temp, p + i, rest);
          g_free (retc->x.str_val);
          retc->x.str_val = temp;
          retc->size = rest;
        }
      else
        return -1;
    }

  return 0;
}

/**
 * nasl function
 *
 *  rsa_public_encrypt(data:data, e:mpi_e, n:mpi_n, pad:<TRUE:FALSE>)
 *
 * Encrypt the provided data  with the public RSA key given by its parameters e
 * and n. The return value is the encrypted data.
 */
tree_cell *
nasl_rsa_public_encrypt (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t e = NULL, n = NULL, dt = NULL;
  gcry_sexp_t key = NULL, data = NULL, encrypted = NULL;
  gcry_error_t err;
  int type = get_var_type_by_name (lexic, "pad");
  int pad = 0;

  if (type == VAR2_INT)
    pad = get_int_var_by_name (lexic, "pad", 0);
  /** TODO: In future releases, string support for padding should be removed */
  else if (type == VAR2_STRING)
    {
      if (!strcmp (get_str_var_by_name (lexic, "pad"), "TRUE"))
        pad = 1;
    }
  else
    {
      nasl_perror (lexic, "Syntax : rsa_public_encrypt(data:<d>,"
                          "n:<n>, e:<e>, pad:<TRUE:FALSE>)");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);

  if (mpi_from_named_parameter (lexic, &dt, "data", "nasl_rsa_public_encrypt")
      < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &e, "e", "nasl_rsa_public_encrypt") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &n, "n", "nasl_rsa_public_encrypt") < 0)
    goto fail;

  err = gcry_sexp_build (&key, NULL, "(public-key (rsa (n %m) (e %m)))", n, e);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build pubkey", err);
      goto fail;
    }

  if (pad == 1)
    err = gcry_sexp_build (&data, NULL, "(data (flags pkcs1) (value %m))", dt);
  else
    err = gcry_sexp_build (&data, NULL, "(data (flags raw) (value %m))", dt);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build data", err);
      goto fail;
    }

  err = gcry_pk_encrypt (&encrypted, data, key);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_pk_encrypt", err);
      goto fail;
    }

  if (pad == 1)
    {
      if (set_retc_from_sexp (retc, encrypted, "a") >= 0
          && strip_pkcs1_padding (retc) >= 0)
        goto ret;
    }
  else
    {
      if (set_retc_from_sexp (retc, encrypted, "a") >= 0)
        goto ret;
    }

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_sexp_release (encrypted);
  gcry_sexp_release (key);
  gcry_sexp_release (data);
  gcry_mpi_release (dt);
  gcry_mpi_release (e);
  gcry_mpi_release (n);
  return retc;
}

/**
 * nasl function
 *
 *  rsa_private_decrypt(data:data, d:mpi_d, e:mpi_e, n:mpi_n, pad:<TRUE:FALSE>)
 *
 * Decrypt the provided data with the private RSA key given by its parameters
 * d, e and n. The return value is the decrypted data in plaintext format.
 */
tree_cell *
nasl_rsa_private_decrypt (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t e = NULL, n = NULL, d = NULL, dt = NULL;
  gcry_sexp_t key = NULL, data = NULL, decrypted = NULL;
  gcry_error_t err;
  int type = get_var_type_by_name (lexic, "pad");
  int pad = 0;

  if (type == VAR2_INT)
    pad = get_int_var_by_name (lexic, "pad", 0);
  /** TODO: In future releases, string support for padding should be removed */
  else if (type == VAR2_STRING)
    {
      if (!strcmp (get_str_var_by_name (lexic, "pad"), "TRUE"))
        pad = 1;
    }
  else
    {
      nasl_perror (lexic, "Syntax : rsa_public_encrypt(data:<d>,"
                          "n:<n>, e:<e>, pad:<TRUE:FALSE>)");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);

  if (mpi_from_named_parameter (lexic, &dt, "data", "nasl_rsa_private_decrypt")
      < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &e, "e", "nasl_rsa_private_decrypt") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &n, "n", "nasl_rsa_private_decrypt") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &d, "d", "nasl_rsa_private_decrypt") < 0)
    goto fail;

  err = gcry_sexp_build (&key, NULL, "(private-key (rsa (n %m) (e %m) (d %m)))",
                         n, e, d);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build privkey", err);
      goto fail;
    }

  if (pad == 1)
    err =
      gcry_sexp_build (&data, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))", dt);
  else
    err =
      gcry_sexp_build (&data, NULL, "(enc-val (flags raw) (rsa (a %m)))", dt);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build data", err);
      goto fail;
    }

  err = gcry_pk_decrypt (&decrypted, data, key);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_pk_decrypt", err);
      goto fail;
    }

  if (pad == 1)
    {
      if (set_retc_from_sexp (retc, decrypted, "value") >= 0
          && strip_pkcs1_padding (retc) >= 0)
        goto ret;
    }
  else
    {
      if (set_retc_from_sexp (retc, decrypted, "value") >= 0)
        goto ret;
    }

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_sexp_release (decrypted);
  gcry_sexp_release (key);
  gcry_sexp_release (data);
  gcry_mpi_release (dt);
  gcry_mpi_release (e);
  gcry_mpi_release (n);
  gcry_mpi_release (d);
  return retc;
}

/**
 * nasl function
 *
 *   rsa_public_decrypt(sig:signature, e:mpi_e, n:mpi_n)
 *
 * Decrypt the data in signature (usually an rsa-encrypted hash) with
 * the public RSA key given by its parameters e and n.  The return value
 * is the decrypted data.
 */
tree_cell *
nasl_rsa_public_decrypt (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t e = NULL, n = NULL, s = NULL;
  gcry_sexp_t key = NULL, sig = NULL, decrypted = NULL;
  gcry_error_t err;

  retc = alloc_typed_cell (CONST_DATA);

  if (mpi_from_named_parameter (lexic, &s, "sig", "nasl_rsa_public_decrypt")
      < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &e, "e", "nasl_rsa_public_decrypt") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &n, "n", "nasl_rsa_public_decrypt") < 0)
    goto fail;

  err = gcry_sexp_build (&key, NULL, "(public-key (rsa (n %m) (e %m)))", n, e);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build pubkey", err);
      goto fail;
    }
  err = gcry_sexp_build (&sig, NULL, "(data (flags raw) (value %m))", s);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build sig", err);
      goto fail;
    }

  /* gcry_pk_encrypt is equivalent to the public key decryption at least
   * for RSA keys. */
  err = gcry_pk_encrypt (&decrypted, sig, key);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_pk_encrypt", err);
      goto fail;
    }

  if (set_retc_from_sexp (retc, decrypted, "a") >= 0
      && strip_pkcs1_padding (retc) >= 0)
    goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_sexp_release (decrypted);
  gcry_sexp_release (key);
  gcry_sexp_release (sig);
  gcry_mpi_release (s);
  gcry_mpi_release (e);
  gcry_mpi_release (n);
  return retc;
}

/**
 * @brief Creates a libgcryt s-expression from a GnuTLS private RSA key.
 */
#define NUM_RSA_PARAMS 6
static gcry_sexp_t
nasl_sexp_from_privkey (lex_ctxt *lexic, gnutls_x509_privkey_t privkey)
{
  gnutls_datum_t datums[NUM_RSA_PARAMS]; /* m/n, e, d, p, q, u */
  gcry_mpi_t mpis[NUM_RSA_PARAMS];       /* m/n, e, d, p, q, u */
  gcry_sexp_t key = NULL;
  int err;
  gcry_error_t gerr;
  int i;

  for (i = 0; i < NUM_RSA_PARAMS; i++)
    {
      datums[i].data = NULL;
      mpis[i] = NULL;
    }

  err = gnutls_x509_privkey_export_rsa_raw (privkey, datums + 0, datums + 1,
                                            datums + 2, datums + 3, datums + 4,
                                            datums + 5);
  if (err)
    {
      print_tls_error (lexic, "gnutls_x509_privkey_export_rsa_raw", err);
      goto fail;
    }

  for (i = 0; i < NUM_RSA_PARAMS; i++)
    {
      err = mpi_from_string (lexic, mpis + i, datums[i].data, datums[i].size,
                             "rsa parameter", "nasl_sexp_from_privkey");
      if (err < 0)
        goto fail;
    }

  /* make sure that p < q. libgcrypt requires this. */
  if (gcry_mpi_cmp (mpis[3], mpis[4]) > 0)
    {
      gcry_mpi_swap (mpis[3], mpis[4]);
      gcry_mpi_invm (mpis[5], mpis[3], mpis[4]);
    }

  gerr = gcry_sexp_build (&key, NULL,
                          "(private-key (rsa (n %m) (e %m) (d %m)"
                          " (p %m) (q %m) (u %m)))",
                          mpis[0], mpis[1], mpis[2], mpis[3], mpis[4], mpis[5]);
  if (gerr)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build", gerr);
      goto fail;
    }

fail:
  for (i = 0; i < NUM_RSA_PARAMS; i++)
    {
      gnutls_free (datums[i].data);
      gcry_mpi_release (mpis[i]);
    }

  return key;
}

/**
 * nasl function
 *
 *   rsa_sign(data:hash, priv:pem, passphrase:passphrase)
 *
 * Signs the data with the private RSA key priv given in PEM format.
 * The passphrase is the passphrase needed to decrypt the private key.
 * Returns the signed data.
 *
 * In the OpenSSL based nasl, the key was not given in PEM form and with
 * a passphrase.  Instead it was given as the RSA parameters e, n and d.
 * libgcrypt always requires all the parameters (including p, g, and u),
 * so this function was changed to simply accept the full private key in
 * PEM form.  The one place where it was called had that the key
 * available in that form.
 */
tree_cell *
nasl_rsa_sign (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  char *data;
  int data_size;
  gcry_sexp_t ssig = NULL, sdata = NULL, skey = NULL;
  gnutls_x509_privkey_t priv_key = NULL;
  gcry_error_t err;

  retc = alloc_typed_cell (CONST_DATA);

  data = get_str_var_by_name (lexic, "data");
  data_size = get_var_size_by_name (lexic, "data");
  if (!data)
    goto fail;

  priv_key = nasl_load_privkey_param (lexic, "priv", "passphrase");
  if (!priv_key)
    goto fail;

  err = gcry_sexp_build (&sdata, NULL, "(data (flags pkcs1) (hash sha1 %b))",
                         data_size, data);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for data", err);
      goto fail;
    }

  skey = nasl_sexp_from_privkey (lexic, priv_key);
  if (!skey)
    goto fail;

  err = gcry_pk_sign (&ssig, sdata, skey);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_pk_sign", err);
      goto fail;
    }

  if (set_retc_from_sexp (retc, ssig, "s") >= 0)
    goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = g_malloc0 (1);
ret:
  gcry_sexp_release (ssig);
  gcry_sexp_release (sdata);
  gcry_sexp_release (skey);
  gnutls_x509_privkey_deinit (priv_key);
  return retc;
}

/**
 * nasl function
 *
 *   dsa_do_verify(p:mpi_p, g:mpi_g, q:mpi_q, pub:mpi_pub,
 *                 r:mpi_r, s:mpi_s, data:hash)
 *
 * Verify that the DSA signature given by r and s matches the hash given
 * in data using the public DSA key given by p, g, q and pub.  Returns 1
 * if the signature is valid and 0 if it's invalid.
 */
tree_cell *
nasl_dsa_do_verify (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t p = NULL, g = NULL, q = NULL, pub = NULL, data = NULL;
  gcry_mpi_t r = NULL, s = NULL;
  gcry_sexp_t ssig = NULL, skey = NULL, sdata = NULL;
  gcry_error_t err;

  retc = g_malloc0 (sizeof (tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_INT;
  retc->x.i_val = 0;

  if (mpi_from_named_parameter (lexic, &p, "p", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &g, "g", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &q, "q", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &pub, "pub", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &r, "r", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &s, "s", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &data, "data", "nasl_dsa_do_sign") < 0)
    goto fail;

  err = gcry_sexp_build (&sdata, NULL, "(data (flags raw) (value %m))", data);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for data", err);
      goto fail;
    }

  err = gcry_sexp_build (&skey, NULL,
                         "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))", p, q,
                         g, pub);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for private key", err);
      goto fail;
    }

  err = gcry_sexp_build (&ssig, NULL, "(sig-val (dsa (r %m) (s %m)))", r, s);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for signature", err);
      goto fail;
    }

  err = gcry_pk_verify (ssig, sdata, skey);
  if (err == 0)
    retc->x.i_val = 1;
  else if (gcry_err_code (err) == GPG_ERR_BAD_SIGNATURE)
    retc->x.i_val = 0;
  else
    {
      print_gcrypt_error (lexic, "gcry_pk_sign", err);
      goto fail;
    }

fail:
  gcry_mpi_release (p);
  gcry_mpi_release (g);
  gcry_mpi_release (q);
  gcry_mpi_release (pub);
  gcry_mpi_release (r);
  gcry_mpi_release (s);
  gcry_mpi_release (data);
  gcry_sexp_release (ssig);
  gcry_sexp_release (skey);
  gcry_sexp_release (sdata);

  return retc;
}

/**
 * nasl function
 *
 *   dsa_do_sign(p:mpi_p, g:mpi_g, q:mpi_q, pub:mpi_pub, priv:mpi_priv,
 *               data:hash)
 *
 * Computes the DSA signature of the hash in data using the private DSA
 * key given by p, g, q, pub and priv.  The return value is a 40 byte
 * string encoding the two MPIs r and s of the DSA signature.  The first
 * 20 bytes are the value of r and the last 20 bytes are the value of s.
 */
tree_cell *
nasl_dsa_do_sign (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  gcry_mpi_t p = NULL, g = NULL, q = NULL, pub = NULL, priv = NULL, data = NULL;
  gcry_mpi_t r = NULL, s = NULL;
  gcry_sexp_t ssig = NULL, skey = NULL, sdata = NULL;
  long rlen, slen;
  unsigned char *sigblob = NULL;
  gcry_error_t err;

  retc = g_malloc0 (sizeof (tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_DATA;
  retc->x.i_val = 0;

  if (mpi_from_named_parameter (lexic, &p, "p", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &g, "g", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &q, "q", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &pub, "pub", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &priv, "priv", "nasl_dsa_do_sign") < 0)
    goto fail;
  if (mpi_from_named_parameter (lexic, &data, "data", "nasl_dsa_do_sign") < 0)
    goto fail;

  err = gcry_sexp_build (&sdata, NULL, "(data (flags raw) (value %m))", data);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for data", err);
      goto fail;
    }

  err = gcry_sexp_build (
    &skey, NULL, "(private-key (dsa (p %m) (q %m) (g %m) (y %m) (x %m)))", p, q,
    g, pub, priv);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_sexp_build for private-key", err);
      goto fail;
    }

  err = gcry_pk_sign (&ssig, sdata, skey);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_pk_sign", err);
      goto fail;
    }

  r = extract_mpi_from_sexp (ssig, "r");
  s = extract_mpi_from_sexp (ssig, "s");
  if (!r || !s)
    goto fail;

  rlen = (gcry_mpi_get_nbits (r) + 7) / 8;
  slen = (gcry_mpi_get_nbits (s) + 7) / 8;
  if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN)
    {
      nasl_perror (lexic, "rlen (%d) or slen (%d) > INTBLOB_LEN (%d)\n", rlen,
                   slen, INTBLOB_LEN);
      goto fail;
    }

  sigblob = g_malloc0 (SIGBLOB_LEN);
  memset (sigblob, 0, SIGBLOB_LEN);

  err = gcry_mpi_print (
    GCRYMPI_FMT_USG,
    (unsigned char *) (sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen), rlen, NULL,
    r);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_mpi_print(r)", err);
      goto fail;
    }
  err = gcry_mpi_print (GCRYMPI_FMT_USG,
                        (unsigned char *) (sigblob + SIGBLOB_LEN - slen), rlen,
                        NULL, s);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_mpi_print(s)", err);
      goto fail;
    }

  retc->x.str_val = (char *) sigblob;
  sigblob = NULL;
  retc->size = SIGBLOB_LEN;

fail:
  gcry_mpi_release (p);
  gcry_mpi_release (g);
  gcry_mpi_release (q);
  gcry_mpi_release (pub);
  gcry_mpi_release (priv);
  gcry_mpi_release (data);
  gcry_mpi_release (r);
  gcry_mpi_release (s);
  gcry_sexp_release (ssig);
  gcry_sexp_release (skey);
  gcry_sexp_release (sdata);
  g_free (sigblob);

  return retc;
}

/**
 * @brief Implements the nasl functions bf_cbc_encrypt and bf_cbc_decrypt.
 */
static tree_cell *
nasl_bf_cbc (lex_ctxt *lexic, int enc)
{
  tree_cell *retc = NULL;
  char *enckey = NULL, *iv = NULL, *data = NULL, *out = NULL;
  long enckeylen, ivlen, datalen;
  gcry_cipher_hd_t hd = NULL;
  anon_nasl_var v;
  nasl_array *a;
  gcry_error_t err;

  retc = alloc_typed_cell (CONST_DATA);

  /* key */
  enckey = get_str_var_by_name (lexic, "key");
  enckeylen = get_var_size_by_name (lexic, "key");

  /* initialization vector */
  iv = get_str_var_by_name (lexic, "iv");
  ivlen = get_var_size_by_name (lexic, "iv");

  /* data to decrypt/encrypt */
  data = get_str_var_by_name (lexic, "data");
  datalen = get_var_size_by_name (lexic, "data");

  if (enckey == NULL || data == NULL || iv == NULL)
    goto fail;
  if (enckeylen < 16)
    {
      /* key length must be at least 16 for compatibility with libnasl
       * code from before the OpenSSL -> GnuTLS migration */
      nasl_perror (lexic,
                   "nasl_bf_cbc: unexpected enckeylen = %d; must be >= 16\n",
                   enckeylen);
      goto fail;
    }
  if (ivlen < 8)
    {
      nasl_perror (lexic, "nasl_bf_cbc: unexpected ivlen = %d; must >= 8\n",
                   ivlen);
      goto fail;
    }
  if (datalen < 8)
    {
      nasl_perror (lexic, "nasl_bf_cbc: unexpected datalen = %d; must >= 8\n",
                   datalen);
      goto fail;
    }

  err = gcry_cipher_open (&hd, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_cipher_open", err);
      goto fail;
    }

  /* Always pass 16 as the length of enckey.  The old OpenSSL based code
   * did this explicitly.  The length cannot be < 16 at this point
   * because we checked for this case above. */
  err = gcry_cipher_setkey (hd, enckey, 16);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_cipher_setkey", err);
      goto fail;
    }
  /* Always pass 8 as the length of iv.  The old OpenSSL based code did
   * this implicitly.  The length cannot be < 8 at this point because we
   * checked for this case above. */
  err = gcry_cipher_setiv (hd, iv, 8);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_cipher_setiv", err);
      goto fail;
    }

  out = g_malloc0 (datalen);
  if (!out)
    goto fail;

  if (enc)
    err = gcry_cipher_encrypt (hd, out, datalen, data, datalen);
  else
    err = gcry_cipher_decrypt (hd, out, datalen, data, datalen);
  if (err)
    {
      print_gcrypt_error (lexic, "gcry_cipher_encrypt", err);
      goto fail;
    }

  retc->type = DYN_ARRAY;
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  /* first encrypted */
  v.var_type = VAR2_DATA;
  v.v.v_str.s_siz = datalen;
  v.v.v_str.s_val = (unsigned char *) out;
  (void) add_var_to_list (a, 0, &v);

  /* second iv */
  /* the iv to use to for the next part of the data is always the last
   * eight bytes of the cipher text.  When encrypting the cipher text is
   * in out when decrypting it's in data.
   */
  v.var_type = VAR2_DATA;
  v.v.v_str.s_siz = 8;
  v.v.v_str.s_val = (unsigned char *) ((enc ? out : data) + datalen - 8);
  (void) add_var_to_list (a, 1, &v);

  goto ret;

fail:
  retc->type = CONST_DATA;
  retc->x.str_val = g_malloc0 (1);
  retc->size = 0;

ret:
  g_free (out);
  gcry_cipher_close (hd);

  return retc;
}

/**
 * nasl function
 *
 *   bf_cbc_encrypt(key:key, iv:iv, data:data)
 *
 * Encrypt the plaintext data using the blowfish algorithm in CBC mode
 * with the key key and the initialization vector iv.  The key must be
 * 16 bytes long.  The iv must be at least 8 bytes long.  data must be a
 * multiple of 8 bytes long.
 *
 * The return value is an array a with a[0] being the encrypted data and
 * a[1] the new initialization vector to use for the next part of the
 * data.
 */
tree_cell *
nasl_bf_cbc_encrypt (lex_ctxt *lexic)
{
  return nasl_bf_cbc (lexic, 1);
}

/**
 * nasl function
 *
 *   bf_cbc_decrypt(key:key, iv:iv, data:data)
 *
 * Decrypt the cipher text data using the blowfish algorithm in CBC mode
 * with the key key and the initialization vector iv.  The key must be
 * 16 bytes long.  The iv must be at least 8 bytes long.  data must be a
 * multiple of 8 bytes long.
 *
 * The return value is an array a with a[0] being the plaintext data
 * and a[1] the new initialization vector to use for the next part of
 * the data.
 */
tree_cell *
nasl_bf_cbc_decrypt (lex_ctxt *lexic)
{
  return nasl_bf_cbc (lexic, 0);
}

/**
 * @brief Open a stream cipher. This function creates a context handle and
 * stores it in a cipher table.
 * Open cipher must be deleted with delete_cipher_item() at the end of the
 * stream encryption.
 * @param[in] cipher The cipher algorithm.
 * @param[in] mode The cipher mode. Must be compatible with the algorithm.
 * @param[in] caller_func Name of the caller function to be logged in case
 * of error.
 * @return Returns the ID of the cipher handler on success. Otherwise NULL.
 */
static tree_cell *
nasl_open_stream_cipher (lex_ctxt *lexic, int cipher, int mode,
                         const char *caller_func)
{
  gcry_cipher_hd_t hd;
  gcry_error_t error;
  void *key, *iv;
  size_t keylen, ivlen;
  tree_cell *retc;
  cipher_table_item_t *hd_item;
  int cipher_id;

  key = get_str_var_by_name (lexic, "key");
  keylen = get_var_size_by_name (lexic, "key");
  iv = get_str_var_by_name (lexic, "iv");
  ivlen = get_var_size_by_name (lexic, "iv");

  if (!key || keylen <= 0)
    {
      nasl_perror (lexic,
                   "Syntax: open_stream_cipher (called from "
                   "%s): Missing key argument",
                   caller_func);
      return NULL;
    }

  if ((error = gcry_cipher_open (&hd, cipher, mode, 0)))
    {
      nasl_perror (lexic, "gcry_cipher_open: %s", gcry_strerror (error));
      gcry_cipher_close (hd);
      return NULL;
    }
  if ((error = gcry_cipher_setkey (hd, key, keylen)))
    {
      nasl_perror (lexic, "gcry_cipher_setkey: %s", gcry_strerror (error));
      gcry_cipher_close (hd);
      return NULL;
    }

  if (iv && ivlen)
    {
      if ((error = gcry_cipher_setiv (hd, iv, ivlen)))
        {
          nasl_perror (lexic, "gcry_cipher_setiv: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          return NULL;
        }
    }

  cipher_id = get_new_cipher_id ();
  if (cipher_id == -1)
    {
      nasl_perror (lexic, "%s: No available slot for a new cipher.", __func__);
      gcry_cipher_close (hd);
      return NULL;
    }

  hd_item = cipher_table_item_new ();
  hd_item->hd = hd;
  hd_item->id = cipher_id;
  cipher_table = g_list_append (cipher_table, hd_item);

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = hd_item->id;
  return retc;
}

/**
 * @brief Encrypt data using an existent cipher handle. As the handler is not
 * close, the key is updated to encrypt the next block of the stream data.
 *
 * @param[in] cipher The cipher algorithm. It must be the same used for the
 * handler. It is used to prepare the data. Only GCRY_CIPHER_ARCFOUR is
 * currently supported.
 * @param[in] caller_func Name of the caller function to be logged in case
 * of error.
 * @return Returns the encrypted data on success. Otherwise NULL.
 */
static tree_cell *
encrypt_stream_data (lex_ctxt *lexic, int cipher, const char *caller_func)
{
  gcry_cipher_hd_t hd;
  gcry_error_t error;
  void *result, *data, *tmp;
  size_t resultlen, datalen, tmplen;
  tree_cell *retc;
  int cipher_id;

  cipher_id = get_int_var_by_name (lexic, "hd", -1);
  data = get_str_var_by_name (lexic, "data");
  datalen = get_var_size_by_name (lexic, "data");

  if (!data || datalen <= 0)
    {
      nasl_perror (lexic,
                   "Syntax: %s (called from "
                   "%s): Missing data argument",
                   __func__, caller_func);
      return NULL;
    }

  hd = verify_cipher_id (lexic, cipher_id);
  if (hd == NULL)
    return NULL;

  if (cipher == GCRY_CIPHER_ARCFOUR)
    {
      resultlen = datalen;
      tmp = g_malloc0 (datalen);
      memcpy (tmp, data, datalen);
      tmplen = datalen;
    }
  else
    {
      nasl_perror (lexic,
                   "Syntax: %s (called from "
                   "%s): invalid cipher",
                   __func__, caller_func);
      return NULL;
    }
  result = g_malloc0 (resultlen);
  if ((error = gcry_cipher_encrypt (hd, result, resultlen, tmp, tmplen)))
    {
      g_message ("gcry_cipher_encrypt: %s", gcry_strerror (error));
      delete_cipher_item (cipher_id);
      g_free (result);
      g_free (tmp);
      return NULL;
    }

  g_free (tmp);
  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = result;
  retc->size = resultlen;
  return retc;
}

/**
 * @brief Nasl function to delete a cipher item from the cipher table.
 *
 * @param[in] cipher_id The cipher id to close
 *
 * @return Returns zero on success. Otherwise NULL.
 */
tree_cell *
nasl_close_stream_cipher (lex_ctxt *lexic)
{
  tree_cell *retc;
  int cipher_id;
  gcry_cipher_hd_t hd;

  cipher_id = get_int_var_by_name (lexic, "hd", 0);

  hd = verify_cipher_id (lexic, cipher_id);
  if (hd == NULL)
    return NULL;

  delete_cipher_item (cipher_id);
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 0;
  return retc;
}

static tree_cell *
nasl_mac (lex_ctxt *lexic, int algo, int flags)
{
  gcry_error_t error;

  char *data, *key, *iv;
  char *result = NULL;
  size_t datalen, keylen, ivlen, resultlen;
  tree_cell *retc = NULL;

  data = get_str_var_by_name (lexic, "data");
  datalen = get_var_size_by_name (lexic, "data");
  key = get_str_var_by_name (lexic, "key");
  keylen = get_var_size_by_name (lexic, "key");
  iv = get_str_var_by_name (lexic, "iv");
  ivlen = get_var_size_by_name (lexic, "iv");

  switch ((error = mac (key, keylen, data, datalen, iv, ivlen, algo, flags,
                        &result, &resultlen)))
    {
    case GPG_ERR_NO_ERROR:
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = result;
      retc->size = resultlen;
      break;
    case GPG_ERR_MISSING_KEY:
    case GPG_ERR_MISSING_VALUE:
      nasl_perror (lexic, "Syntax: nasl_mac: Missing key, or data argument");
      break;
    default:
      nasl_perror (lexic, "Internal: %s.", gcry_strerror (error));
    }

  return retc;
}

tree_cell *
nasl_aes_mac_cbc (lex_ctxt *lexic)
{
  return nasl_mac (lexic, GCRY_MAC_CMAC_AES, GCRY_MAC_FLAG_SECURE);
}

tree_cell *
nasl_aes_mac_gcm (lex_ctxt *lexic)
{
  return nasl_mac (lexic, GCRY_MAC_GMAC_AES, GCRY_MAC_FLAG_SECURE);
}

static tree_cell *
crypt_data (lex_ctxt *lexic, int cipher, int mode, int flags)
{
  gcry_cipher_hd_t hd;
  gcry_error_t error;
  void *data, *key, *iv, *aad;
  unsigned char *result = NULL, *auth = NULL;
  size_t resultlen, datalen, keylen, ivlen, aadlen, authlen, len;
  tree_cell *retc;

  data = get_str_var_by_name (lexic, "data");
  datalen = get_var_size_by_name (lexic, "data");
  key = get_str_var_by_name (lexic, "key");
  keylen = get_var_size_by_name (lexic, "key");
  iv = get_str_var_by_name (lexic, "iv");
  ivlen = get_var_size_by_name (lexic, "iv");
  aad = get_str_var_by_name (lexic, "aad");
  aadlen = get_var_size_by_name (lexic, "aad");
  len = get_int_var_by_name (lexic, "len", 0);

  if (!data || datalen == 0 || !key || keylen == 0)
    {
      nasl_perror (lexic, "Syntax: crypt_data: Missing data or key argument");
      return NULL;
    }

  if (flags & NASL_DECRYPT && len <= 0)
    {
      nasl_perror (lexic,
                   "Syntax: crypt_data: Missing or invalid len argument");
      return NULL;
    }

  if ((error = gcry_cipher_open (&hd, cipher, mode, 0)))
    {
      nasl_perror (lexic, "gcry_cipher_open: %s", gcry_strerror (error));
      gcry_cipher_close (hd);
      return NULL;
    }

  if ((error = gcry_cipher_setkey (hd, key, keylen)))
    {
      nasl_perror (lexic, "gcry_cipher_setkey: %s", gcry_strerror (error));
      gcry_cipher_close (hd);
      return NULL;
    }

  if (iv && ivlen)
    {
      if ((error = gcry_cipher_setiv (hd, iv, ivlen)))
        {
          nasl_perror (lexic, "gcry_cipher_setiv: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          return NULL;
        }
    }

  if (flags & NASL_DECRYPT)
    {
      resultlen = len;
    }
  else
    {
      if (cipher == GCRY_CIPHER_ARCFOUR || mode == GCRY_CIPHER_MODE_CCM)
        resultlen = datalen;
      else if (cipher == GCRY_CIPHER_3DES)
        resultlen = ((datalen / 8) + 1) * 8;
      else if (cipher == GCRY_CIPHER_AES128)
        resultlen = datalen;
      else if (cipher == GCRY_CIPHER_AES256)
        resultlen = datalen;
      else
        {
          nasl_perror (lexic, "encrypt_data: Unknown cipher %d", cipher);
          gcry_cipher_close (hd);
          return NULL;
        }
    }

  if (mode == GCRY_CIPHER_MODE_CCM)
    {
      u_int64_t params[3];
      params[0] = datalen;
      params[1] = aadlen;
      params[2] = 16;
      if ((error = gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params,
                                    sizeof (params))))
        {
          nasl_perror (lexic, "gcry_cipher_ctl: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          return NULL;
        }
    }
  if (flags & NASL_AAD)
    {
      if (!aad || aadlen == 0)
        {
          nasl_perror (
            lexic, "Syntax: crypt_data: Missing or invalid aad value required");
          gcry_cipher_close (hd);
          return NULL;
        }

      if ((error = gcry_cipher_authenticate (hd, aad, aadlen)))
        {
          nasl_perror (lexic, "gcry_cipher_authenticate: %s",
                       gcry_strerror (error));
          gcry_cipher_close (hd);
          return NULL;
        }
    }

  result = g_malloc0 (resultlen);
  if (flags & NASL_DECRYPT)
    {
      if ((error =
             gcry_cipher_decrypt (hd, result, resultlen, data, resultlen)))
        {
          g_message ("gcry_cipher_decrypt: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          g_free (result);
          return NULL;
        }
    }
  else
    {
      if ((error =
             gcry_cipher_encrypt (hd, result, resultlen, data, resultlen)))
        {
          g_message ("gcry_cipher_encrypt: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          g_free (result);
          return NULL;
        }
    }

  if (flags & NASL_AAD)
    {
      authlen = 16;
      auth = g_malloc0 (authlen);

      if ((error = gcry_cipher_gettag (hd, auth, authlen)))
        {
          g_message ("gcry_cipher_gettag: %s", gcry_strerror (error));
          gcry_cipher_close (hd);
          g_free (result);
          g_free (auth);
          return NULL;
        }
      gcry_cipher_close (hd);

      anon_nasl_var v;
      retc = alloc_typed_cell (DYN_ARRAY);
      retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
      memset (&v, 0, sizeof (v));
      v.var_type = VAR2_DATA;
      v.v.v_str.s_val = result;
      v.v.v_str.s_siz = resultlen;
      add_var_to_list (retc->x.ref_val, 0, &v);

      memset (&v, 0, sizeof (v));
      v.var_type = VAR2_DATA;
      v.v.v_str.s_val = auth;
      v.v.v_str.s_siz = authlen;
      add_var_to_list (retc->x.ref_val, 1, &v);
      return retc;
    }

  gcry_cipher_close (hd);
  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = (char *) result;
  retc->size = resultlen;
  return retc;
}

/**
 * @brief Nasl function to encrypt data with a RC4 cipher. If an hd param
 * exist in the lexix context, it will use this handler to encrypt the data
 * as part of a stream data.
 * e.g.: rc4_encrypt(data: data, hd: hd)
 *
 * Otherwise encrypts the data as block and the key is mandatory:
 * e.g.: rc4_encrypt(data: data, key: key)
 *
 * @return Returns the encrypted data on success. Otherwise NULL.
 */
tree_cell *
nasl_rc4_encrypt (lex_ctxt *lexic)
{
  int cipher_id;
  gcry_cipher_hd_t hd;
  cipher_id = get_int_var_by_name (lexic, "hd", -1);

  if (cipher_id >= 0)
    {
      hd = verify_cipher_id (lexic, cipher_id);
      if (hd == NULL)
        return NULL;
      return encrypt_stream_data (lexic, GCRY_CIPHER_ARCFOUR, "rc4_encrypt");
    }

  return crypt_data (lexic, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM,
                     NASL_ENCRYPT);
}

/**
 * @brief Nasl function to open RC4 cipher to encrypt a stream of data.
 * The handler can be used to encrypt stream data.
 * Open cipher must be close with close_stream_cipher() when it is not useful
 * anymore.
 * @return Returns the id of the cipher handler encrypted data on success.
 * Otherwise NULL.
 */
tree_cell *
nasl_open_rc4_cipher (lex_ctxt *lexic)
{
  return nasl_open_stream_cipher (lexic, GCRY_CIPHER_ARCFOUR,
                                  GCRY_CIPHER_MODE_STREAM, "open_rc4_cipher");
}

tree_cell *
nasl_aes128_cbc_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes256_cbc_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes128_ctr_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes256_ctr_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_des_ede_cbc_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes128_gcm_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes128_gcm_encrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, NASL_AAD);
}

tree_cell *
nasl_aes128_gcm_decrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                     NASL_DECRYPT);
}

tree_cell *
nasl_aes128_gcm_decrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                     NASL_AAD | NASL_DECRYPT);
}

tree_cell *
nasl_aes256_gcm_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes256_gcm_encrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, NASL_AAD);
}

tree_cell *
nasl_aes256_gcm_decrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM,
                     NASL_DECRYPT);
}

tree_cell *
nasl_aes256_gcm_decrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM,
                     NASL_AAD | NASL_DECRYPT);
}

tree_cell *
nasl_aes128_ccm_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes128_ccm_encrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, NASL_AAD);
}

tree_cell *
nasl_aes128_ccm_decrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM,
                     NASL_DECRYPT);
}

tree_cell *
nasl_aes128_ccm_decrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM,
                     NASL_AAD | NASL_DECRYPT);
}

tree_cell *
nasl_aes256_ccm_encrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM,
                     NASL_ENCRYPT);
}

tree_cell *
nasl_aes256_ccm_encrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM, NASL_AAD);
}

tree_cell *
nasl_aes256_ccm_decrypt (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM,
                     NASL_DECRYPT);
}

tree_cell *
nasl_aes256_ccm_decrypt_auth (lex_ctxt *lexic)
{
  return crypt_data (lexic, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM,
                     NASL_AAD | NASL_DECRYPT);
}

/**
 * @brief Add the SMB3KDF as specified in [SP800-108] section 5.1
 *
 * @param lexic
 * @return tree_cell*
 */
tree_cell *
nasl_smb3kdf (lex_ctxt *lexic)
{
  gcry_mac_hd_t hd;
  gcry_error_t error;
  void *result, *key, *label, *context, *buf;
  u_char *tmp;
  size_t resultlen, keylen, labellen, contextlen, buflen, r = 4;
  long lvalue;
  int i = 1;
  tree_cell *retc;

  key = get_str_var_by_name (lexic, "key");
  keylen = get_var_size_by_name (lexic, "key");
  label = get_str_var_by_name (lexic, "label");
  labellen = get_var_size_by_name (lexic, "label");
  context = get_str_var_by_name (lexic, "ctx");
  contextlen = get_var_size_by_name (lexic, "ctx");
  lvalue = get_int_var_by_name (lexic, "lvalue", 0);

  if (!key || keylen <= 0 || !label || labellen <= 0 || !context
      || contextlen <= 0)
    {
      nasl_perror (
        lexic, "Syntax: nasl_smb3kdf: Missing key, label or context argument");
      return NULL;
    }

  if (lvalue != 128 && lvalue != 256)
    {
      nasl_perror (lexic,
                   "nasl_smb3kdf: lvalue must have a value of 128 or 256");
      return NULL;
    }

  if ((error = gcry_mac_open (&hd, GCRY_MAC_HMAC_SHA256, 0, NULL)))
    {
      nasl_perror (lexic, "gcry_mac_open: %s", gcry_strerror (error));
      gcry_mac_close (hd);
      return NULL;
    }

  if ((error = gcry_mac_setkey (hd, key, keylen)))
    {
      nasl_perror (lexic, "gcry_mac_setkey: %s", gcry_strerror (error));
      gcry_mac_close (hd);
      return NULL;
    }

  resultlen = lvalue / 8;

  // Prepare buffer as in [SP800-108] section 5.1
  // [i]2 || Label || 0x00 || Context || [L]2
  // [i]2 is the binary presentation of the iteration. Allways 1
  // Label is given by caller
  // 0x00 is a byte set to 0
  // Context is given by caller
  // L is a integer set to 128 or 256 for smb3kdf
  buflen = r + labellen + 1 + contextlen + 4;
  buf = g_malloc0 (buflen);
  tmp = buf;

  // We need bytes in big endian, but they are currently stored as little endian
  i = htonl (i);
  memcpy (tmp, &i, r);
  tmp = tmp + r;

  memcpy (tmp, label, labellen);
  tmp = tmp + labellen;
  *tmp = 0;
  tmp = tmp + 1;
  memcpy (tmp, context, contextlen);
  tmp = tmp + contextlen;

  // We need bytes in big endian, but they are currently stored as little endian
  lvalue = htonl (lvalue);
  memcpy (tmp, &lvalue, 4);

  if ((error = gcry_mac_write (hd, buf, buflen)))
    {
      g_message ("gcry_mac_write: %s", gcry_strerror (error));
      gcry_mac_close (hd);
      g_free (buf);
      return NULL;
    }

  result = g_malloc0 (resultlen);
  if ((error = gcry_mac_read (hd, result, &resultlen)))
    {
      g_message ("gcry_mac_read: %s", gcry_strerror (error));
      gcry_mac_close (hd);
      g_free (buf);
      g_free (result);
      return NULL;
    }

  g_free (buf);
  gcry_mac_close (hd);
  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = result;
  retc->size = resultlen;
  return retc;
}
