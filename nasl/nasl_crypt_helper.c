/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../misc//support.h"
#include "nasl_crypto_helper.h"
#include "nasl_debug.h"

#include <assert.h>
#include <ctype.h>
#include <gcrypt.h>
#include <glib.h>
#include <gpg-error.h>
#include <gvm/base/logging.h>
#include <stddef.h>
#include <stdlib.h>

void *
hmac_md5_for_prf (const void *key, int keylen, const void *buf, int buflen)
{
  void *signature = g_malloc0 (16);
  gsize signlen = 16;
  GHmac *hmac;

  hmac = g_hmac_new (G_CHECKSUM_MD5, key, keylen);
  g_hmac_update (hmac, buf, buflen);
  g_hmac_get_digest (hmac, signature, &signlen);
  g_hmac_unref (hmac);
  return signature;
}

void *
hmac_sha1 (const void *key, int keylen, const void *buf, int buflen)
{
  void *signature = g_malloc0 (20);
  gsize signlen = 20;
  GHmac *hmac;

  hmac = g_hmac_new (G_CHECKSUM_SHA1, key, keylen);
  g_hmac_update (hmac, buf, buflen);
  g_hmac_get_digest (hmac, signature, &signlen);
  g_hmac_unref (hmac);
  return signature;
}

void *
hmac_sha256 (const void *key, int keylen, const void *buf, int buflen)
{
  void *signature = g_malloc0 (32);
  gsize signlen = 32;
  GHmac *hmac;

  hmac = g_hmac_new (G_CHECKSUM_SHA256, key, keylen);
  g_hmac_update (hmac, buf, buflen);
  g_hmac_get_digest (hmac, signature, &signlen);
  g_hmac_unref (hmac);
  return signature;
}

void *
hmac_sha384 (const void *key, int keylen, const void *buf, int buflen)
{
  gcry_md_hd_t hd;
  gcry_error_t err;
  void *ret;

  if (!buf || buflen <= 0)
    return NULL;

  err = gcry_md_open (&hd, GCRY_MD_SHA384, key ? GCRY_MD_FLAG_HMAC : 0);
  if (err)
    {
      g_message ("nasl_gcrypt_hash(): gcry_md_open failed: %s/%s",
                 gcry_strsource (err), gcry_strerror (err));
      return NULL;
    }

  if (key)
    {
      err = gcry_md_setkey (hd, key, keylen);
      if (err)
        {
          g_message ("nasl_gcrypt_hash(): gcry_md_setkey failed: %s/%s",
                     gcry_strsource (err), gcry_strerror (err));
          return NULL;
        }
    }

  gcry_md_write (hd, buf, buflen);
  ret = g_memdup2 (gcry_md_read (hd, 0), 48);
  gcry_md_close (hd);
  return ret;
}

gpg_err_code_t
mac (const char *key, const size_t key_len, const char *data,
     const size_t data_len, const char *iv, const size_t iv_len, int algo,
     int flags, char **out, size_t *out_len)
{
  // guardian
  gpg_err_code_t result = 0;
  gcry_mac_hd_t hd;
  if (key == NULL || key_len < 1)
    return GPG_ERR_MISSING_KEY;
  if (data == NULL || data_len < 1)
    return GPG_ERR_MISSING_VALUE;
  if (out == NULL)
    {
      return GPG_ERR_GENERAL;
    }
  if ((result = gcry_mac_open (&hd, algo, flags, NULL)))
    return result;
  if ((result = gcry_mac_setkey (hd, key, key_len)))
    goto cexit;
  if (iv && (result = gcry_mac_setiv (hd, iv, iv_len)))
    goto cexit;
  if ((result = gcry_mac_write (hd, data, data_len)))
    goto cexit;

  *out_len = gcry_mac_get_algo_maclen (algo);
  if ((*out = g_malloc0 (*out_len * sizeof (*out))) == NULL)
    {
      result = GPG_ERR_ENOMEM;
      goto cexit;
    }
  if ((result = gcry_mac_read (hd, *out, out_len)))
    goto cexit;

cexit:
  gcry_mac_close (hd);
  return result;
}

static gcry_error_t
smb_sign (const int algo, const char *key, const size_t key_len, char *buf,
          const size_t buf_len, const char *iv, const size_t iv_len, char **out)
{
  gcry_error_t error = GPG_ERR_NO_ERROR;
  char *signature = NULL;
  size_t signature_len;
  if (buf == NULL || buf_len < 64)
    {
      return GPG_ERR_NO_VALUE;
    }
  if (key == NULL || key_len < 16)
    return GPG_ERR_NO_KEY;
  memset ((char *) buf + 48, 0, 16);
  switch (algo)
    {
    case GCRY_MAC_GMAC_AES:
      if ((error = mac (key, key_len, buf, buf_len, iv, iv_len, algo,
                        GCRY_MAC_FLAG_SECURE, &signature, &signature_len)))
        goto exit;
      break;
    case GCRY_MAC_CMAC_AES:
      if ((error = mac (key, key_len, buf, buf_len, NULL, 0, algo,
                        GCRY_MAC_FLAG_SECURE, &signature, &signature_len)))
        goto exit;
      break;
    case G_CHECKSUM_SHA256:
      signature = hmac_sha256 (key, key_len, buf, buf_len);
      break;
    default:
      // not defined;
      error = GPG_ERR_UNKNOWN_ALGORITHM;
      goto exit;
    }
  // TODO is 16 hard coded or should it be signature_len?
  *out = g_malloc0 (buf_len);
  memcpy (*out, buf, buf_len);
  memcpy (*out + 48, signature, 16);
  free (signature);
exit:
  return error;
}

tree_cell *
nasl_smb_sign (const int algo, lex_ctxt *lexic)
{
  char *key, *buf, *iv, *res;
  int keylen, buflen, ivlen;
  gcry_error_t error;
  tree_cell *retc = NULL;

  key = get_str_var_by_name (lexic, "key");
  buf = get_str_var_by_name (lexic, "buf");
  iv = get_str_var_by_name (lexic, "iv");
  keylen = get_var_size_by_name (lexic, "key");
  buflen = get_var_size_by_name (lexic, "buf");
  ivlen = get_var_size_by_name (lexic, "iv");

  switch ((error = smb_sign (algo, key, keylen, buf, buflen, iv, ivlen, &res)))
    {
    case GPG_ERR_NO_ERROR:
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = res;
      retc->size = buflen;
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
