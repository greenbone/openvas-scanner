/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_crypto.c
 * @brief This file contains all the cryptographic functions NASL has.
 */

/* MODIFICATION: added definitions for implementing NTLMSSP features */

#include "nasl_crypto.h"

#include "../misc/support.h"
#include "exec.h"
#include "hmacmd5.h"
#include "nasl_crypto_helper.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"
#include "ntlmssp.h"
#include "smb.h"
#include "smb_crypt.h"
#include "smb_signing.h"

#include <assert.h>
#include <ctype.h>
#include <gcrypt.h>
#include <glib.h>
#include <gvm/base/logging.h>
#include <stddef.h>
#include <stdlib.h>

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

#ifndef uint32
#define uint32 uint32_t
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/*-------------------[  Std. HASH ]-------------------------------------*/
static tree_cell *
nasl_gcrypt_hash (lex_ctxt *lexic, int algorithm, void *data, size_t datalen,
                  void *key, size_t keylen)
{
  gcry_md_hd_t hd;
  gcry_error_t err;
  tree_cell *retc;
  unsigned int dlen = gcry_md_get_algo_dlen (algorithm);

  if (data == NULL)
    return NULL;

  err = gcry_md_open (&hd, algorithm, key ? GCRY_MD_FLAG_HMAC : 0);
  if (err)
    {
      nasl_perror (lexic, "nasl_gcrypt_hash(): gcry_md_open failed: %s/%s\n",
                   gcry_strsource (err), gcry_strerror (err));
      return NULL;
    }

  if (key)
    {
      err = gcry_md_setkey (hd, key, keylen);
      if (err)
        {
          nasl_perror (lexic,
                       "nasl_gcrypt_hash():"
                       " gcry_md_setkey failed: %s/%s\n",
                       gcry_strsource (err), gcry_strerror (err));
          return NULL;
        }
    }

  gcry_md_write (hd, data, datalen);

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_malloc0 (dlen + 1);
  memcpy (retc->x.str_val, gcry_md_read (hd, algorithm), dlen + 1);
  retc->size = dlen;

  gcry_md_close (hd);

  return retc;
}

static tree_cell *
nasl_hash (lex_ctxt *lexic, int algorithm)
{
  char *data = get_str_var_by_num (lexic, 0);
  int len = get_var_size_by_num (lexic, 0);

  return nasl_gcrypt_hash (lexic, algorithm, data, len, NULL, 0);
}

tree_cell *
nasl_md2 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD2);
}

tree_cell *
nasl_md4 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD4);
}

tree_cell *
nasl_md5 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_sha1 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_SHA1);
}

tree_cell *
nasl_sha256 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_SHA256);
}

tree_cell *
nasl_sha512 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_SHA512);
}

tree_cell *
nasl_ripemd160 (lex_ctxt *lexic)
{
  return nasl_hash (lexic, GCRY_MD_RMD160);
}

static tree_cell *
nasl_cipher (int algorithm, void *data, size_t dlen, void *key, size_t klen)
{
  gcry_cipher_hd_t hd;
  gcry_error_t error;
  tree_cell *retc;
  char *result;

  if ((error = gcry_cipher_open (&hd, algorithm, GCRY_CIPHER_MODE_ECB, 0)))
    {
      g_message ("gcry_cipher_open: %s", gcry_strerror (error));
      return NULL;
    }
  if ((error = gcry_cipher_setkey (hd, key, klen)))
    {
      g_message ("gcry_cipher_setkey: %s", gcry_strerror (error));
      return NULL;
    }
  result = g_malloc0 (dlen);
  if ((error = gcry_cipher_encrypt (hd, result, dlen, data, dlen)))
    {
      g_message ("gcry_cipher_encrypt: %s", gcry_strerror (error));
      return NULL;
    }
  gcry_cipher_close (hd);

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = result;
  retc->size = dlen;
  return retc;
}

tree_cell *
nasl_cipher_des (lex_ctxt *lexic)
{
  char *data, *key;
  size_t dlen, klen;

  data = get_str_var_by_num (lexic, 0);
  dlen = get_var_size_by_num (lexic, 0);
  key = get_str_var_by_num (lexic, 1);
  klen = get_var_size_by_num (lexic, 1);
  return nasl_cipher (GCRY_CIPHER_DES, data, dlen, key, klen);
}

/*-------------------[  HMAC ]-------------------------------------*/

static tree_cell *
nasl_hmac (lex_ctxt *lexic, int algorithm)
{
  char *data = get_str_var_by_name (lexic, "data");
  char *key = get_str_var_by_name (lexic, "key");
  int data_len = get_var_size_by_name (lexic, "data");
  int key_len = get_var_size_by_name (lexic, "key");

  return nasl_gcrypt_hash (lexic, algorithm, data, data_len, key, key_len);
}

tree_cell *
nasl_hmac_md2 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_MD2);
}

tree_cell *
nasl_hmac_md5 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_hmac_sha1 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_SHA1);
}

tree_cell *
nasl_hmac_sha384 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_SHA384);
}

tree_cell *
nasl_hmac_ripemd160 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_RMD160);
}

/*-------------------[ Windows ]-------------------------------------*/
tree_cell *
nasl_get_sign (lex_ctxt *lexic)
{
  char *mac_key = (char *) get_str_var_by_name (lexic, "key");
  uint8_t *buf = (uint8_t *) get_str_var_by_name (lexic, "buf");
  int buflen = get_int_var_by_name (lexic, "buflen", -1);
  int seq_num = get_int_var_by_name (lexic, "seq_number", -1);
  if (mac_key == NULL || buf == NULL || buflen == -1 || seq_num <= -1)
    {
      nasl_perror (lexic, "Syntax : get_signature(key:<k>, buf:<b>, "
                          "buflen:<bl>, seq_number:<s>)\n");
      return NULL;
    }
  uint8_t calc_md5_mac[16];
  simple_packet_signature_ntlmssp ((uint8_t *) mac_key, buf, seq_num,
                                   calc_md5_mac);
  memcpy (buf + 18, calc_md5_mac, 8);
  char *ret = g_malloc0 (buflen);
  memcpy (ret, buf, buflen);
  tree_cell *retc;
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = buflen;
  retc->x.str_val = (char *) ret;
  return retc;
}

tree_cell *
nasl_hmac_sha256 (lex_ctxt *lexic)
{
  void *key, *data, *signature;
  int keylen, datalen;
  tree_cell *retc;

  key = get_str_var_by_name (lexic, "key");
  data = get_str_var_by_name (lexic, "data");
  datalen = get_var_size_by_name (lexic, "data");
  keylen = get_var_size_by_name (lexic, "key");
  if (!key || !data || keylen <= 0 || datalen <= 0)
    {
      nasl_perror (lexic, "Syntax : hmac_sha256(data:<b>, key:<k>)\n");
      return NULL;
    }
  signature = hmac_sha256 (key, keylen, data, datalen);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 32;
  retc->x.str_val = (char *) signature;
  return retc;
}

/* @brief PRF function from RFC 2246 chapter 5.
 *
 * @param hmac   0 for SHA256, 1 for SHA384, 2 for MD5, 3 for SHA1.
 *
 * */
static void *
tls_prf (const void *secret, size_t secret_len, const void *seed,
         size_t seed_len, const void *label, size_t outlen, int hmac)
{
  char *result = NULL;
  size_t pos = 0, lslen, hmac_size;
  void *Ai;
  void *lseed;
  void *(*hmac_func) (const void *, int, const void *, int);

  if (hmac == 0)
    {
      hmac_size = 32;
      hmac_func = hmac_sha256;
    }
  else if (hmac == 1)
    {
      hmac_size = 48;
      hmac_func = hmac_sha384;
    }
  else if (hmac == 2)
    {
      hmac_size = 16;
      hmac_func = hmac_md5_for_prf;
    }
  else
    {
      hmac_size = 20;
      hmac_func = hmac_sha1;
    }

  /*
   * lseed = label + seed
   * A0 = lseed (new seed)
   * Ai = HMAC(secret, A(i - 1))
   */
  lslen = strlen (label) + seed_len;
  lseed = g_malloc0 (lslen);
  memcpy (lseed, label, strlen (label));
  memcpy ((char *) lseed + strlen (label), seed, seed_len);

  Ai = hmac_func (secret, secret_len, lseed, lslen);
  if (!Ai)
    {
      g_free (lseed);
      return NULL;
    }

  result = g_malloc0 (outlen);
  while (pos < outlen)
    {
      void *tmp, *tmp2;
      size_t clen;

      /* HMAC_hash(secret, Ai + lseed) */
      tmp = g_malloc0 (hmac_size + lslen);
      memcpy (tmp, Ai, hmac_size);
      memcpy ((char *) tmp + hmac_size, lseed, lslen);
      tmp2 = hmac_func (secret, secret_len, tmp, hmac_size + lslen);
      g_free (tmp);
      /* concat to result */
      clen = outlen - pos;
      if (clen > hmac_size)
        clen = hmac_size;
      memcpy (result + pos, tmp2, clen);
      pos += clen;
      g_free (tmp2);

      /* A(i+1) */
      tmp = hmac_func (secret, secret_len, Ai, hmac_size);
      g_free (Ai);
      Ai = tmp;
    }

  g_free (Ai);
  g_free (lseed);
  return result;
}

/* @brief PRF function from RFC 4346 chapter 5. TLS v1.1
 *
 * Legacy function in which P_MD5 and PSHA1 are combined.
 *
 * Legacy function has been replaced with prf_sha256 and prf_sha348
 *  in TLS v1.2, as it can be read in chapter 1.2
 * */
static void *
tls1_prf (const void *secret, size_t secret_len, const void *seed,
          size_t seed_len, const void *label, size_t outlen)
{
  void *result, *secret1 = NULL, *secret2 = NULL;
  unsigned int half_slen, odd = 0, i;
  char *resultmd5 = NULL, *resultsha1 = NULL, *aux_res = NULL;

  if (secret_len % 2 == 0)
    half_slen = secret_len / 2;
  else
    {
      half_slen = (secret_len + 1) / 2;
      odd = 1;
    }

  secret1 = g_malloc0 (half_slen);
  memcpy (secret1, secret, half_slen);
  resultmd5 = tls_prf (secret1, half_slen, seed, seed_len, label, outlen, 2);
  if (!resultmd5)
    {
      g_free (secret1);
      return NULL;
    }

  secret2 = g_malloc0 (half_slen);
  memcpy (secret2, (char *) secret + (half_slen - odd), half_slen);
  resultsha1 = tls_prf (secret2, half_slen, seed, seed_len, label, outlen, 3);
  if (!resultsha1)
    {
      g_free (resultmd5);
      g_free (secret1);
      g_free (secret2);
      return NULL;
    }

  aux_res = g_malloc0 (outlen);
  for (i = 0; i < outlen; i++)
    aux_res[i] = resultmd5[i] ^ resultsha1[i];

  result = g_malloc (outlen);
  memcpy (result, aux_res, outlen);

  g_free (resultmd5);
  g_free (resultsha1);
  g_free (secret1);
  g_free (secret2);
  g_free (aux_res);

  return result;
}

static tree_cell *
nasl_prf (lex_ctxt *lexic, int hmac)
{
  void *secret, *seed, *label, *result;
  int secret_len, seed_len, label_len, outlen;
  tree_cell *retc;

  secret = get_str_var_by_name (lexic, "secret");
  seed = get_str_var_by_name (lexic, "seed");
  label = get_str_var_by_name (lexic, "label");
  outlen = get_int_var_by_name (lexic, "outlen", -1);
  seed_len = get_var_size_by_name (lexic, "seed");
  secret_len = get_var_size_by_name (lexic, "secret");
  label_len = get_var_size_by_name (lexic, "label");
  if (!secret || !seed || secret_len <= 0 || seed_len <= 0 || !label
      || label_len <= 0 || outlen <= 0)
    {
      nasl_perror (lexic, "Syntax : prf(secret, seed, label, outlen)\n");
      return NULL;
    }
  if (hmac != 2)
    result = tls_prf (secret, secret_len, seed, seed_len, label, outlen, hmac);
  else
    result = tls1_prf (secret, secret_len, seed, seed_len, label, outlen);

  if (!result)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = outlen;
  retc->x.str_val = (char *) result;
  return retc;
}

tree_cell *
nasl_prf_sha256 (lex_ctxt *lexic)
{
  return nasl_prf (lexic, 0);
}

tree_cell *
nasl_prf_sha384 (lex_ctxt *lexic)
{
  return nasl_prf (lexic, 1);
}

tree_cell *
nasl_tls1_prf (lex_ctxt *lexic)
{
  return nasl_prf (lexic, 2);
}

tree_cell *
nasl_hmac_sha512 (lex_ctxt *lexic)
{
  return nasl_hmac (lexic, GCRY_MD_SHA512);
}

tree_cell *
nasl_get_smb2_sign (lex_ctxt *lexic)
{
  return nasl_smb_sign (G_CHECKSUM_SHA256, lexic);
}

tree_cell *
nasl_smb_cmac_aes_sign (lex_ctxt *lexic)
{
  return nasl_smb_sign (GCRY_MAC_CMAC_AES, lexic);
}

tree_cell *
nasl_smb_gmac_aes_sign (lex_ctxt *lexic)
{
  return nasl_smb_sign (GCRY_MAC_GMAC_AES, lexic);
}

tree_cell *
nasl_ntlmv2_response (lex_ctxt *lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *user = (char *) get_str_var_by_name (lexic, "user");
  char *domain = (char *) get_str_var_by_name (lexic, "domain");
  unsigned char *ntlmv2_hash =
    (unsigned char *) get_str_var_by_name (lexic, "ntlmv2_hash");
  char *address_list = get_str_var_by_name (lexic, "address_list");
  int address_list_len = get_int_var_by_name (lexic, "address_list_len", -1);

  if (cryptkey == NULL || user == NULL || domain == NULL || ntlmv2_hash == NULL
      || address_list == NULL || address_list_len < 0)
    {
      nasl_perror (
        lexic, "Syntax : ntlmv2_response(cryptkey:<c>, user:<u>, domain:<d>, "
               "ntlmv2_hash:<n>, address_list:<a>, address_list_len:<len>)\n");
      return NULL;
    }
  uint8_t lm_response[24];
  uint8_t nt_response[16 + 28 + address_list_len];
  uint8_t session_key[16];
  bzero (lm_response, sizeof (lm_response));
  bzero (nt_response, sizeof (nt_response));
  bzero (session_key, sizeof (session_key));

  ntlmssp_genauth_ntlmv2 (user, domain, address_list, address_list_len,
                          cryptkey, lm_response, nt_response, session_key,
                          ntlmv2_hash);
  tree_cell *retc;
  int lm_response_len = 24;
  int nt_response_len = 16 + 28 + address_list_len;
  int len = lm_response_len + nt_response_len + sizeof (session_key);
  char *ret = g_malloc0 (len);
  memcpy (ret, lm_response, lm_response_len);
  memcpy (ret + lm_response_len, session_key, sizeof (session_key));
  memcpy (ret + lm_response_len + sizeof (session_key), nt_response,
          nt_response_len);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlm2_response (lex_ctxt *lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "password");
  uint8_t pass_len = get_var_size_by_name (lexic, "password");
  void *nt_hash = get_str_var_by_name (lexic, "nt_hash");
  int hash_len = get_var_size_by_name (lexic, "nt_hash");

  if (!cryptkey || !password || !nt_hash || hash_len < 16)
    {
      nasl_perror (lexic, "Syntax : ntlm2_response(cryptkey:<c>, password:<p>, "
                          "nt_hash:<n[16]>)\n");
      return NULL;
    }

  uint8_t lm_response[24];
  uint8_t nt_response[24];
  uint8_t session_key[16];

  tree_cell *retc;
  ntlmssp_genauth_ntlm2 (password, pass_len, lm_response, nt_response,
                         session_key, cryptkey, nt_hash);
  int len = sizeof (lm_response) + sizeof (nt_response) + sizeof (session_key);
  char *ret = g_malloc0 (len);
  memcpy (ret, lm_response, sizeof (lm_response));
  memcpy (ret + sizeof (lm_response), nt_response, sizeof (nt_response));
  memcpy (ret + sizeof (lm_response) + sizeof (nt_response), session_key,
          sizeof (session_key));
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlm_response (lex_ctxt *lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "password");
  uint8_t pass_len = (uint8_t) get_var_size_by_name (lexic, "password");
  void *nt_hash = get_str_var_by_name (lexic, "nt_hash");
  int hash_len = get_var_size_by_name (lexic, "nt_hash");
  int neg_flags = get_int_var_by_name (lexic, "neg_flags", -1);

  if (!cryptkey || !password || !nt_hash || hash_len < 16 || neg_flags < 0)
    {
      nasl_perror (lexic, "Syntax : ntlm_response(cryptkey:<c>, password:<p>, "
                          "nt_hash:<n[16]>, neg_flags:<nf>)\n");
      return NULL;
    }

  uint8_t lm_response[24];
  uint8_t nt_response[24];
  uint8_t session_key[16];

  tree_cell *retc;

  ntlmssp_genauth_ntlm (password, pass_len, lm_response, nt_response,
                        session_key, cryptkey, nt_hash, neg_flags);

  int len = sizeof (lm_response) + sizeof (nt_response) + sizeof (session_key);
  char *ret = g_malloc0 (len);
  memcpy (ret, lm_response, sizeof (lm_response));
  memcpy (ret + sizeof (lm_response), nt_response, sizeof (nt_response));
  memcpy (ret + sizeof (lm_response) + sizeof (nt_response), session_key,
          sizeof (session_key));
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_keyexchg (lex_ctxt *lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  uint8_t *session_key = (uint8_t *) get_str_var_by_name (lexic, "session_key");
  unsigned char *nt_hash =
    (unsigned char *) get_str_var_by_name (lexic, "nt_hash");

  if (cryptkey == NULL || session_key == NULL || nt_hash == NULL)
    {
      nasl_perror (
        lexic,
        "Syntax : key_exchange(cryptkey:<c>, session_key:<s>, nt_hash:<n> )\n");
      return NULL;
    }
  uint8_t new_sess_key[16];
  tree_cell *retc;
  uint8_t *encrypted_session_key = NULL;
  encrypted_session_key = ntlmssp_genauth_keyexchg (
    session_key, cryptkey, nt_hash, (uint8_t *) &new_sess_key);
  int len = 16 + 16;
  char *ret = g_malloc0 (len);
  memcpy (ret, new_sess_key, 16);
  memcpy (ret + 16, encrypted_session_key, 16);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlmv1_hash (lex_ctxt *lexic)
{
  const uchar *cryptkey = (uchar *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "passhash");
  int pass_len = get_var_size_by_name (lexic, "passhash");
  unsigned char p21[21];
  tree_cell *retc;
  uchar *ret;

  if (cryptkey == NULL || password == NULL)
    {
      nasl_perror (lexic, "Syntax : ntlmv1_hash(cryptkey:<c>, passhash:<p>)\n");
      return NULL;
    }

  if (pass_len < 16)
    pass_len = 16;

  bzero (p21, sizeof (p21));
  memcpy (p21, password, pass_len);

  ret = g_malloc0 (24);

  E_P24 (p21, cryptkey, ret);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 24;
  retc->x.str_val = (char *) ret;

  return retc;
}

tree_cell *
nasl_nt_owf_gen (lex_ctxt *lexic)
{
  char *pass = get_str_var_by_num (lexic, 0);
  gunichar2 *upass;
  glong upass_len;
  tree_cell *ret;

  if (!pass)
    {
      nasl_perror (lexic, "Syntax : nt_owf_gen(<password>)\n");
      return NULL;
    }
  upass = g_utf8_to_utf16 (pass, -1, NULL, &upass_len, NULL);
  ret = nasl_gcrypt_hash (lexic, GCRY_MD_MD4, upass, upass_len * 2, NULL, 0);
  g_free (upass);
  return ret;
}

tree_cell *
nasl_lm_owf_gen (lex_ctxt *lexic)
{
  char *pass = get_str_var_by_num (lexic, 0);
  int pass_len = get_var_size_by_num (lexic, 0);
  tree_cell *retc;
  uchar pwd[15];
  uchar p16[16];
  unsigned int i;

  if (pass_len < 0 || pass == NULL)
    {
      nasl_perror (lexic, "Syntax : nt_lm_gen(password:<p>)\n");
      return NULL;
    }

  bzero (pwd, sizeof (pwd));
  strncpy ((char *) pwd, pass, sizeof (pwd) - 1);
  for (i = 0; i < sizeof (pwd); i++)
    pwd[i] = toupper (pwd[i]);

  E_P16 (pwd, p16);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 16;
  retc->x.str_val = g_memdup2 (p16, 16);
  return retc;
}

tree_cell *
nasl_insert_hexzeros (lex_ctxt *lexic)
{
  const uchar *in = (uchar *) get_str_var_by_name (lexic, "in");
  int in_len = get_var_size_by_name (lexic, "in");
  char *src;
  smb_ucs2_t *out, *dst, val;
  int i;
  size_t byte_len;
  tree_cell *retc;
  if (in_len < 0 || in == NULL)
    {
      nasl_perror (lexic, "Syntax : insert_hexzeros(in:<i>)\n");
      return NULL;
    }

  byte_len = sizeof (smb_ucs2_t) * (strlen ((char *) in) + 1);
  out = g_malloc0 (byte_len);
  dst = out;
  src = (char *) in;

  for (i = 0; i < in_len; i++)
    {
      val = *src;
      *dst = val;
      dst++;
      src++;
      if (val == 0)
        break;
    }

  /* We don't want null termination */
  byte_len = byte_len - 2;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = byte_len;
  retc->x.str_val = (char *) out;
  return retc;
}

/* Does both the NTLMv2 owfs of a user's password */
tree_cell *
nasl_ntv2_owf_gen (lex_ctxt *lexic)
{
  const uchar *owf_in = (uchar *) get_str_var_by_name (lexic, "owf");
  int owf_in_len = get_var_size_by_name (lexic, "owf");
  char *user_in = get_str_var_by_name (lexic, "login");
  int user_in_len = get_var_size_by_name (lexic, "login");
  char *domain_in = get_str_var_by_name (lexic, "domain");
  int domain_len = get_var_size_by_name (lexic, "domain");
  char *src_user, *src_domain;
  smb_ucs2_t *user, *dst_user, val_user;
  smb_ucs2_t *domain, *dst_domain, val_domain;
  int i;
  size_t user_byte_len;
  size_t domain_byte_len;
  tree_cell *retc;
  uchar *kr_buf;
  HMACMD5Context ctx;

  if (owf_in_len < 0 || owf_in == NULL || user_in_len < 0 || user_in == NULL
      || domain_len < 0 || domain_in == NULL)
    {
      nasl_perror (lexic,
                   "Syntax : ntv2_owf_gen(owf:<o>, login:<l>, domain:<d>)\n");
      return NULL;
    }

  assert (owf_in_len == 16);

  user_byte_len = sizeof (smb_ucs2_t) * (strlen (user_in) + 1);
  user = g_malloc0 (user_byte_len);
  dst_user = user;
  src_user = user_in;

  for (i = 0; i < user_in_len; i++)
    {
      val_user = *src_user;
      *dst_user = val_user;
      dst_user++;
      src_user++;
      if (val_user == 0)
        break;
    }

  domain_byte_len = sizeof (smb_ucs2_t) * (strlen (domain_in) + 1);
  domain = g_malloc0 (domain_byte_len);
  dst_domain = domain;
  src_domain = domain_in;

  for (i = 0; i < domain_len; i++)
    {
      val_domain = *src_domain;
      *dst_domain = val_domain;

      dst_domain++;
      src_domain++;
      if (val_domain == 0)
        break;
    }

  strupper_w (user);
  strupper_w (domain);

  assert (user_byte_len >= 2);
  assert (domain_byte_len >= 2);

  /* We don't want null termination */
  user_byte_len = user_byte_len - 2;
  domain_byte_len = domain_byte_len - 2;

  kr_buf = g_malloc0 (16);

  hmac_md5_init_limK_to_64 (owf_in, 16, &ctx);
  hmac_md5_update ((const unsigned char *) user, user_byte_len, &ctx);
  hmac_md5_update ((const unsigned char *) domain, domain_byte_len, &ctx);
  hmac_md5_final (kr_buf, &ctx);

  g_free (user);
  g_free (domain);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = 16;
  retc->x.str_val = (char *) kr_buf;

  return retc;
}

tree_cell *
nasl_ntlmv2_hash (lex_ctxt *lexic)
{
  const uchar *server_chal = (uchar *) get_str_var_by_name (lexic, "cryptkey");
  int sc_len = get_var_size_by_name (lexic, "cryptkey");
  const uchar *ntlm_v2_hash = (uchar *) get_str_var_by_name (lexic, "passhash");
  int hash_len = get_var_size_by_name (lexic, "passhash");
  int client_chal_length = get_int_var_by_name (lexic, "length", -1);
  tree_cell *retc;
  unsigned char ntlmv2_response[16];
  unsigned char *ntlmv2_client_data = NULL;
  unsigned char *final_response;
  int i;

  if (sc_len < 0 || server_chal == NULL || hash_len < 0 || ntlm_v2_hash == NULL
      || client_chal_length < 0)
    {
      nasl_perror (
        lexic,
        "Syntax : ntlmv2_hash(cryptkey:<c>, passhash:<p>, length:<l>)\n");
      return NULL;
    }

  /* NTLMv2 */

  /* We also get to specify some random data */
  ntlmv2_client_data = g_malloc0 (client_chal_length);
  for (i = 0; i < client_chal_length; i++)
    ntlmv2_client_data[i] = rand () % 256;

  assert (hash_len == 16);
  /* Given that data, and the challenge from the server, generate a response */
  SMBOWFencrypt_ntv2_ntlmssp (ntlm_v2_hash, server_chal, 8, ntlmv2_client_data,
                              client_chal_length, ntlmv2_response);

  /* put it into nt_response, for the code below to put into the packet */
  final_response = g_malloc0 (client_chal_length + sizeof (ntlmv2_response));
  memcpy (final_response, ntlmv2_response, sizeof (ntlmv2_response));
  /* after the first 16 bytes is the random data we generated above, so the
   * server can verify us with it */
  memcpy (final_response + sizeof (ntlmv2_response), ntlmv2_client_data,
          client_chal_length);

  g_free (ntlmv2_client_data);

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = client_chal_length + sizeof (ntlmv2_response);
  retc->x.str_val = (char *) final_response;

  return retc;
}
