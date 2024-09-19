/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
 */

#include "gcrypt_mac.h"

#include <gcrypt.h>
#include <stdlib.h>

#define NASL_ENCRYPT 0
#define NASL_DECRYPT 1
#define NASL_AAD 2

gcry_error_t
nasl_aes_mac_gcm (const char *data, const size_t data_len, const char *key,
                  const size_t key_len, const char *iv, const size_t iv_len,
                  char **out)
{
  gpg_err_code_t err;
  gcry_mac_hd_t hd;
  size_t result_len;

  if (!key || key_len < 1)
    return GPG_ERR_MISSING_KEY;
  if (!data || data_len < 1)
    return GPG_ERR_MISSING_VALUE;
  if (!iv || iv_len < 1)
    return GPG_ERR_GENERAL;
  if (!*out)
    {
      return GPG_ERR_GENERAL;
    }
  if ((err =
         gcry_mac_open (&hd, GCRY_MAC_GMAC_AES, GCRY_MAC_FLAG_SECURE, NULL)))
    return err;
  if ((err = gcry_mac_setkey (hd, key, key_len)))
    goto cexit;
  if ((err = gcry_mac_write (hd, data, data_len)))
    goto cexit;
  if ((err = gcry_mac_setiv (hd, iv, iv_len)))
    goto cexit;

  err = gcry_mac_read (hd, *out, &result_len);

cexit:
  gcry_mac_close (hd);
  return err;
}

unsigned int
nasl_get_aes_mac_gcm_len ()
{
  return gcry_mac_get_algo_maclen (GCRY_MAC_GMAC_AES);
}
