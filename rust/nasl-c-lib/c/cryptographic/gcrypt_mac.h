/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
 */

#ifndef NASL_GCRYPT_MAC_H
#define NASL_GCRYPT_MAC_H

#include <gcrypt.h>
#include <stdlib.h>

/**
 * @brief
 *
 * @param data
 * @param data_len
 * @param key
 * @param key_len
 * @param iv
 * @param iv_len
 * @param out
 * @return int
 */
gcry_error_t
nasl_aes_mac_gcm (const char *data, const size_t data_len, const char *key,
                  const size_t key_len, const char *iv, const size_t iv_len,
                  char **out);

/**
 * @brief Get the aes mac gcm len object
 *
 * @return unsigned int
 */
unsigned int
nasl_get_aes_mac_gcm_len ();

#endif
