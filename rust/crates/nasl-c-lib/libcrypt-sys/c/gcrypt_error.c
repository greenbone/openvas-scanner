/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
 */

#include "gcrypt_error.h"

#include <gcrypt.h>

const char *
gcrypt_strerror (gcry_error_t err)
{
  return gcry_strerror (err);
}
