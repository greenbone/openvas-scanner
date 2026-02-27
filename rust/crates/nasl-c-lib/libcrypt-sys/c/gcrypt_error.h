/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
 */

#ifndef NASL_GCRYPT_ERROR_H
#define NASL_GCRYPT_ERROR_H

#include <gcrypt.h>

const char *
gcrypt_strerror (gcry_error_t err);

#endif
