/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NASL_NASL_SIGNATURE_H
#define NASL_NASL_SIGNATURE_H

#include <stddef.h>

int
nasl_verify_signature (const char *, const char *, size_t);

#endif
