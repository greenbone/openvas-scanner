/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file vendorversion.h
 * @brief Header file: vendor version functions prototypes.
 */

#ifndef MISC_VENDORVERSION_H
#define MISC_VENDORVERSION_H

#include <glib.h>

const gchar *
vendor_version_get (void);

void
vendor_version_set (const gchar *);

#endif /* not MISC_VENDORVERSION_H */
