/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file file_utils.h
 * @brief file_utils.c headerfile.
 */

#ifndef MISC_FILE_UTILS_H
#define MISC_FILE_UTILS_H

#include <glib.h>
#include <sys/types.h>

int
file_utils_init (const char *id);

const char *
file_utils_get_dir (void);

gchar *
file_utils_hash (const char *value);

void
file_utils_delete_matching (const char *pattern);

void
file_utils_cleanup (void);

#endif /* MISC_FILE_UTILS_H */
