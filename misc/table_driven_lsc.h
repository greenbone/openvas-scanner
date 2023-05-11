/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file table_drive_lsc.h
 * @brief Header file for module table_driven_lsc.
 */

#ifndef MISC_TABLE_DRIVEN_LSC_H
#define MISC_TABLE_DRIVEN_LSC_H

#include <glib.h>

gchar *
make_table_driven_lsc_info_json_str (const char *, const char *, const char *,
                                     const char *, const char *);

gchar *
get_status_of_table_driven_lsc_from_json (const char *, const char *,
                                          const char *, int);

#endif // MISC_TABLE_DRIVEN_LSC_H
