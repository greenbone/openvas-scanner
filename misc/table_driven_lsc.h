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
#include <gvm/util/kb.h> // for kb_t

void
set_lsc_flag (void);

int
lsc_has_run (void);

int
run_table_driven_lsc (const char *, const char *, const char *, const char *,
                      const char *);

#endif // MISC_TABLE_DRIVEN_LSC_H
