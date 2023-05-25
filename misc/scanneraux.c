/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file scanneraux.c
 * @brief Auxiliary functions and structures for scanner.
 */

#include "scanneraux.h"

void
destroy_scan_globals (struct scan_globals *globals)
{
  if (globals == NULL)
    return;

  g_free (globals->scan_id);

  if (globals->files_translation)
    g_hash_table_destroy (globals->files_translation);

  if (globals->files_size_translation)
    g_hash_table_destroy (globals->files_size_translation);

  g_free (globals);
  globals = NULL;
}
