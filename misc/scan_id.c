/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "scan_id.h"

#include <stdlib.h>

const char *scan_id = NULL;

int
set_scan_id (const char *new_scan_id)
{
  if (scan_id != NULL)
    return -1;
  scan_id = new_scan_id;
  return 0;
}

const char *
get_scan_id ()
{
  return scan_id;
}
