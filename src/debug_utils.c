/* Portions Copyright (C) 2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file debug_utils.c
 * @brief Initialize sentry
 */

#include "debug_utils.h"

#include <gvm/base/logging.h>
#include <stdio.h> /* for snprintf */
#include <stdlib.h>

int
init_sentry (void)
{
  char *sentry_dsn_openvas = NULL;
  char version[96];

  snprintf (version, sizeof (version), "openvas@%s", OPENVAS_VERSION);

  sentry_dsn_openvas = getenv ("SENTRY_DSN_OPENVAS");
  if (gvm_has_sentry_support () && sentry_dsn_openvas && *sentry_dsn_openvas)
    {
      gvm_sentry_init (sentry_dsn_openvas, version);
      return 1;
    }
  return 0;
}
