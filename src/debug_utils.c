/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file debug_utils.c
 * @brief Initialize sentry
 */

#include "debug_utils.h"

#include <gvm/base/logging.h>
#include <stdio.h> /* for snprintf */
#include <stdlib.h>

/**
 * @brief Init sentry.
 *
 * @return 0 on success, -1 on error.
 */
int
init_sentry (void)
{
  char *sentry_dsn_openvas = NULL;
  char version[96];

  snprintf (version, sizeof (version), "openvas@%s", OPENVAS_VERSION);

  sentry_dsn_openvas = getenv ("SENTRY_DSN_OPENVAS");
  if (FALSE
      == (gvm_has_sentry_support () && sentry_dsn_openvas
          && *sentry_dsn_openvas))
    {
      return -1;
    }
  else
    {
      gvm_sentry_init (sentry_dsn_openvas, version);
      return 0;
    }
}
