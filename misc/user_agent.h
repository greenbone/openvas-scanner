/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file user_agent.h
 * @brief Header file: user agent functions prototypes.
 */

#ifndef MISC_USERAGENT_H
#define MISC_USERAGENT_H

#include "ipc.h"

#include <glib.h>

int
user_agent_get (struct ipc_context *, char **);

gchar *
user_agent_set (const gchar *);

#endif /* not MISC_USERAGENT_H */
