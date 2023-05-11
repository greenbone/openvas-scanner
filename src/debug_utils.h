/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file debug_utils.h
 * @brief debug_utils.c headerfile.
 */

#ifndef OPENVAS_DEBUG_UTILS_H
#define OPENVAS_DEBUG_UTILS_H

#include <gvm/base/gvm_sentry.h> /* for gvm_sentry_init */

int
init_sentry (void);

#endif
