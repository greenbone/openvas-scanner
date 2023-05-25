/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file heartbeat.h
 * @brief heartbeat.c headerfile.
 */

#ifndef OPENVAS_HEARTBEAT_H
#define OPENVAS_HEARTBEAT_H

#include "../misc/scanneraux.h"

int
check_host_still_alive (kb_t, const char *);
#endif
