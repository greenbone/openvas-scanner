/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file attack.h
 * @brief attack.c header.
 */

#ifndef OPENVAS_ATTACK_H
#define OPENVAS_ATTACK_H

#include "../misc/scanneraux.h"

#include <gvm/util/kb.h>

void
attack_network (struct scan_globals *);

#endif
