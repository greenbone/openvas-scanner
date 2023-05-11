/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2007 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file kb_cache.h
 * @brief Header file to cache main_kb.
 */

#ifndef MISC_KB_CACHE_H
#define MISC_KB_CACHE_H
#include <gvm/util/kb.h>

void set_main_kb (kb_t);
kb_t
get_main_kb (void);

#endif
