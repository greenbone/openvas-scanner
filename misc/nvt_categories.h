/* Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
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
 * @file nvt_categories.h
 * @brief Category (ACT_*) definitions.
 *
 * This file contains defines for the categories of NVTs.
 * Categories influence the execution order of NVTs (e.g. NVTs with category
 * ACT_SCANNER are in principle executed first).
 */

#ifndef _NVT_CATEGORIES_H
#define _NVT_CATEGORIES_H

/**
 * @brief NVT 'Categories', influence execution order of NVTs.
 *
 * @todo Consider creation of an enumeration.
 */

/** Last plugins actions type. */
#define ACT_LAST                ACT_END
/** First plugins actions type. */
#define ACT_FIRST               ACT_INIT

#define ACT_UNKNOWN             11
#define ACT_END                 10
#define ACT_FLOOD               9
#define ACT_KILL_HOST           8
#define ACT_DENIAL              7
#define ACT_DESTRUCTIVE_ATTACK  6
#define ACT_MIXED_ATTACK        5
#define ACT_ATTACK              4
#define ACT_GATHER_INFO         3
#define ACT_SETTINGS            2
#define ACT_SCANNER             1
#define ACT_INIT                0

#endif /* _NVT_CATEGORIES_H */
