/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2007 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nvt_categories.h
 * @brief Category (ACT_*) definitions.
 *
 * This file contains defines for the categories of NVTs.
 * Categories influence the execution order of NVTs (e.g. NVTs with category
 * ACT_SCANNER are in principle executed first).
 */

#ifndef MISC_NVT_CATEGORIES_H
#define MISC_NVT_CATEGORIES_H

/**
 * @brief NVT 'Categories', influence execution order of NVTs.
 */
typedef enum
{
  ACT_INIT = 0,
  ACT_SCANNER,
  ACT_SETTINGS,
  ACT_GATHER_INFO,
  ACT_ATTACK,
  ACT_MIXED_ATTACK,
  ACT_DESTRUCTIVE_ATTACK,
  ACT_DENIAL,
  ACT_KILL_HOST,
  ACT_FLOOD,
  ACT_END,
} nvt_category;

#endif /* MISC_NVT_CATEGORIES_H */
