/* Copyright (C) 2009-2021 Greenbone Networks GmbH
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
 * @file nvt_qod_types.h
 * @brief QOD_TYPES definitions.
 *
 * This file contains defines for the QoD types of NVTs.
 */

#ifndef _NVT_QOD_H
#define _NVT_QOD_H

typedef enum
{
  EXPLOIT = 100,
  REMOTE_VUL = 99,
  REMOTE_APP = 98,
  PACKAGE = 97,
  REGISTRY = 97,
  REMOTE_ACTIVE = 95,
  REMOTE_BANNER = 80,
  EXECUTABLE_VERSION = 80,
  REMOTE_ANALYSIS = 70,
  REMOTE_PROBE = 50,
  REMOTE_BANNER_UNRELIABLE = 30,
  EXECUTABLE_VERSION_UNRELIABLE = 30,
  GENERAL_NOTE = 1,
  DEFAULT = 70,
} qod_val;

int
qod_type2val (const char *);

#endif /* _NVT_QOD_H */
