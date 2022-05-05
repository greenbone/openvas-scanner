/* Copyright (C) 2009-2022 Greenbone Networks GmbH
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
 * @file support.h
 * @brief Support macros for special platforms.
 */

#ifndef _OPENVAS_MISC_SUPPORT_H
#define _OPENVAS_MISC_SUPPORT_H

// This structure does not exist on MacOS or FreeBSD systems
#ifndef s6_addr32
#if defined(__APPLE__) || defined(__FreeBSD__)
#define s6_addr32 __u6_addr.__u6_addr32
#endif // __APPLE__ || __FreeBSD__
#endif // !s6_addr32

// Add backward compatibility for systems with older glib version
// which still support g_memdup
#include <glib.h>
// TODO: Remove once our reference system supports g_memdup2
#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION < 68
#define g_memdup2 g_memdup
#endif
// TODO: Remove once our reference system supports g_pattern_spec_match_string
#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION < 70
#define g_pattern_spec_match_string g_pattern_match_string
#endif

#endif /* not _OPENVAS_MISC_SUPPORT_H */
