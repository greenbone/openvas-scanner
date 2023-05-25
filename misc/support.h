/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file support.h
 * @brief Support macros for special platforms.
 */

#ifndef MISC_SUPPORT_H
#define MISC_SUPPORT_H

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

#endif /* not MISC_SUPPORT_H */
