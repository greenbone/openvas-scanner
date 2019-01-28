/* Copyright (C) Andrew Tridgell 2004
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
 * @file iconv.h
 * @brief Unix SMB/CIFS implementation. iconv memory system include wrappers
 */

#ifndef _system_iconv_h
#define _system_iconv_h

#if !defined(HAVE_ICONV) && defined(HAVE_ICONV_H)
#define HAVE_ICONV
#endif

#if !defined(HAVE_GICONV) && defined(HAVE_GICONV_H)
#define HAVE_GICONV
#endif

#if !defined(HAVE_BICONV) && defined(HAVE_BICONV_H)
#define HAVE_BICONV
#endif

#ifdef HAVE_NATIVE_ICONV
#if defined(HAVE_ICONV)
#include <iconv.h>
#elif defined(HAVE_GICONV)
#include <giconv.h>
#elif defined(HAVE_BICONV)
#include <biconv.h>
#endif
#endif /* HAVE_NATIVE_ICONV */

/* needed for some systems without iconv. Doesn't really matter
   what error code we use */
#ifndef EILSEQ
#define EILSEQ EIO
#endif

#endif
