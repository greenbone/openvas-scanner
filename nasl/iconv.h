/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2004 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file iconv.h
 * @brief Unix SMB/CIFS implementation. iconv memory system include wrappers
 */

#ifndef NASL_ICONV_H
#define NASL_ICONV_H

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
