/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1997-1998 Andrew Tridgell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file md4.h
 * @brief Unix SMB/CIFS implementation.
 *
 * A implementation of MD4 designed for use in the SMB authentication protocol
 */
#ifndef NASL_MD4_H
#define NASL_MD4_H

void
mdfour_ntlmssp (unsigned char *out, const unsigned char *in, int n);

#endif