/*
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2003.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

   Modified by Preeti Subramanian <spreeti@secpod.com> for OpenVAS:
      simple packet signature function argument struct smb_basic_signing_context
      *data to uint8_t* mac_key and henceforth used mac_key in the implementation
*/

#ifndef _SMB_SIGNING_H
#define _SMB_SIGNING_H

#include "md5.h"
#include "byteorder.h"
#include "smb.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void simple_packet_signature_ntlmssp(uint8_t *mac_key, const uchar *buf, uint32 seq_number, unsigned char *calc_md5_mac);

#endif
