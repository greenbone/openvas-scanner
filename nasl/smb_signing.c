/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2003 Jeremy Allison
 * SPDX-FileCopyrightText: 2002-2003 Andrew Bartlett <abartlet@samba.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file smb_signing.c
 * @brief Unix SMB/CIFS implementation.  SMB Signing Code
 */

/*
   Modified by Preeti Subramanian <spreeti@secpod.com> for OpenVAS:
      simple packet signature function argument struct smb_basic_signing_context
      *data to uint8_t* mac_key and henceforth used mac_key in the
   implementation
*/

#include "smb_signing.h"

void
simple_packet_signature_ntlmssp (uint8_t *mac_key, const uchar *buf,
                                 uint32 seq_number, unsigned char *calc_md5_mac)
{
  const size_t offset_end_of_sig = (smb_ss_field + 8);
  unsigned char sequence_buf[8];
  struct MD5Context md5_ctx;

  /*
   * Firstly put the sequence number into the first 4 bytes.
   * and zero out the next 4 bytes.
   *
   * We do this here, to avoid modifying the packet.
   */

  SIVAL (sequence_buf, 0, seq_number);
  SIVAL (sequence_buf, 4, 0);

  /* Calculate the 16 byte MAC - but don't alter the data in the
     incoming packet.

     This makes for a bit of fussing about, but it's not too bad.
  */
  MD5Init (&md5_ctx);

  /* initialise with the key */
  MD5Update (&md5_ctx, mac_key, 16);

  /* copy in the first bit of the SMB header */
  MD5Update (&md5_ctx, buf + 4, smb_ss_field - 4);

  /* copy in the sequence number, instead of the signature */
  MD5Update (&md5_ctx, sequence_buf, sizeof (sequence_buf));

  /* copy in the rest of the packet in, skipping the signature */
  MD5Update (&md5_ctx, buf + offset_end_of_sig,
             smb_len (buf) - (offset_end_of_sig - 4));

  /* calculate the MD5 sig */
  MD5Final (calc_md5_mac, &md5_ctx);
}
