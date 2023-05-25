/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2005 Jeremy Allison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "proto.h"

#include <stdlib.h>
/*****************************************************************
 Initialize state for an arc4 crypt/decrpyt.
 arc4 state is 258 bytes - last 2 bytes are the index bytes.
*****************************************************************/

void
smb_arc4_init_ntlmssp (unsigned char arc4_state_out[258],
                       const unsigned char *key, size_t keylen)
{
  size_t ind;
  unsigned char j = 0;

  for (ind = 0; ind < 256; ind++)
    {
      arc4_state_out[ind] = (unsigned char) ind;
    }

  for (ind = 0; ind < 256; ind++)
    {
      unsigned char tc;

      j += (arc4_state_out[ind] + key[ind % keylen]);

      tc = arc4_state_out[ind];
      arc4_state_out[ind] = arc4_state_out[j];
      arc4_state_out[j] = tc;
    }
  arc4_state_out[256] = 0;
  arc4_state_out[257] = 0;
}

/*****************************************************************
 Do the arc4 crypt/decrpyt.
 arc4 state is 258 bytes - last 2 bytes are the index bytes.
*****************************************************************/

void
smb_arc4_crypt_ntlmssp (unsigned char arc4_state_inout[258],
                        unsigned char *data, size_t len)
{
  unsigned char index_i = arc4_state_inout[256];
  unsigned char index_j = arc4_state_inout[257];
  size_t ind;

  for (ind = 0; ind < len; ind++)
    {
      unsigned char tc;
      unsigned char t;

      index_i++;
      index_j += arc4_state_inout[index_i];

      tc = arc4_state_inout[index_i];
      arc4_state_inout[index_i] = arc4_state_inout[index_j];
      arc4_state_inout[index_j] = tc;

      t = arc4_state_inout[index_i] + arc4_state_inout[index_j];
      data[ind] = data[ind] ^ arc4_state_inout[t];
    }

  arc4_state_inout[256] = index_i;
  arc4_state_inout[257] = index_j;
}
