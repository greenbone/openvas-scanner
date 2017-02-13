# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Tests for the nasl functions bf_cbc_encrypt and bf_cbc_decrypt
#
# Authors:
# Bernhard Herzog <bernhard.herzog@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

function test_bf_cbc_encrypt(key, iv, data, expected_enc, expected_iv,
			     variant)
{
  local_var enc;

  testcase_start("test_bf_cbc_encrypt " + variant);

  enc = bf_cbc_encrypt(key:key, iv:iv, data:data);
  if (enc[0] == expected_enc && hexstr(enc[1]) == expected_iv)
    {
      testcase_ok();
    }
  else
    {
      testcase_failed();
      display(strcat("enc[0]=", hexstr(enc[0]), string("\n")));
      display(strcat("enc[1]=", hexstr(enc[1]), string("\n")));
    }
}

function test_bf_cbc_decrypt(key, iv, data, expected_dec, expected_iv)
{
  local_var dec;
  testcase_start("test_bf_cbc_decrypt");

  dec = bf_cbc_decrypt(key:key, iv:iv, data:data);
  if (dec[0] == expected_dec && hexstr(dec[1]) == expected_iv)
    {
      testcase_ok();
    }
  else
    {
      testcase_failed();
      display(strcat("dec[0]=", hexstr(dec[0]), string("\n")));
      display(strcat("dec[1]=", hexstr(dec[1]), string("\n")));
    }
}

clear_text = "abcdefghijklmnopabcdefghijklmnop";
cipher_text = raw_string(0xf5, 0xd5, 0x88, 0x8e, 0x81, 0x40, 0xda, 0x9f,
			 0x48, 0x50, 0x89, 0x87, 0xad, 0x45, 0x9e, 0x8f,
			 0x1c, 0xe0, 0x1f, 0x0b, 0x0d, 0x7d, 0x68, 0x31,
			 0x09, 0x44, 0xab, 0x3b, 0x17, 0x9d, 0x18, 0x15);

test_bf_cbc_encrypt(variant:"standard lengths",
		    key:"0123456789abcdef", iv:"00000000",
		    data:clear_text,
		    expected_enc:cipher_text,
		    expected_iv:"0944ab3b179d1815");
test_bf_cbc_decrypt(key:"0123456789abcdef", iv:"00000000",
		    data:cipher_text,
		    expected_dec:clear_text,
		    expected_iv:"0944ab3b179d1815");
test_bf_cbc_encrypt(variant:"long key and iv",
		    key:raw_string(0x74, 0x39, 0xbf, 0x6a, 0x61, 0x99, 0xe2,
				   0x1b, 0xd4, 0xa3, 0x53, 0xcc, 0x55, 0x11,
				   0x26, 0x55, 0xc5, 0x80, 0x03, 0xbb),
		    iv:raw_string(0x28, 0x42, 0x42, 0x36, 0xfb, 0x93, 0xa2,
				  0x4a, 0x59, 0x67, 0x74, 0xfc, 0x78, 0xf7,
				  0xb6, 0xcf, 0xad, 0x3e, 0xb7, 0x60),
		    data:raw_string(0x00, 0x00, 0x00, 0x1c, 0x0a, 0x05, 0x00,
				    0x00, 0x00, 0x0c, 0x73, 0x73, 0x68, 0x2d,
				    0x75, 0x73, 0x65, 0x72, 0x61, 0x75, 0x74,
				    0x68, 0x29, 0xf8, 0xaa, 0x18, 0xcf, 0x29,
				    0xa3, 0x39, 0x10, 0x65),
		    expected_enc:raw_string(0x56, 0x0e, 0x45, 0x31, 0x14, 0x5c,
					    0xfe, 0x93, 0x66, 0x3a, 0xcd, 0x3a,
					    0x5f, 0x2b, 0xc9, 0xac, 0x22, 0xa0,
					    0x52, 0xb3, 0xec, 0xc6, 0x90, 0x6e,
					    0xb0, 0x8b, 0xeb, 0x69, 0xcf, 0xaa,
					    0x78, 0x42),
		    expected_iv:"b08beb69cfaa7842");
