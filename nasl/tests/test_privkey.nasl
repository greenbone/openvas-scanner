# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Tests for the nasl functions pem_to_rsa and pem_to_dsa
#
# Authors:
# Bernhard Herzog <bernhard.herzog@intevation.de>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH
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

# unencrypted RSA key. GnuTLS command:
# certtool -p --outfile key-p8-rsa-unenc.pem
rsa_key_plain = string(
"-----BEGIN RSA PRIVATE KEY-----\n",
"MIICWwIBAAKBgQDZsYxvtOq/S/FIITbZyUn5lTPzos9YM1FUuh8XhfRmsiDq32d7\n",
"2swNxQwWxD7xJTLeQ+8PxU2Cj4W9Eye3L52Bfmird99Am5zRERmNIb8OaAPd6hH+\n",
"H0GnXGMI5Nnr9Z3Jz3l+lvSRnGwbSDEQiJR6jBN9+1JXQq+aQbogipwsswIDAQAB\n",
"AoGAC3ciGgwMRRD/NI5TRjsnbewMIBaAwc4fcs1EBUglLCImQQM31GUcqX5UTv/8\n",
"/1Rh48+Y0AV95JTMir3Eh2MMR4R6TOnPA6VLlXRb02XoE4Mh89uLOQKCJUQ+pn+P\n",
"fHSzLez+MWjyIaLx52uPc8eTYAysKNU0pBW0GVRgfid/G2kCQQDjjOcD8so/MS0F\n",
"sIvTroEzpysnZhyNeTD0KynGO1NmSC5L/80wm9G0PBH1fzVbL/OhiTqZP3425ytx\n",
"S7FmJdC/AkEA9OkpoiKYZ8zqx40eJqvmiSAUbSacfYx0DeOQCrgbsr04zyRFpkNl\n",
"UZBNjAkNKfHeKGeW948uBBSmQX/468EtDQJAXYOJaOj9Tszx2LW+MQc1F7oqlO10\n",
"7HsSsDWQ3GODGbSuOhNtCv3uR2isZLybe9cQA6G20EX0o7GK++uEgxslVwJAfT67\n",
"7tF4VSUDL9eoAqjINXn1WDh1sPLh6rRkVkb+yzJfWfc3syYmK0b7kVCTrc6mCM2o\n",
"86MCKk4RE9AJES9yBQJARUVBKsPK0ViAQmE+llXlaUPVWB25Dx2nyRX4hvHeYwji\n",
"eN6l16F0rOV4IvtbRsQQjhMW4OM5Z6SZ7vWmZRHTWQ==\n",
"-----END RSA PRIVATE KEY-----\n");


# encrypted RSA key. created from rsa_key_plain with openssl:
# openssl pkcs8 -topk8 -v2 des3 -in key-p8-rsa-unenc.pem -out key-p8-rsa-des.pem
rsa_key_encrypted = string(
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
"MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIxHEGjqmqAVcCAggA\n",
"MBQGCCqGSIb3DQMHBAiAGcor2rXuLgSCAoDabyOr28HQTP1DkPB4iAbHv0N1K5RP\n",
"qd51qSHBafw0oxRj0jNTjorKztClAuSW49g+t+QWKdc2h281b6sJ4E/rCHgVdUmV\n",
"zqgkvWv4l/SUL+YpyvFsX6sC30I2vHaV2HRFFxyXWEJpFuTMkFMTP3LcUYohFjZz\n",
"guYFc0I9JMW1x0E4rT0oYqfVwRE5XHeGd/u/h23RjP+teRyn+m9aVSJ6lldK6PT/\n",
"Hnlb6a30B7Or6nDukVMLiPdEHVhFzKBGHIvE5I8URk90bmSdQaS3ooY+VJbwkz8E\n",
"/TfwJA6FxUo+Fxg4Tx8Is3IK/fQG/0+AkYrceKR1GQayBRceA6P9OKoIBXQpciGG\n",
"UEt5Zt3NSn+Dfjd2QvzoawEaZJN82XJ0f1ZoX0ByHvUsK2Bn4Hc1Y6Wd/y1nNGF/\n",
"gSC0sGzJPju+U2l4LKUp853ahvnVz5FT5p+HN7sH8iTKh5QpJHRp8746pwPAD+et\n",
"p3Q3z//fONN4BY5yxZ5yoASYiE0OcTDDgr8uRR7sYv7IV+jjbJSFdpU7YaxEsvmt\n",
"GMWG6eX+cBaYFejnyHe99Ew4nyJxVcSP2QxrsE2u+qyAvjhVQ8xCf9NE43RcYP3/\n",
"VArR3UVMS77XD/eRbieVg8XvVahthoLN7dsH4Nci7+/vzk9CKGoy3tY4WZu0WjIJ\n",
"2Y2O1ajfFmbHuPV1iOp/zc/TuO5veuR/qzveJyQg5We+03L04cCU5V/cjRc3pGw4\n",
"kyV+pYZSnjhqE0Zhdmfaaz5Wh1uBVdMuudUlvq4DzXm/JZv0UqZ53cKnqmLzBdb4\n",
"TSQh8rr1f5E0HAhoKE6s0yof55ZBWXBogdYv3wFNWUmPAkEVCENzz0Jy\n",
"-----END ENCRYPTED PRIVATE KEY-----\n");


rsa_key_passphrase = "openvas";

# unencrypted DSA key.  GnuTLS command:
# certtool -p --dsa --outfile key-dsa.pem
dsa_key_plain = string(
"-----BEGIN DSA PRIVATE KEY-----\n",
"MIIBuwIBAAKBgQCnF+nY+CF9r5qROZUq9YlYZfCwaRomOdOnSEXavIjJGXzYUP2A\n",
"E1jY6NxMQnbX6X6/Rb4PWdI70U5AMoNrCJuoN4ewGIoNhp9IUn4CG3+29whK/O8B\n",
"D8qVa3MVhEwmRmMO/o5u3ldTeSYvEXNt4spoJMC952Qd9f/Wlo3j28hzlwIVAN7M\n",
"Atg6YAfOVucN1UFq0r/gmZOxAoGADItFZiNYrOKN49guGFwDhHyS/BLhwktREo1f\n",
"URuh6vuqS4DkXPjBV5VPnukDataVZMNg6T+lvsLY58Wd8dwvg9VX4LJXZs1deaAj\n",
"Dd6G4MUT7GxynyKsY3t4DQp/dzyvepXKtfhriDyY1cCiogKpfoZst399EfEL4fCe\n",
"JTzRWOMCgYEAoP35oGXR7S3vcUkanWK8TBjNgxWMG7Oq41c/zegqT2AV/BeQhdys\n",
"+NIr+hYlT9+rz3XsB4ZE0yFtsDtUv67gvFNdVERrguhabDVr0PTcCbp5CMDVHbgg\n",
"WK+DwRFP5ZP9Ippoqni7tIHIbvBlvHv0DY4rtV3cJb34H1QFe2gxg7kCFFw+Ijpz\n",
"NODP8R34Rg+lMJHVIKTn\n",
"-----END DSA PRIVATE KEY-----\n");

# encrypted DSA key.  Converted from dsa_key with openssl:
# openssl pkcs8 -topk8 -v2 des3 -in key-dsa.pem -out key-p8-dsa-des.pem
dsa_key_encrypted = string(
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
"MIIBcTAbBgkqhkiG9w0BBQMwDgQIlqMZXYtotz4CAggABIIBUB0y7YkIowaRgN1Y\n",
"7xhul6A1ZN2cAvt+W6Q8O30k524lNtQyXgA944VStpALZtV4+H1mqTtJPEAZD6Mp\n",
"fqcloF4KRd8NTIxwawRZ3aJf8LH2qZvczHSwjCK8eR8PJEaBzOrYIQS+t43bTLCx\n",
"AGebp+6YLHlyvtMy9H02CCAv/8+g3nZKiaQCuHZXsmQmk7aSsPlc5dAUvRm49KqE\n",
"drYm25R+LDQRkafUzV4HJgFInrmRLHEW7NtSTDBp8oSo/p4vMRLoqAz8d2cDus/I\n",
"Gy6+ItgFlqC3yNpuKrH38alaAn6ar2TThM51yhmzmsj7cUcir7BOmZ0mvWtUrXQo\n",
"d9EmDi7s8yGi/hiz0ewFawUHavdNe5IuoiEIpiOOxipyy8tlQIbHeLTlfsy1Y19S\n",
"pnqQmzxd6Dh49AhsBaVO7x8RQC0bxsfNUkh4ZHnB6se9elh5zA==\n",
"-----END ENCRYPTED PRIVATE KEY-----\n");

dsa_key_passphrase = string("openvas");


function test_pem_to(type, priv, passphrase, expected)
{
  local_var key;

  testcase_start(string("test_pem_to_", type));

  if (type == "rsa")
    {
      key = pem_to_rsa(priv:priv, passphrase:passphrase);
    }
  else
    {
      key = pem_to_dsa(priv:priv, passphrase:passphrase);
    }

  if (hexstr(key) == expected)
    testcase_ok();
  else
    {
      testcase_failed();
      display("key=");
      display(hexstr(key));
      display("\n");
    }
}

test_pem_to(type:"rsa", priv:rsa_key_plain, passphrase:"",
	    expected:string("0b77221a0c0c4510ff348e53463b276d",
			    "ec0c201680c1ce1f72cd440548252c22",
			    "26410337d4651ca97e544efffcff5461",
			    "e3cf98d0057de494cc8abdc487630c47",
			    "847a4ce9cf03a54b95745bd365e81383",
			    "21f3db8b39028225443ea67f8f7c74b3",
			    "2decfe3168f221a2f1e76b8f73c79360",
			    "0cac28d534a415b41954607e277f1b69"));
test_pem_to(type:"rsa", priv:rsa_key_encrypted, passphrase:rsa_key_passphrase,
	    expected:string("0b77221a0c0c4510ff348e53463b276d",
			    "ec0c201680c1ce1f72cd440548252c22",
			    "26410337d4651ca97e544efffcff5461",
			    "e3cf98d0057de494cc8abdc487630c47",
			    "847a4ce9cf03a54b95745bd365e81383",
			    "21f3db8b39028225443ea67f8f7c74b3",
			    "2decfe3168f221a2f1e76b8f73c79360",
			    "0cac28d534a415b41954607e277f1b69"));

test_pem_to(type:"dsa", priv:dsa_key_plain, passphrase:"",
	    expected:"5c3e223a7334e0cff11df8460fa53091d520a4e7");
# pkcs8 files with DSA keys are not supported yet by GnuTLS.  The
# following test should work, if it were:
#test_pem_to(type:"dsa", priv:dsa_key_encrypted, passphrase:dsa_key_passphrase,
#	    expected:"5c3e223a7334e0cff11df8460fa53091d520a4e7");
