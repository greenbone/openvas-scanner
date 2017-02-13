/*
   Unix SMB/CIFS implementation.

   Functions to create reasonable random numbers for crypto use.

   Copyright (C) Jeremy Allison 2001

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
*/

/*
   Modified for OpenVAS by Preeti Subramanian <spreeti@secpod.com>
   MODIFICATION: This file has only those functions that cater to the
   requirements of OpenVAS, remaining functions are removed
                  * BOOL is changed to bool
                  * sys_open is changed to open
                  * sys_getpid is changed to getpid
                  * In do_reseed function, adding secret file contents of smb
                    passwd file not required(removed) and add in the root encrypted
                    password note required(removed)
*/
#include <pwd.h>
#include <unistd.h>
#include "byteorder.h"
#include "smb.h"
#include <time.h>
#include "md4.h"
#include "proto.h"
#ifndef HAVE_UCBINCLUDE
#include <fcntl.h>
#else
/* Solaris */
#include "/usr/ucbinclude/fcntl.h"
#endif

#ifndef uint32
#define uint32 uint32_t
#endif

typedef unsigned int bool;
#define False 0
#define True 1

static unsigned char smb_arc4_state[258];
static uint32 counter;

/**
 * @file
 * @brief Random number generation
 */

/* zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

static bool done_reseed_ntlmssp = False;
static void (*reseed_callback_ntlmssp)(int *newseed);

/****************************************************************
 Copy any user given reseed data.
*****************************************************************/

static void get_rand_reseed_data_ntlmssp(int *reseed_data)
{
	if (reseed_callback_ntlmssp) {
		reseed_callback_ntlmssp(reseed_data);
	} else {
		*reseed_data = 0;
	}
}

/****************************************************************
 Get a 16 byte hash from the contents of a file.
 Note that the hash is not initialised.
*****************************************************************/

static void do_filehash_ntlmssp(const char *fname, unsigned char *the_hash)
{
	unsigned char buf[1011]; /* deliberate weird size */
	unsigned char tmp_md4[16];
	int fd, n;

	fd = open(fname,O_RDONLY,0);
	if (fd == -1)
		return;

	while ((n = read(fd, (char *)buf, sizeof(buf))) > 0) {
		mdfour_ntlmssp(tmp_md4, buf, n);
		for (n=0;n<16;n++)
			the_hash[n] ^= tmp_md4[n];
	}
	close(fd);
}

/**************************************************************
 Try and get a good random number seed. Try a number of
 different factors. Firstly, try /dev/urandom - use if exists.

 We use /dev/urandom as a read of /dev/random can block if
 the entropy pool dries up. This leads clients to timeout
 or be very slow on connect.

 If we can't use /dev/urandom then seed the stream random generator
 above...
**************************************************************/

static int do_reseed_ntlmssp(bool use_fd, int fd)
{
	unsigned char seed_inbuf[40];
	uint32 v1, v2; struct timeval tval; pid_t mypid;
	int reseed_data = 0;

	if (use_fd) {
		if (fd != -1)
			return fd;
		fd = open( "/dev/urandom", O_RDONLY,0);
		if(fd >= 0)
			return fd;
	}

	/* Add in some secret file contents */

	do_filehash_ntlmssp("/etc/shadow", &seed_inbuf[0]);
	/*
	 * Add the counter, time of day, and pid.
	 */

	GetTimeOfDay_ntlmssp(&tval);
	mypid = getpid();
	v1 = (counter++) + mypid + tval.tv_sec;
	v2 = (counter++) * mypid + tval.tv_usec;

	SIVAL(seed_inbuf, 32, v1 ^ IVAL(seed_inbuf, 32));
	SIVAL(seed_inbuf, 36, v2 ^ IVAL(seed_inbuf, 36));

	/*
	 * Add any user-given reseed data.
	 */

	get_rand_reseed_data_ntlmssp(&reseed_data);
	if (reseed_data) {
		size_t i;
		for (i = 0; i < sizeof(seed_inbuf); i++)
			seed_inbuf[i] ^= ((char *)(&reseed_data))[i % sizeof(reseed_data)];
	}

	smb_arc4_init_ntlmssp(smb_arc4_state, seed_inbuf, sizeof(seed_inbuf));

	return -1;
}

/*******************************************************************
 Interface to the (hopefully) good crypto random number generator.
********************************************************************/

void generate_random_buffer_ntlmssp( unsigned char *out, int len)
{
	static int urand_fd = -1;
	unsigned char md4_buf[64];
	unsigned char tmp_buf[16];
	unsigned char *p;

	if(!done_reseed_ntlmssp) {
		urand_fd = do_reseed_ntlmssp(True, urand_fd);
		done_reseed_ntlmssp = True;
	}

	if (urand_fd != -1 && len > 0) {

		if (read(urand_fd, out, len) == len)
			return; /* len bytes of random data read from urandom. */

		/* Read of urand error, drop back to non urand method. */
		close(urand_fd);
		urand_fd = -1;
		do_reseed_ntlmssp(False, -1);
		done_reseed_ntlmssp = True;
	}

	/*
	 * Generate random numbers in chunks of 64 bytes,
	 * then md4 them & copy to the output buffer.
	 * This way the raw state of the stream is never externally
	 * seen.
	 */

	p = out;
	while(len > 0) {
		int copy_len = len > 16 ? 16 : len;

		smb_arc4_crypt_ntlmssp(smb_arc4_state, md4_buf, sizeof(md4_buf));
		mdfour_ntlmssp(tmp_buf, md4_buf, sizeof(md4_buf));
		memcpy(p, tmp_buf, copy_len);
		p += copy_len;
		len -= copy_len;
	}
}
