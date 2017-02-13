/*
 Unix SMB/CIFS implementation.
 SMB parameters and setup, plus a whole lot more.

 Copyright (C) Andrew Tridgell              1992-2000
 Copyright (C) John H Terpstra              1996-2002
 Copyright (C) Luke Kenneth Casson Leighton 1996-2000
 Copyright (C) Paul Ashton                  1998-2000
 Copyright (C) Simo Sorce                   2001-2002
 Copyright (C) Martin Pool                  2002

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
    MODIFICATION: changes for OpenVAS
    1. declarations useful for OpenVAS are retained, others are removed
    2. malloc_ changes to malloc in SMB_MALLOC_P
*/

#ifndef _SMB_H
#define _SMB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include "charset.h"

#define SMB_PORT1 445
#define SMB_PORT2 139
#define SMB_PORTS "445 139"

/* offsets into message for common items */
#define smb_com 8
#define smb_rcls 9
#define smb_reh 10
#define smb_err 11
#define smb_flg 13
#define smb_flg2 14
#define smb_pidhigh 16
#define smb_ss_field 18
#define smb_tid 28
#define smb_pid 30
#define smb_uid 32
#define smb_mid 34
#define smb_wct 36
#define smb_vwv 37
#define smb_vwv0 37
#define smb_vwv1 39
#define smb_vwv2 41
#define smb_vwv3 43
#define smb_vwv4 45
#define smb_vwv5 47
#define smb_vwv6 49
#define smb_vwv7 51
#define smb_vwv8 53
#define smb_vwv9 55
#define smb_vwv10 57
#define smb_vwv11 59
#define smb_vwv12 61
#define smb_vwv13 63
#define smb_vwv14 65
#define smb_vwv15 67
#define smb_vwv16 69
#define smb_vwv17 71

/* generic iconv conversion structure */
typedef struct _smb_iconv_t {
        size_t (*direct)(void *cd, const char **inbuf, size_t *inbytesleft,
                         char **outbuf, size_t *outbytesleft);
        size_t (*pull)(void *cd, const char **inbuf, size_t *inbytesleft,
                       char **outbuf, size_t *outbytesleft);
        size_t (*push)(void *cd, const char **inbuf, size_t *inbytesleft,
                       char **outbuf, size_t *outbytesleft);
        void *cd_direct, *cd_pull, *cd_push;
        char *from_name, *to_name;
} *smb_iconv_t;

/* string manipulation flags - see clistr.c and srvstr.c */
#define STR_TERMINATE 1
#define STR_UPPER 2
#define STR_ASCII 4
#define STR_UNICODE 8
#define STR_NOALIGN 16
#define STR_TERMINATE_ASCII 128

/* Sercurity mode bits. */
#define NEGOTIATE_SECURITY_USER_LEVEL		0x01
#define NEGOTIATE_SECURITY_CHALLENGE_RESPONSE	0x02
#define NEGOTIATE_SECURITY_SIGNATURES_ENABLED	0x04
#define NEGOTIATE_SECURITY_SIGNATURES_REQUIRED	0x08

/* NT Flags2 bits - cifs6.txt section 3.1.2 */

#define FLAGS2_LONG_PATH_COMPONENTS    0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES     0x0002
#define FLAGS2_SMB_SECURITY_SIGNATURES 0x0004
#define FLAGS2_UNKNOWN_BIT4            0x0010
#define FLAGS2_IS_LONG_NAME            0x0040
#define FLAGS2_EXTENDED_SECURITY       0x0800
#define FLAGS2_DFS_PATHNAMES           0x1000
#define FLAGS2_READ_PERMIT_EXECUTE     0x2000
#define FLAGS2_32_BIT_ERROR_CODES      0x4000
#define FLAGS2_UNICODE_STRINGS         0x8000

#define FLAGS2_WIN2K_SIGNATURE         0xC852 /* Hack alert ! For now... JRA. */

/* TCONX Flag (smb_vwv2). */
#define TCONX_FLAG_EXTENDED_RESPONSE	0x8

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE         0x0001
#define CAP_MPX_MODE         0x0002
#define CAP_UNICODE          0x0004
#define CAP_LARGE_FILES      0x0008
#define CAP_NT_SMBS          0x0010
#define CAP_RPC_REMOTE_APIS  0x0020
#define CAP_STATUS32         0x0040
#define CAP_LEVEL_II_OPLOCKS 0x0080
#define CAP_LOCK_AND_READ    0x0100
#define CAP_NT_FIND          0x0200
#define CAP_DFS              0x1000
#define CAP_W2K_SMBS         0x2000
#define CAP_LARGE_READX      0x4000
#define CAP_LARGE_WRITEX     0x8000
#define CAP_UNIX             0x800000 /* Capabilities for UNIX extensions. Created by HP. */
#define CAP_EXTENDED_SECURITY 0x80000000

/* protocol types. It assumes that higher protocols include lower protocols
 *    as subsets */
enum protocol_types {PROTOCOL_NONE,PROTOCOL_CORE,PROTOCOL_COREPLUS,PROTOCOL_LANMAN1,PROTOCOL_LANMAN2,PROTOCOL_NT1};

#ifdef WORDS_BIGENDIAN
#define UCS2_SHIFT 8
#else
#define UCS2_SHIFT 0
#endif

/* turn a 7 bit character into a ucs2 character */
#define UCS2_CHAR(c) ((c) << UCS2_SHIFT)

/* return an ascii version of a ucs2 character */
#define UCS2_TO_CHAR(c) (((c) >> UCS2_SHIFT) & 0xff)

/* Copy into a smb_ucs2_tt from a possibly unaligned buffer. Return the copied smb_ucs2_tt */
#define COPY_UCS2_CHAR(dest,src) (((unsigned char *)(dest))[0] = ((unsigned char *)(src))[0],\
				((unsigned char *)(dest))[1] = ((unsigned char *)(src))[1], (dest))

/* 64 bit time (100 nanosec) 1601 - cifs6.txt, section 3.5, page 30, 4 byte aligned */
typedef uint64_t NTTIME;

/*-------------------taken from samba's smb_macros.h-------------------------------*/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

#define SMB_MALLOC_P(type) (type *)malloc(sizeof(type))

#define SMB_REALLOC(p,s) Realloc((p),(s),True)  /* Always frees p on error or s == 0 */
#ifndef SMB_MALLOC
#define SMB_MALLOC(s) malloc(s)
#endif

#define SMB_STRDUP(s) strdup(s)
#define SMB_STRNDUP(s,n) strndup(s,n)

#define smb_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|((PVAL(buf,1)&1)<<16))

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
/*---------------------------------------------------------------------------------*/

#endif /* _SMB_H */
