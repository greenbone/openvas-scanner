/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2005 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __LIB_NASL_H__
#define __LIB_NASL_H__

/**
 * @mainpage
 *
 * @section installation Overview and installation instructions
 * @verbinclude README
 *
 * @section copying License Information
 * @verbinclude COPYING
 */

#include <glib.h>

#include "../misc/arglists.h"           /* for struct arglist */

/* Signature information extraction and verification (not nasl- specific
  anymore, thus likely to be moved to openvas-libraries): */
int nasl_verify_signature (const char *filename);
char *nasl_extract_signature_fprs (const char *filename);
GSList *nasl_get_all_certificates (void);
/* End of Signature information extraction */

int add_nasl_inc_dir (const char *);

int
exec_nasl_script (struct arglist *, const char *, const char *, int);
int
execute_preparsed_nasl_script (struct arglist *, char *, char *, int, int);
char *
nasl_version (void);
pid_t
nasl_server_start (char *, char *);
void
nasl_server_recompile (char *, char *);

/* exec_nasl_script modes */
#define NASL_EXEC_DESCR			   (1 << 0)
#define NASL_EXEC_PARSE_ONLY		   (1 << 1)
#define NASL_ALWAYS_SIGNED		   (1 << 2)
#define NASL_COMMAND_LINE		   (1 << 3)
#define NASL_LINT			   (1 << 4)


#define NASL_ERR_NOERR		0
#define NASL_ERR_ETIMEDOUT 	1
#define NASL_ERR_ECONNRESET	2
#define NASL_ERR_EUNREACH	3
#define NASL_ERR_EUNKNOWN	99
#endif
