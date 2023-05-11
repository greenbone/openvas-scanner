/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2005 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_H
#define NASL_H

#include "../misc/scanneraux.h"

#include <glib.h>

/* Signature information extraction and verification (not nasl- specific
  anymore, thus likely to be moved to openvas-libraries): */
int
nasl_verify_signature (const char *filename);

char *
nasl_extract_signature_fprs (const char *filename);

GSList *
nasl_get_all_certificates (void);
/* End of Signature information extraction */

int
add_nasl_inc_dir (const char *);

void
nasl_clean_inc (void);

int
exec_nasl_script (struct script_infos *, int);

char *
nasl_version (void);

pid_t
nasl_server_start (char *, char *);

void
nasl_server_recompile (char *, char *);

/* exec_nasl_script modes */
#define NASL_EXEC_DESCR (1 << 0)
#define NASL_EXEC_PARSE_ONLY (1 << 1)
#define NASL_ALWAYS_SIGNED (1 << 2)
#define NASL_COMMAND_LINE (1 << 3)
#define NASL_LINT (1 << 4)

#define NASL_ERR_NOERR 0
#define NASL_ERR_ETIMEDOUT 1
#define NASL_ERR_ECONNRESET 2
#define NASL_ERR_EUNREACH 3
#define NASL_ERR_EUNKNOWN 99
#endif
