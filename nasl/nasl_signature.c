/* OpenVAS-LibNASL
 *
 * Authors:
 * Bernhard Herzog <bernhard.herzog@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>             /* for strlen */
#include <locale.h>             /* for LC_CTYPE  */

#include <gvm/util/gpgmeutils.h>

#include "nasl_tree.h"
#include "nasl_var.h"
#include "nasl_func.h"
#include "nasl_lex_ctxt.h"
#include "nasl_debug.h"

/**
 * @brief Prints an error message for errors returned by gpgme.
 *
 * @param function Calling function name (debug info).
 * @param err The gpgme error that caused the problem.
 */
static void
print_gpgme_error (char *function, gpgme_error_t err)
{
  nasl_perror (NULL, "%s failed: %s/%s\n", function, gpgme_strsource (err),
               gpgme_strerror (err));
}

/**
 * @brief Checks whether the signature verification result contains at least one
 * @brief signature and whether all signatures are fully valid.
 *
 * The function returns 1 if all signatures are fully valid and 0 otherwise.
 *
 * @param result The verification result to examine.
 *
 * @return 1 if signatures found and all are fully valid, 0 otherwise.
 */
static int
examine_signatures (gpgme_verify_result_t result)
{
  int num_sigs = 0;
  int num_valid = 0;
  gpgme_signature_t sig;

  nasl_trace (NULL, "examine_signatures\n");

  sig = result->signatures;
  while (sig)
    {
      num_sigs += 1;

      if (nasl_trace_enabled ())
        {
          nasl_trace (NULL, "examine_signatures: signature #%d:\n", num_sigs);
          nasl_trace (NULL, "examine_signatures:    summary: %d\n",
                      sig->summary);
          nasl_trace (NULL, "examine_signatures:    validity: %d\n",
                      sig->validity);
          nasl_trace (NULL, "examine_signatures:    status: %s\n",
                      gpg_strerror (sig->status));
          nasl_trace (NULL, "examine_signatures:    timestamp: %ld\n",
                      sig->timestamp);
          nasl_trace (NULL, "examine_signatures:    exp_timestamp: %ld\n",
                      sig->exp_timestamp);
          nasl_trace (NULL, "examine_signatures:    fpr: %s\n", sig->fpr);
        }

      if (sig->summary & GPGME_SIGSUM_VALID)
        {
          nasl_trace (NULL, "examine_signatures: signature is valid\n");
          num_valid += 1;
        }
      else
        {
          nasl_trace (NULL, "examine_signatures: signature is invalid\n");
          /** @todo Early stop might be possible. Can return here. */
        }
      sig = sig->next;
    }

  return num_sigs > 0 && num_sigs == num_valid;
}


/**
 * Checks the detached OpenPGP signature of the file given by FILENAME.
 * The name of the signature file is derived from FILENAME by appending
 * ".asc".
 *
 * If a signature file exists and it contains only fully valid
 * signatures, the function returns 0.  If any of the signatures is not
 * valid or was made by an unknown or untrusted key, the function
 * returns 1.  If an error occurs or the file does not have a
 * corresponding detached signature the function returns -1.
 *
 * @param filename Filename (e.g. 1.txt) for which to check signature (e.g.
                   1.txt.asc).
 *
 * @return Zero, if files exists and all signatures are fully trusted. 1 if at
 *         least one signature from invalid or untrusted key. -1 on missing file
 *         or error.
 */
int
nasl_verify_signature (const char *filename)
{
  int retcode = -1;
  char *sigfilename = NULL;
  gchar * path = g_build_filename (OPENVAS_SYSCONF_DIR, "gnupg", NULL);
  gpgme_error_t err;
  gpgme_ctx_t ctx = gvm_init_gpgme_ctx_from_dir (path);
  gpgme_data_t sig = NULL, text = NULL;

  g_free (path);

  if (ctx == NULL)
    {
      nasl_trace (NULL, "gpgme context could not be initialized.\n");
      goto fail;
    }

  nasl_trace (NULL, "nasl_verify_signature: loading scriptfile '%s'\n",
              filename);

  err = gpgme_data_new_from_file (&text, filename, 1);
  if (err)
    {
      print_gpgme_error ("gpgme_data_new_from_file", err);
      goto fail;
    }

  sigfilename = g_malloc0 (strlen (filename) + 4 + 1);
  strcpy (sigfilename, filename);
  strcat (sigfilename, ".asc");
  nasl_trace (NULL, "nasl_verify_signature: loading signature file '%s'\n",
              sigfilename);
  err = gpgme_data_new_from_file (&sig, sigfilename, 1);
  if (err)
    {
      /* If the file doesn't exist, fail without an error message
       * because an unsigned file is a very common and expected
       * condition */
      if (gpgme_err_code (err) != GPG_ERR_ENOENT)
        print_gpgme_error ("gpgme_data_new_from_file", err);
      else
        nasl_trace (NULL, "nasl_verify_signature: %s: %s\n", sigfilename,
                    gpgme_strerror (err));
      goto fail;
    }

  err = gpgme_op_verify (ctx, sig, text, NULL);
  nasl_trace (NULL, "nasl_verify_signature: gpgme_op_verify -> '%d'\n", err);
  if (err)
    {
      print_gpgme_error ("gpgme_op_verify", err);
      goto fail;
    }

  if (examine_signatures (gpgme_op_verify_result (ctx)))
    retcode = 0;
  else
    retcode = 1;

fail:
  gpgme_data_release (sig);
  gpgme_data_release (text);
  if (ctx != NULL)
    gpgme_release (ctx);
  g_free (sigfilename);

  return retcode;
}
