/* OpenVAS
* $Id$
* Description: generates/checks a signature for a given file.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

/* FIXME: The code here is mostly a duplicate of code in
 * openvas-libnasl/nasl/nasl_crypto2.c.  The main difference is that the
 * signatures dealt with here are detached, whereas the signatures
 * handled by nasl_crypto2.c are part of the signed file.
 *
 * Also, the original OpenSSL code in this file was probably better at
 * handling larger files.  The new code read the file to sign or verify
 * completely into memory which may be inefficient for large files.
 *
 * Before something is done about it, OpenVAS needs to decide how to
 * deal with signed files in general.
 */

#include <includes.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


void
print_tls_error(char *txt, int err)
{
  fprintf(stderr, "%s: %s (%d)\n", txt, gnutls_strerror(err), err);
}

gnutls_datum_t
map_file(const char * filename)
{
  FILE *f;
  gnutls_datum loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  if (!(f = fopen(filename, "r"))
      || fseek(f, 0, SEEK_END) != 0
      || (filelen = ftell(f)) < 0
      || fseek(f, 0, SEEK_SET) != 0
      || !(ptr = emalloc((size_t) filelen))
      || fread(ptr, 1, (size_t) filelen, f) < (size_t) filelen)
    {
      return loaded_file;
    }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int) filelen;
  return loaded_file;
}

static ptrdiff_t
hexdecode(unsigned char *binary, const unsigned char *hex, size_t fromlen)
{
  char temp[3] = {0, 0, 0};
  unsigned char * to = binary;
  const unsigned char * from = hex;

  while ((from - hex) < fromlen - 1)
    {
      temp[0] = from[0];
      temp[1] = from[1];
      *to = strtoul(temp, NULL, 16);
      to += 1;
      from += 2;
    }

  return to - binary;
}


/*
 * Signs a given file
 */
static int
generate_signature(char * keyfilename, char * filename)
{
  int result = -1;
  int i;
  int be_len;
  gnutls_datum_t pem = {NULL, 0};
  gnutls_datum_t script = {NULL, 0};
  gnutls_x509_privkey_t privkey = NULL;
  unsigned char* signature = NULL;
  size_t signature_size = 0;
  int err;

  err = gnutls_x509_privkey_init(&privkey);
  if (err)
    {
      print_tls_error("gnutls_x509_privkey_init", err);
      goto fail;
    }

  pem = map_file(keyfilename);
  if (!pem.data)
    goto fail;

  err = gnutls_x509_privkey_import(privkey, &pem, GNUTLS_X509_FMT_PEM);
  if (err)
    {
      print_tls_error("gnutls_x509_privkey_import", err);
      goto fail;
    }

  script = map_file(filename);
  if (!script.data)
    {
      goto fail;
    }

  /* append the size of the file at the end of the script */
  script.data = erealloc(script.data, script.size + sizeof(be_len));
  be_len = htonl(script.size);
  memcpy(script.data + script.size, &be_len, sizeof(be_len));
  script.size += sizeof(be_len);

  /* call gnutls_x509_privkey_sign_data twice: once to determine the
   * size of the signature and then again to actually create the
   * signature */
  err = gnutls_x509_privkey_sign_data(privkey, GNUTLS_DIG_SHA1, 0, &script,
				      signature, &signature_size);
  if (err != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      print_tls_error("gnutls_x509_privkey_sign_data", err);
      goto fail;
    }

  signature = emalloc(signature_size);
  err = gnutls_x509_privkey_sign_data(privkey, GNUTLS_DIG_SHA1, 0, &script,
				      signature, &signature_size);
  if (err)
    {
      print_tls_error("gnutls_x509_privkey_sign_data", err);
      goto fail;
    }

  /* print the signature to stdout in hexadecimal */
  for (i = 0; i < signature_size; i++)
    {
      printf("%.2x", signature[i]);
    }
  printf("\n");

  result = 0;

 fail:
  efree(&pem.data);
  efree(&script.data);
  efree(&signature);
  gnutls_x509_privkey_deinit(privkey);

  return result;
}


/*
 * Verify an archive signature
 *
 * Returns :
 *	-1 : if an error occured
 *	 0 : if the signature matches
 *	 1 : if the signature does NOT match
 */
static int
verify_signature(char * certfilename, char * filename, char * sigfilename)
{
  int be_len;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t pem = {NULL, 0};
  gnutls_datum_t script = {NULL, 0};
  gnutls_datum_t signature = {NULL, 0};
  int result = -1;
  int err;

  pem = map_file(certfilename);
  if (!pem.data)
    goto fail;

  err = gnutls_x509_crt_init(&cert);
  if (err)
    {
      print_tls_error("gnutls_x509_crt_init", err);
      goto fail;
    }

  err = gnutls_x509_crt_import(cert, &pem, GNUTLS_X509_FMT_PEM);
  if (err)
    {
      print_tls_error("gnutls_x509_crt_import", err);
      goto fail;
    }

  script = map_file(filename);
  if (!script.data)
    {
      goto fail;
    }

  /* Make room for the size of the file at the end of the script and
   * append the size */
  script.data = erealloc(script.data, script.size + sizeof(be_len));
  be_len = htonl(script.size);
  memcpy(script.data + script.size, &be_len, sizeof(be_len));
  script.size += sizeof(be_len);

  /* read and decode the hex signature.  Decoding can be done in place
   * because the binary signature is always shorter than its hexadecimal
   * representation. */
  signature = map_file(sigfilename);
  if (!signature.data)
    {
      goto fail;
    }
  signature.size = hexdecode(signature.data, signature.data, signature.size);

  err = gnutls_x509_crt_verify_data(cert, 0, &script, &signature);
  if (err < 0)
    {
      print_tls_error("gnutls_x509_crt_verify_data", err);
      goto fail;
    }

  result = err == 1 ? 0 : 1;

 fail:
  gnutls_x509_crt_deinit(cert);
  efree(&script.data);
  efree(&signature.data);
  efree(&pem);

  return result;

}


int
main(int argc, char ** argv)
{
  int do_sign = 0;
  int do_print_usage = 0;
  char * keyfile = NULL;
  char * certfile = NULL;
  int opt;
  int option_index = 0;
  struct option long_options[] =
    {
      {"help",		no_argument,	   0, 'h'},
      {"certificate",   required_argument, 0, 'c'},
      {"key",           required_argument, 0, 'k'},
      {"sign",		no_argument,	   0, 's'},
      {0, 0, 0, 0}
    };

  while ((opt = getopt_long(argc, argv, "c:hk:s", long_options, &option_index))
	 != -1)
    {
      switch (opt)
	{
	case 'c':
	  certfile = optarg;
	  break;

	case 'h':
	  do_print_usage = 1;
	  break;

	case 'k':
	  keyfile = optarg;
	  break;

	case 's':
	  do_sign = 1;
	  break;

	case '?':
	  fprintf(stderr, "unknown option or missing"
		  " parameter for option '%c'\n", opt);
	  return 1;

	default:
	  fprintf(stderr, "option '%c' not implemented\n", opt);
	  return 1;
	}
    }

  if (do_print_usage)
    {
      fprintf(stderr,
	      "Usage: openvas-check-signature [options]"
	      " filename [signaturefile]\n");
      fprintf(stderr, "Options:\n");
      fprintf(stderr, " -h           Print this help message\n");
      fprintf(stderr, " -k keyfile   File with private key for signature\n");
      fprintf(stderr, " -c certfile  File with certificate for signature"
	      " verificationi\n");
      return 0;
    }

  nessus_SSL_init(NULL);

  if (do_sign)
    {
      if (!keyfile)
	{
	  fprintf(stderr, "Missing parameter -k required for"
		  " signature generation\n");
	  return 1;
	}
      if (optind >= argc)
	{
	  fprintf(stderr, "missing filename parameter\n");
	  return 1;
	}

      generate_signature(keyfile, argv[optind]);
    }
  else
    {
      if (!certfile)
	{
	  fprintf(stderr, "Missing parameter -c required for"
		  " signature verification\n");
	  return 1;
	}

      if (optind + 1 >= argc)
	{
	  fprintf(stderr, "for signature verification, a filename and the"
		  " signature filename must be given\n");
	  return 1;
	}
      else
	{
	  char * filename = argv[optind];
	  char * signaturefile = argv[optind + 1];

	  if (verify_signature(certfile, filename, signaturefile) == 0)
	    return 0;
	  else
	    {
	      fprintf(stderr, "%s is not the valid signature for %s\n",
		      signaturefile, filename);
	      return 1;
	    }
	}
    }

  return 0;
}
