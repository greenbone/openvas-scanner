/* OpenVAS
 * Copyright (C) 1998 - 2004 Renaud Deraison
 * Copyright (C) 2005 Tim Brown
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * 
 * This very simply utility generates/checks a signature for a given file
 *
 *
 * $Id$
 */
#include <includes.h>
#ifdef HAVE_SSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#include <openssl/blowfish.h>



/* 
 * Signs a given file
 */
int generate_signature(char * filename)
{
 RSA * rsa = NULL;
 FILE * fp = fopen(OPENVASD_STATEDIR "/openvas_org.priv.pem", "r");
 unsigned char  * result;
 unsigned int len;
 int i;
 unsigned char md[SHA_DIGEST_LENGTH+1];
 int be_len;

 SHA_CTX ctx;
 int fd;
 int n;
 char buf[1024];
 struct stat st;


 SHA1_Init(&ctx);

 fd = open(filename, O_RDONLY);
 if ( fd < 0 ) 
 {
  fprintf(stderr, "open(%s) : %s\n", filename, strerror(errno));
  return -1;
 }

 fstat(fd, &st);
 bzero(buf, sizeof(buf));
 while ( ( n = read(fd, buf, sizeof(buf))) > 0 )
 {
  SHA1_Update(&ctx, buf, n);
 } 
 /* Add the size of the file at the end of the message */
 be_len = htonl(st.st_size);
 SHA1_Update(&ctx, &be_len, sizeof(be_len));
 SHA1_Final(md, &ctx);
 close(fd);
 


 if ( fp == NULL ) 
	{
	perror("open ");
	return -1;
	}
 
 rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
 fclose(fp);
 if ( rsa == NULL ) 
	{
	fprintf(stderr, "PEM_read_RSAPrivateKey() failed\n");
	return -1;
	}

 len = RSA_size(rsa);
 result = emalloc(len);
	
 RSA_sign(NID_sha1, md, SHA_DIGEST_LENGTH, result, &len, rsa);
 for ( i = 0 ; i < len ; i ++ )
 {
  printf("%.2x", result[i]);
 }
 printf("\n");
 fflush(stdout);
 efree(&result);
 RSA_free(rsa);
 
 return 0;
}

 
/* 
 * Verify an archive signature
 *
 * Returns :
 *	-1 : if an error occured
 *	 0 : if the signature matches
 *	 1 : if the signature does NOT match
 */
int verify_signature(char * filename, char * signature)
{
 unsigned char md[SHA_DIGEST_LENGTH+1];
 RSA * rsa = NULL;
 FILE * fp = fopen(OPENVASD_STATEDIR "/openvas_org.pem", "r");

 char sig[16384];
 unsigned char bin_sig[8192];
 int binsz = 0;

 int i, sig_len = 0, res = -1, be_len;
 FILE * sigfile = fopen(signature, "r");

 SHA_CTX ctx;
 struct stat st;
 int fd;
 char buf[1024];
 int n;


 if ( fp == NULL )
 {
  fprintf(stderr, "Open %s/openvas_org.pem : %s\n", OPENVASD_STATEDIR, strerror(errno));
  return -1;
 }

 /* No signature - fail */
 if ( sigfile == NULL )
 {
  fprintf(stderr, "Open %s : %s\n", signature, strerror(errno));
  return 1;
 }

 fgets(sig, sizeof(sig) - 1, sigfile);
 fclose(sigfile);
 sig[sizeof(sig) - 1] = '\0';


 fd = open(filename, O_RDONLY);
 if ( fd < 0 )
 {
  fprintf(stderr, "open(%s) : %s\n", filename, strerror(errno));
  return 1;
 } 
 

 fstat(fd, &st);
 SHA1_Init(&ctx);
 bzero(buf, sizeof(buf));
 while ( ( n = read(fd, buf, sizeof(buf)) ) > 0 )
 {
  SHA1_Update(&ctx, buf, n); 
 }

 be_len = htonl(st.st_size);
 SHA1_Update(&ctx, &be_len, sizeof(be_len));
 SHA1_Final(md, &ctx);
 close(fd);

 rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
 fclose(fp);
 if ( rsa == NULL ) return -1;


 sig_len = strlen(sig) - 1;

 for ( i = 0 ; i < sig_len ; i += 2 )
 {
  char t[3];
  strncpy(t, sig + i, 2);
  t[2] = '\0';
  bin_sig[binsz] = strtoul(t, NULL, 16);
  binsz ++; 
  if ( binsz >= sizeof(bin_sig) ) goto err; /* Too long signature */
 }
 
 

 res = RSA_verify(NID_sha1, md, SHA_DIGEST_LENGTH, bin_sig, binsz, rsa);
 RSA_free(rsa);
 return res == 1 ? 0 : 1;
 
err:
  RSA_free(rsa);
  return -1;
 
}


int main(int argc, char ** argv)
{
 int do_sign = 0; 
 if ( argc != 3 )
 {
  fprintf(stderr, "Usage: openvas-check-signature [-S] filename [signaturefile]\n");
  exit(1);
 }

 nessus_SSL_init(NULL);

 if ( strcmp(argv[1], "-S") == 0 )
	do_sign ++;

 if ( do_sign == 0 )
 {
  if  ( verify_signature(argv[1], argv[2]) <= 0 )
	exit(0);
  else
	{
	printf("%s is not the valid signature for %s\n", argv[2], argv[1]);
	exit(1);
	}
 }
 else {
	generate_signature(argv[2]);
	}
 exit(0);
}
#else
int main()
{
 printf("openvas-check-signature: OpenSSL support has been disabled\n");
 exit(0);
}
#endif
