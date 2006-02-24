/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 * UI hooks for the SSL questions
 *
 */
#include <includes.h>

#ifdef USE_AF_UNIX
#undef NESSUS_ON_SSL
#endif
#ifdef NESSUS_ON_SSL
#include "globals.h"


/*
 * Ask the level of paranoia the user wants to set.
 *
 * Returns :
 *	<-1>    : An error occured
 *	<0|1|2> : The level of paranoia selected by the user
 */ 
int
sslui_ask_paranoia_level()
{
	int ret;
	static char question[] = "\
Please choose your level of SSL paranoia (Hint: if you want to manage many\n\
servers from your client, choose 2. Otherwise, choose 1, or 3, if you are \n\
paranoid.\n";	

  do {
  printf("%s", question);
  ret = 0;
  }
  while( (ret = (getc(stdin) - '0')) != 1 && ret != 2 && ret != 3 );
  if(ret >= 1 && ret <= 3)
   {
   return ret;
   }
  else 
   return -1;
}


/*
 * Shows the SSL certificate to the user.
 *
 * Input: 
 *	<ssl>   : the ssl connection
 *
 *
 * Output: 
 *	<0>  : the certificate is accepted
 *	<-1> : the certificate is invalid
 */ 
int
sslui_check_cert(ssl)
	SSL * ssl;
{
 char * ascii_cert;
 X509 * cert = SSL_get_peer_certificate(ssl);
 BIO * b;
 BUF_MEM * bptr;
 int x;
 
 b = BIO_new(BIO_s_mem());
 if(X509_print(b, cert) > 0)
 {
  BIO_get_mem_ptr(b, &bptr);
  ascii_cert = emalloc(1 + bptr->length);
  memcpy(ascii_cert, bptr->data, bptr->length);
 }
 else
 {
  ascii_cert = emalloc(1024);
  sprintf(ascii_cert, "This certificate has never been seen before and can't be shown\n");
 }
 BIO_free(b);

 printf("%s\n", ascii_cert);
 printf("Do you accept it ? (y/n) ");
 fflush(stdout);
 do {
  x = getchar();
 } while (x != EOF && x !='y' && x != 'n');
 
 return (x == 'y') ? 0:-1;
}
	
	

char*
sslui_ask_trusted_ca_path()
{
 return NULL;
}
#endif /* NESSUS_ON_SSL */
