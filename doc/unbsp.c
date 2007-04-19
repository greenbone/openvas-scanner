/*
 *          Copyright (c) mjh-EDV Beratung, 1996-1999
 *     mjh-EDV Beratung - 63263 Neu-Isenburg - Rosenstrasse 12
 *          Tel +49 6102 328279 - Fax +49 6102 328278
 *                Email info@mjh.teddy-net.com
 *
 *   Author: Jordan Hrycaj <jordan@mjh.teddy-net.com>
 *
 *   $Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Library General Public
 *   License as published by the Free Software Foundation; either
 *   version 2 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Library General Public License for more details.
 *
 *   You should have received a copy of the GNU Library General Public
 *   License along with this library; if not, write to the Free
 *   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <errno.h>

char* pname ;

void
usage
 (void)
{
  fprintf (stderr, "Usage: %s [--] doc-file(s) ...\n", pname);
  exit (1);
}

void
set_pname
  (char *s)
{
  if ((pname = (char*)strrchr (s, '/')) == 0)
    pname = s ;
  else
    ++ pname ;
}


void
unbackspace 
  (FILE *fp)
{
  int c, last ;

  if ((last = getc (fp)) == EOF)
    return ;
  
  /* filter out backspace sequences from catman */
  for (;;)
    switch (c =  getc (fp)) {
    case '\b':
      last = getc (fp) ;
      continue ;
    case EOF:
      return;
    default:
      putchar (last) ;
      last = c ;
    }
}

int
main 
  (int    argc, 
   char **argv) 
{
  FILE *fp ;
  set_pname (*argv++) ; argc -- ;

  if (argc == 0 || 
      (argv [0][0] == '-' && 
       argv [0][1] != '-' &&
       argv [0][1] != '\0'))
    usage () ;

  do {
    if (argv [0][0] == '-' && argv [0][0] == '\0')
      fp = stdin ;
    else
      if ((fp = fopen (* argv, "r")) == 0) {
	perror (*argv);
	exit (2);
      }
    unbackspace (fp) ;
    if (fp != stdin)
      fclose (fp);
  } while (++ argv, -- argc);

  exit (0);
}
