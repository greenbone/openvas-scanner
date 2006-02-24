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
 */
 
#include <includes.h>

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif
#ifdef HAVE_SETJMP_H
# include <setjmp.h>
#endif

#include "globals.h"

/* fixing the problem when nessus is started in the background while
   the user is requested to enter a pass phrase */

#define BLURB " --- better you start in the foreground.\n"

#ifdef SIGTTOU
/* this is the preferable soulution printing an error message
   and terminating nessus  */
static jmp_buf jenv;

static void
die_on_background_tty
  (int sig)
{
  signal (sig, SIG_IGN);
  fputs ("\n\nNo password dialogue possible" BLURB, stderr);
  longjmp (jenv, -1);
}

static char *
verify_tty_getpass
  (const char *prompt)
{
  /* when getpass tries to write the password prompt on the background,
     a stop-output signal will be risen, if available  */
  void (*fn)(int) = signal (SIGTTOU, die_on_background_tty);
  if (setjmp (jenv) == 0) {
    char *s = getpass (prompt);
    signal (SIGTTOU, fn);
    return s;
  }
  return (char*)-1;
}
#define getpass(s) verify_tty_getpass (s)
#else  /* SIGTTOU */

#ifdef TCION /* found in termios */

/* this is a fall back, only taking care that input can be 
   read  when getting back into the forground, again */
static char *
retrieve_tty_getpass
  (const char *prompt)
{
  int fd ;
  if ((fd = open ("/dev/tty", O_RDONLY)) < 0) {
    fprintf (stderr, "Cannot open tty (%s)" BLURB, strerror (errno)) ;
    exit (0);
  }
  /* this causes getpass() to retrieve the input properly once 
     it has been brought back in the foreground, again */
  if (tcflow (fd, TCION) < 0) {
    fprintf (stderr, "Cannot access tty (%s)" BLURB, strerror (errno)) ;
    exit (0);
  }
  close (fd);
  return getpass (prompt);
}
#define getpass(s) retrieve_tty_getpass (s)
#endif /* SIGTTOU */
#endif /* TCION */ 
#undef BLURB

/* non GUI password dialogue */
char* 
cmdline_pass
  (int unused)
{
  return getpass ("Server password: "); 
}

 
/* used for private key activation */
static int __created_key = 0;

int /* return just-generated-private-key status */
created_private_key 
 (void)
{
  int n = __created_key ;
  __created_key = 0 ;
  return n;
}

char* 
get_pwd 
 (int mode) {
  char *s, *t ;

  switch (mode) {
  case 0:
    /* key activation mode */
    if(F_quiet_mode)return getpass("Pass phrase: ");
    else
    return getpass("Pass phrase: ");
  case 2:
    __created_key ++ ;
#   ifdef FIRST_PWD_BLURB
    fflush (stderr);
    printf ("%s", FIRST_PWD_BLURB);
    fflush (stdout);
#   endif
  }

  if ((s = getpass ("New pass phrase: ")) == 0 || s == (char*)-1)
    return (char*)-1;
  s = estrdup (s);
  if ((t = getpass ("Repeat         : ")) == 0 || t == (char*)-1) {
    efree (&s);
    return (char*)-1;
  }
  if (strcmp (s, t) != 0)
    t = 0 ;
  efree (&s);
  if (t == 0)
    return (char*)-1;
  return t ;
}
 
 
 
