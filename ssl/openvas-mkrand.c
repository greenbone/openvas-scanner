/* OpenVAS
* $Id$
* Description: Entropy generator for users who do not have /dev/urandom.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 2001 Michel Arboi.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <signal.h>


FILE		*fp;

/* 
 * Ugly but portable
 */

int 
setup_tty()
{

	return !system("stty -icanon") && !system("stty -echo");
}

int
restore_tty()
{
	return !system("stty echo") && !system("stty icanon");
}

void
sighand(sig)
	int sig;
{
	restore_tty();
 	if(fp)fclose(fp);
	exit(1);
}

int
usage()
{

      fprintf(stderr, "Usage: openvas-mkrand file entropy_in_bits\nNote: Data will be appended to the file\n");
      exit(1);
}

int
main(argc, argv)
     int	argc;
     char	*argv[];
{
  int		entropy = 1024, i, j, x;
  int		prec;
  double	e, f, l2 = log(2.0);
  struct timeval	tictac;
  unsigned char		c, *p;
  int		count[256][256], sum[256];
  char *	out = NULL;

  signal(SIGTERM, sighand);
  signal(SIGINT, sighand);

  if(argc > 1 && !strncmp(argv[1], "-h", 2))
  {
	  usage();
  }

  if(argc > 1)
    out = strdup(argv[1]);

  if(argc > 2)
    entropy = atoi(argv[2]);

  if (entropy <= 0)
    {
      fprintf(stderr, "I cannot generate zero or less bytes!\n");
      usage();
    }

  if(!out)
  {
    char * home = getenv("HOME");
    if(!home)
    {
	    fprintf(stderr, "$HOME not set - exiting\n");
	    return 1;
    }
    out = malloc(strlen(home) + 7);
    sprintf(out, "%s/.rnd", home);
  }
  if ((fp = fopen(out, "a")) == NULL)
    {
      perror(out);
      return 1;
    }

  for (i = 0; i < 256; i ++)
    {
      sum[i] = 0;
      for (j = 0; j < 256; j ++)
	count[i][j] = 0;
    }

  fprintf(stderr, "Now please enter random characters\n");

  setup_tty();
  prec = 0;
  e = 0.0;
  i = 0;
  while (e < entropy)
    {
      gettimeofday(&tictac, NULL);
      if ((x = getchar()) == EOF)
	{
	  perror("getchar");
	  break;
	}

      c = x;
      for (j = 0, p = (unsigned char*)&tictac; j < sizeof(tictac); j ++)
	c = c * 11 + c % 13 + *(p++);

      sum[prec] ++;
      /*
       * 1/48 is linked to the classical "zero probability encoding" 
       * that we see in compression algorithm. I chose a conservative
       * value. 
       */
      f = log(((double) count[prec][c] + (1. / 48.))
	      / (double) sum[prec]) / l2;
      e -= f;
#if 0
      fprintf(stderr, "c=0x%x f=%g\te=%g\n", c, -f, e);
#endif
      count[prec][c] ++;
      prec = c;

      if (fwrite(&c, 1, 1, fp) < 1)
	{
	  perror("fwrite");
	  return 1;
	}
      i ++;
      fputs(".", stdout);
      fflush(stdout);
    }
  restore_tty();
#ifdef DEBUG
  fprintf(stderr, "Estimated entropy = %g bits (= %d bytes)\n",
	  e, (int) (e / 8));
  fprintf(stderr, "Estimated entropy per character = %g bits\n", e / i);
#endif
#if 0
  if (e < entropy)
    fprintf(stderr, "\n**** WARNING. Entropy is too low ****\n\n");
#endif
 
  if (fclose(fp) < 0)
    {
      perror("fclose");
      return 1;
    }

  fprintf(stderr, "That's enough - thank you\n");  
  return 0;
}
