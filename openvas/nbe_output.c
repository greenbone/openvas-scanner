/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
 *
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
#include "report.h"
#include "error_dialog.h"
#include "backend.h"
#include "data_mining.h"
#include "report_utils.h"

int backend_to_nbe(int, char *);
int nbe_to_backend(char*);



/*------------------------- Private functions ------------------------------*/

int 
nbe_to_backend(filename)
 char * filename;
{
 int fd = (strcmp(filename, "-") == 0) ? 0 : open(filename, O_RDONLY);
 int be = backend_init(NULL);
 int befd = backend_fd(be);
 char buf[4096];
 int e;
 
 while((e = read(fd, buf, sizeof(buf))) > 0)
 {
  write(befd, buf, e);
 }
 if(e < 0)
 {
  perror("read ");
  return -1;
 }
 close(fd);
 return be; 
}



extern int F_quiet_mode;

/*
 * XXXX
 *
 * Does not handle the case where the backend is not
 * a file
 */
int 
backend_to_nbe(be, filename)
 int be;
 char * filename;
{
 int fd;
 int befd = backend_fd(be);
 off_t tot = 0;
 char buf[4096];
 struct stat stat;
 int len;
 
 
 if(strcmp(filename, "-") == 0)
  fd = 1; /* stdout */
 else
   if (F_quiet_mode)
     fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
   else
     fd = open(filename, O_RDWR|O_CREAT|O_EXCL, 0600);

 if(fd < 0)
 {
   char	err[1024];
   int	e = errno;
   perror(filename);
   snprintf(err, sizeof(err), "%s: %s", filename, strerror(e));
   show_error(err);
   return -1;
 }

 
 lseek(befd, 0, SEEK_SET);
 fstat(befd, &stat);
 len = (int)stat.st_size;
 while(tot < len)
 {
  int e;
  bzero(buf, sizeof(buf));
  e = read(befd, buf, sizeof(buf));
  if(e < 0)
   {
    perror("read ");
    return -1;
   }
  write(fd, buf, e);
  tot+=e;
 }

 close(fd);
 return 0; 
}

