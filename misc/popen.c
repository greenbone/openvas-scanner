/*
 * Copyright (C) Michel Arboi 2002
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
 *   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#ifndef RLIM_INFINITY
#define RLIM_INFINITY (1024*1024*1024)
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

FILE *
openvas_popen4 (const char *cmd, char *const args[], pid_t * ppid, int inice)
{
  int fd, pipes[2];
  pid_t son;
  FILE *fp;

#if DEBUG
  int i;
  g_message ("openvas_popen4: running %s -", cmd);
  for (i = 0; args[i] != NULL; i++)
    g_message (" %s", args[i]);
  fputc ('\n', stderr);
#endif

  /* pipe() does not always work well on some OS */
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, pipes) < 0)
    {
      perror ("socketpair");
      return NULL;
      /* filedes[0]  is  for  reading, filedes[1] is for writing. */
    }
  if ((son = fork ()) < 0)
    {
      perror ("fork");
      close (pipes[0]);
      close (pipes[1]);
      return NULL;
    }
  if (son == 0)
    {
      struct rlimit rl;
      int i;

      /* Child process */

      if (inice)
        {
          errno = 0;
          /* Some systems returned the new nice value => it may be < 0 */
          if (nice (inice) < 0 && errno)
            perror ("nice");
        }
      /* Memory usage: unlimited */
      rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
      if (setrlimit (RLIMIT_DATA, &rl) < 0)
        perror ("RLIMIT_DATA");
      if (setrlimit (RLIMIT_RSS, &rl) < 0)
        perror ("RLIMIT_RSS");
      if (setrlimit (RLIMIT_STACK, &rl) < 0)
        perror ("RLIMIT_STACK");
      /* We could probably limit the CPU time, but to which value? */

      if ((fd = open ("/dev/null", O_RDONLY)) < 0)
        {
          perror ("/dev/null");
          exit (1);
        }
      close (STDIN_FILENO);
      if (dup2 (fd, STDIN_FILENO) < 0)
        {
          perror ("dup2");
          exit (1);
        }
      close (fd);

      close (STDOUT_FILENO);
      close (STDERR_FILENO);
      if (dup2 (pipes[1], STDOUT_FILENO) < 0 || dup2 (pipes[1], STDERR_FILENO) < 0)
        {
          /* Cannot print error as STDERR is closed! */
          exit (1);
        }

      /*
       * Close all the fd's
       */
      for (i = 3; i < 256; i++)
        {
          close (i);
        }
      signal (SIGTERM, _exit);
      signal (SIGPIPE, _exit);
      execvp (cmd, args);
      perror ("execvp");
      _exit (1);
    }
  close (pipes[1]);
  if ((fp = fdopen (pipes[0], "r")) == NULL)
    {
      perror ("fdopen");
      close (pipes[0]);
      return NULL;
    }

  if (ppid != NULL)
    *ppid = son;
  return fp;
}

int
openvas_pclose (FILE * fp, pid_t pid)
{
  if (pid > 0)
    if (waitpid (pid, NULL, WNOHANG) == 0)
      if (kill (pid, SIGTERM) >= 0)
        if (waitpid (pid, NULL, WNOHANG) == 0)
          {
            usleep (400);
            (void) kill (pid, SIGKILL);
            (void) waitpid (pid, NULL, WNOHANG);
          }
  return fclose (fp);
}
