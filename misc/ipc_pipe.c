#include "ipc_pipe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define IPC_MAX_BUFFER 4096

int
ipc_pipe_send (struct ipc_pipe_context *context, const char *msg, int len)
{
  int wfd, wr;
  wfd = context->fd[1];
  wr = write (wfd, msg, len);
  return wr;
}

char *
ipc_pipe_retrieve (struct ipc_pipe_context *context)
{
  char *result = NULL;
  int rfd, rr, pf;
  // 0 means parent, everything else child
  rfd = context->fd[0];
  pf = fcntl (rfd, F_GETFL, 0);
  if (pf < 0 && errno != EBADF)
    // fd is closed or invalid; we assume closed
    return NULL;
  fcntl (rfd, F_SETFL, pf | O_NONBLOCK);
  if ((result = calloc (1, IPC_MAX_BUFFER)) == NULL)
    return NULL;
  if ((rr = read (rfd, result, IPC_MAX_BUFFER)) > 0)
    {
      return result;
    }
  else
    {
      free (result);
      // if temporary unavailable or not a closed descriptor don't
      // print an error.
      return NULL;
    }
}

int
ipc_pipe_close (struct ipc_pipe_context *context)
{
  int rc = 0;
  if (context == NULL)
    {
      rc = -1;
      goto exit;
    }
  if ((rc = close (context->fd[0])) < 0)
    goto exit;
  if ((rc = close (context->fd[1])) < 0)
    goto exit;
exit:
  return rc;
}

int
ipc_pipe_destroy (struct ipc_pipe_context *context)
{
  int rc = 0;
  if (context == NULL)
    {
      rc = -1;
      goto exit;
    }
  if ((rc = ipc_pipe_close (context)) < 0)
    goto exit;
  free (context);
exit:
  return rc;
}

struct ipc_pipe_context *
ipc_init_pipe (void)
{
  struct ipc_pipe_context *pc = NULL;
  if ((pc = calloc (1, sizeof (*pc))) == NULL)
    goto error;
  if (pipe (pc->fd) == -1)
    {
      goto error;
    }
  return pc;
error:
  if (pc != NULL)
    free (pc);
  return NULL;
}
