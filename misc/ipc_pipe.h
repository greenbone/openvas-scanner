#ifndef IPC_PIPE_H
#define IPC_PIPE_H

struct ipc_pipe_context
{
  int fd[2];
};

int
ipc_pipe_send (struct ipc_pipe_context *context, const char *msg, int len);

char *
ipc_pipe_retrieve (struct ipc_pipe_context *context);

int
ipc_pipe_destroy (struct ipc_pipe_context *context);

int
ipc_pipe_close (struct ipc_pipe_context *context);

struct ipc_pipe_context *
ipc_init_pipe (void);

#endif
