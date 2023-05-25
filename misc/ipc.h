/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MISC_IPC_H
#define MISC_IPC_H

#include <sys/types.h>

enum ipc_protocol
{
  IPC_PIPE
};

enum ipc_relation
{
  IPC_MAIN,
  IPC_CHILD
};

/**
 * ipc_context contains information about an inter process communication
 * process.
 *
 * @param type indicates what type of ipc it represents
 * @param pid is set on ipc_exec_as_process and contains the pid of the child
 * process.
 * @param context contextual data for ipc. Is only used internally.
 */
struct ipc_context
{
  enum ipc_protocol type;
  enum ipc_relation relation;
  unsigned int closed;
  pid_t pid;
  void *context;
};

struct ipc_contexts
{
  int len;
  int cap;
  struct ipc_context *ctxs;
};

typedef void (*ipc_process_func) (struct ipc_context *, void *);

struct ipc_exec_context
{
  // function to be executed before func is executed
  ipc_process_func pre_func;
  // function to be executed
  ipc_process_func func;
  // function to be executed after func is executed
  ipc_process_func post_func;
  void *pre_arg;        // argument for pre_func
  void *func_arg;       // argument for func
  void *post_arg;       // argument for post_func
  void *shared_context; // context to be included in ipc_context
};

// ipc_process_func is a type for the function to be executed.

int
ipc_send (struct ipc_context *context, enum ipc_relation to, const char *msg,
          size_t len);

char *
ipc_retrieve (struct ipc_context *context, enum ipc_relation from);

int
ipc_destroy (struct ipc_context *context);

int
ipc_close (struct ipc_context *context);

struct ipc_context *
ipc_exec_as_process (enum ipc_protocol type,
                     struct ipc_exec_context exec_context);

struct ipc_context *
ipc_init (enum ipc_protocol protocol, enum ipc_relation relation);

struct ipc_contexts *
ipc_contexts_init (int len);

struct ipc_contexts *
ipc_add_context (struct ipc_contexts *ctxs, struct ipc_context *ctx);

int
ipc_destroy_contexts (struct ipc_contexts *ctxs);

#endif
