/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ipc.h"

#include "ipc_pipe.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gvm/base/logging.h>
#include <json-glib/json-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

// default preallocation length for ipc_contexts
#define IPC_CONTEXTS_CAP_STEP 10

/**
 * @brief sends given msg to the target based on the given context
 *
 * @param context the ipc_context to be used; must be previously
 * initialized via ipc_init.
 *
 * @param to the target direction of the message when it is supported by the
 * given ipc_context.
 * @param msg the message to send
 * @param len the length of msg
 *
 * @return bytes written, -2 when the context or msg or context type is unknown,
 * -1 on write error
 */
int
ipc_send (struct ipc_context *context, enum ipc_relation to, const char *msg,
          size_t len)
{
  (void) to;
  if (context == NULL || msg == NULL)
    return -2;
  switch (context->type)
    {
    case IPC_PIPE:
      return ipc_pipe_send (context->context, msg, len);
    };
  return -2;
}

/**
 * @brief destroys given context
 *
 * @param context the ipc_context to be destroyed.
 *
 * @return 0 on success, -1 on context null or failure to destroy
 */
int
ipc_destroy (struct ipc_context *context)
{
  int rc = 0;
  if (context == NULL)
    return -1;
  switch (context->type)
    {
    case IPC_PIPE:
      rc = ipc_pipe_destroy (context->context);
      break;
    }
  g_free (context);
  return rc;
}

/**
 * @brief retrieves data for the relation based on the context
 *
 * @param context the ipc_context to be used; must be previously
 * initialized via ipc_init.
 *
 * @param to the recieving direction of the message when it is supported by the
 * given ipc_context.
 *
 * @return a heap initialized data or NULL
 */
char *
ipc_retrieve (struct ipc_context *context, enum ipc_relation from)
{
  (void) from;
  if (context == NULL)
    return NULL;
  switch (context->type)
    {
    case IPC_PIPE:
      return ipc_pipe_retrieve (context->context);
    };
  return NULL;
}

/**
 * @brief closes given context
 *
 * @param context the ipc_context to be  closed
 *
 * @return -1 when context is either NULL or already closed or 0 on success.
 */
int
ipc_close (struct ipc_context *context)
{
  int rc = -1;
  if (context == NULL || context->closed == 1)
    return rc;
  switch (context->type)
    {
    case IPC_PIPE:
      rc = ipc_pipe_close (context->context);
      context->closed = 1;
    }
  return rc;
}

/**
 * @brief initializes a new context.
 *
 * @param type the protocol type to be initialized
 * @param relation the relation of the context to be initialized when supported
 * by the type.
 *
 * @return a heap initialized context or NULL on failure.
 */
struct ipc_context *
ipc_init (enum ipc_protocol type, enum ipc_relation relation)
{
  struct ipc_context *ctx = NULL;
  void *context = NULL;
  (void) relation;
  if ((ctx = calloc (1, sizeof (*ctx))) == NULL)
    goto exit;
  ctx->type = type;
  switch (type)
    {
    case IPC_PIPE:
      context = ipc_init_pipe ();
      break;
    }
  if (!context)
    goto free_exit;
  ctx->context = context;
  return ctx;

free_exit:
  if (ctx != NULL)
    free (ctx);
exit:
  return NULL;
}

/**
 * @brief runs given functions with the given protocol type.
 *
 * @param type the protocol type to be initialized
 * @param exec_ctx the execution context to be executed.
 *
 * @return a heap initialized context or NULL on failure.
 */
struct ipc_context *
ipc_exec_as_process (enum ipc_protocol type, struct ipc_exec_context exec_ctx)
{
  struct ipc_context *pctx = NULL, *cctx = NULL;
  pid_t pid;
  if (exec_ctx.func == NULL)
    return NULL;
  switch (type)
    {
    case IPC_PIPE:
      if ((pctx = ipc_init (type, IPC_MAIN)) == NULL)
        {
          return NULL;
        }
    }

  gvm_log_lock ();
  pid = fork ();
  gvm_log_unlock ();
  /* fork error */
  if (pid < 0)
    {
      ipc_destroy (pctx);
      return NULL;
    }
  // we are the child process and execute given function
  if (pid == 0)
    {
      if (pctx != NULL)
        cctx = pctx;
      else if ((cctx = ipc_init (type, IPC_CHILD)) == NULL)
        {
          exit (1);
        }

      if (exec_ctx.pre_func != NULL)
        (*exec_ctx.pre_func) (cctx, exec_ctx.pre_arg);
      (*exec_ctx.func) (cctx, exec_ctx.func_arg);
      if (exec_ctx.post_func != NULL)
        (*exec_ctx.post_func) (cctx, exec_ctx.pre_arg);
      switch (type)
        {
        case IPC_PIPE:
          ipc_destroy (pctx);
          break;
        }
      exit (0);
    }

  if (pctx == NULL)
    {
      if ((pctx = malloc (sizeof (*pctx))) == NULL)
        {
          return NULL;
        }
      pctx->relation = IPC_MAIN;
      pctx->type = type;
      pctx->context = exec_ctx.shared_context;
    }
  // we are the parent process and return the id of the child process for
  // observation
  pctx->pid = pid;
  return pctx;
}

/**
 * @brief initializes ipc_contexts with a given preallocated capacity.
 *
 * @param cap to size to be preallocated, if 0 it will not preallocate but
 * allocate on each enw entry.
 *
 * @return a heap initialized contexts or NULL on failure.
 */
struct ipc_contexts *
ipc_contexts_init (int cap)
{
  struct ipc_contexts *ctxs = NULL;
  if ((ctxs = malloc (sizeof (*ctxs))) == NULL)
    goto exit;
  ctxs->len = 0;
  ctxs->cap = cap > 0 ? cap : IPC_CONTEXTS_CAP_STEP;
  if ((ctxs->ctxs = malloc (ctxs->cap * sizeof (*ctxs->ctxs))) == NULL)
    goto free_and_exit;
exit:
  return ctxs;
free_and_exit:
  if (ctxs != NULL)
    free (ctxs);
  return NULL;
}

/**
 * @brief adds a given context to contexts
 *
 * @param ctxs the context holder array to be used to add a new ctx
 * @param ctx the context to be added to ctxs
 *
 * @return a pointer to the given ctxs or NULL on failure.
 */
struct ipc_contexts *
ipc_add_context (struct ipc_contexts *ctxs, struct ipc_context *ctx)
{
  if (ctxs == NULL)
    goto exit_error;
  if (ctx == NULL)
    goto exit_error;
  if (ctxs->len == ctxs->cap)
    {
      ctxs->cap = ctxs->cap + IPC_CONTEXTS_CAP_STEP;
      ctxs->ctxs = realloc (ctxs->ctxs, ctxs->cap * sizeof (*ctxs->ctxs));
      if (ctxs->ctxs == NULL)
        {
          // NOTE: the caller must free ctxs->ctxs in this case.
          goto exit_error;
        }
    }
  ctxs->ctxs[ctxs->len] = *ctx;
  ctxs->len += 1;
  return ctxs;
exit_error:
  return NULL;
}

/**
 * @brief destroys given contexts
 *
 * @param ctxs the context holder array to be destroyed.
 *
 * @return 0 on success or -1 on failure.
 */
int
ipc_destroy_contexts (struct ipc_contexts *ctxs)
{
  int i, rc = 0;
  if (ctxs == NULL)
    return rc;
  for (i = 0; i < ctxs->len; i++)
    {
      if (ipc_close (&ctxs->ctxs[i]) < 0)
        rc = -1;
    }
  free (ctxs->ctxs);
  free (ctxs);
  return rc;
}
