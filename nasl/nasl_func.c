/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_func.h"

#include "exec.h"
#include "nasl_debug.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <glib.h>   /* for g_free */
#include <stdlib.h> /* for free */
#include <string.h> /* for strcmp */

/**
 * @brief This function climbs up in the context list and searches for a given
 * @brief function.
 */
static nasl_func *
get_func (lex_ctxt *ctxt, const char *name)
{
  lex_ctxt *c;

  for (c = ctxt; c != NULL; c = c->up_ctxt)
    {
      nasl_func *v = g_hash_table_lookup (c->functions, name);

      if (v)
        return v;
    }

  return func_is_internal (name);
}

nasl_func *
insert_nasl_func (lex_ctxt *lexic, const char *fname, tree_cell *decl_node,
                  int lint_mode)
{
  nasl_func *pf;

  if (get_func (lexic, fname))
    {
      if (lint_mode == 0)
        nasl_perror (
          lexic, "insert_nasl_func: function '%s' is already defined\n", fname);
      return NULL;
    }
  pf = g_malloc0 (sizeof (nasl_func));
  pf->func_name = g_strdup (fname);

  if (decl_node != NULL && decl_node != FAKE_CELL)
    {
      pf->block = decl_node->link[1];
      ref_cell (pf->block);
    }
  g_hash_table_insert (lexic->functions, pf->func_name, pf);
  return pf;
}

tree_cell *
decl_nasl_func (lex_ctxt *lexic, tree_cell *decl_node, int lint_mode)
{
  if (decl_node == NULL || decl_node == FAKE_CELL)
    {
      nasl_perror (lexic, "Cannot insert NULL or FAKE cell as function\n");
      return NULL;
    }

  if (insert_nasl_func (lexic, decl_node->x.str_val, decl_node, lint_mode)
      == NULL)
    return NULL;
  else
    return FAKE_CELL;
}

nasl_func *
get_func_ref_by_name (lex_ctxt *ctxt, const char *name)
{
  nasl_func *f;

  if ((f = get_func (ctxt, name)))
    return f;
  else
    return NULL;
}

extern FILE *nasl_trace_fp;

tree_cell *
nasl_func_call (lex_ctxt *lexic, const nasl_func *f, tree_cell *arg_list)
{
  int nb_u = 0, nb_a = 0;
  tree_cell *pc = NULL, *pc2 = NULL, *retc = NULL;
  lex_ctxt *lexic2 = NULL;
  char *trace_buf = NULL;
  char *temp_funname = NULL, *tmp_filename = NULL;
  int trace_buf_len = 0, tn;
#define TRACE_BUF_SZ 255

  /* 1. Create a new context */
  lexic2 = init_empty_lex_ctxt ();
  lexic2->script_infos = lexic->script_infos;
  lexic2->oid = lexic->oid;
  lexic2->recv_timeout = lexic->recv_timeout;
  lexic2->fct_ctxt = 1;

  if (nasl_trace_fp != NULL)
    {
      trace_buf = g_malloc0 (TRACE_BUF_SZ);
      tn = snprintf (trace_buf, TRACE_BUF_SZ, "Call %s(", f->func_name);
      if (tn > 0)
        trace_buf_len += tn;
    }

  for (pc = arg_list; pc != NULL; pc = pc->link[1])
    if (pc->x.str_val == NULL)
      nb_u++;

  /*
   * I should look exactly how unnamed arguments works...
   * Or maybe I should remove this feature?
   */

  for (nb_u = 0, pc = arg_list; pc != NULL; pc = pc->link[1])
    {
      pc2 = cell2atom (lexic, pc->link[0]);
      if (pc->x.str_val == NULL)
        {
          /* 2. Add unnamed (numbered) variables for unnamed args */
          if (add_numbered_var_to_ctxt (lexic2, nb_u, pc2) == NULL)
            goto error;
          nb_u++;
          if (nasl_trace_fp != NULL && trace_buf_len < TRACE_BUF_SZ)
            {
              tn = snprintf (trace_buf + trace_buf_len,
                             TRACE_BUF_SZ - trace_buf_len, "%s%d: %s",
                             nb_a > 0 ? ", " : "", nb_u, dump_cell_val (pc2));
              if (tn > 0)
                trace_buf_len += tn;
            }
          nb_a++;
        }
      else
        {
          /* 3. and add named variables for named args */
          if (add_named_var_to_ctxt (lexic2, pc->x.str_val, pc2) == NULL)
            goto error;
          if (nasl_trace_fp != NULL && trace_buf_len < TRACE_BUF_SZ)
            {
              tn = snprintf (trace_buf + trace_buf_len,
                             TRACE_BUF_SZ - trace_buf_len, "%s%s: %s",
                             nb_a > 0 ? ", " : "", pc->x.str_val,
                             dump_cell_val (pc2));
              if (tn > 0)
                trace_buf_len += tn;
            }
          nb_a++;
        }
      deref_cell (pc2);
    }

  if (nasl_trace_fp != NULL)
    {
      if (trace_buf_len < TRACE_BUF_SZ)
        nasl_trace (lexic, "NASL> %s)\n", trace_buf);
      else
        nasl_trace (lexic, "NASL> %s ...)\n", trace_buf);
    }
  /* trace_buf freed here because nasl_trace_fp might get set to NULL during the
   * execution of nasl_func_call and therefore not get freed if we only free in
   * the previous if block. This is done to make static analyzer happy. */
  g_free (trace_buf);

  /* 4. Chain new context to old (lexic) */
  lexic2->up_ctxt = lexic;
  /* 5. Execute */
  tmp_filename = g_strdup (nasl_get_filename (NULL));
  nasl_set_filename (nasl_get_filename (f->func_name));
  if (func_is_internal (f->func_name))
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
      // unless it is arcane system this void casting should work
      // therefore ignoring pedantic here.
      tree_cell *(*pf2) (lex_ctxt *) = f->block;
#pragma GCC diagnostic pop
      retc = pf2 (lexic2);
    }
  else
    {
      temp_funname = g_strdup (nasl_get_function_name ());
      nasl_set_function_name (f->func_name);
      retc = nasl_exec (lexic2, f->block);
      deref_cell (retc);
      retc = FAKE_CELL;
      nasl_set_function_name (temp_funname);
      g_free (temp_funname);
    }
  nasl_set_filename (tmp_filename);
  g_free (tmp_filename);

  if ((retc == NULL || retc == FAKE_CELL)
      && (lexic2->ret_val != NULL && lexic2->ret_val != FAKE_CELL))
    {
      retc = lexic2->ret_val;
      ref_cell (retc);
    }

  if (nasl_trace_enabled ())
    nasl_trace (lexic, "NASL> Return %s: %s\n", f->func_name,
                dump_cell_val (retc));
  if (!nasl_is_leaf (retc))
    {
      nasl_perror (lexic,
                   "nasl_func_call: return value from %s is not atomic!\n",
                   f->func_name);
      nasl_dump_tree (retc);
    }

  free_lex_ctxt (lexic2);
  lexic2 = NULL;
  return retc;

error:
  g_free (trace_buf);
  free_lex_ctxt (lexic2);
  return NULL;
}

tree_cell *
nasl_return (lex_ctxt *ctxt, tree_cell *retv)
{
  tree_cell *c;

  retv = cell2atom (ctxt, retv);
  if (retv == NULL)
    retv = FAKE_CELL;

  if (retv != FAKE_CELL && retv->type == REF_ARRAY)
    /* We have to "copy" it as the referenced array will be freed */
    {
      c = copy_ref_array (retv);
      deref_cell (retv);
      retv = c;
    }

  while (ctxt != NULL)
    {
      ctxt->ret_val = retv;
      ref_cell (retv);
      if (ctxt->fct_ctxt)
        break;
      ctxt = ctxt->up_ctxt;
    }
  /* Bug? Do not return NULL, as we may test it to break the control flow */
  deref_cell (retv);
  return FAKE_CELL;
}

void
free_func (nasl_func *f)
{
  if (!f)
    return;

  g_free (f->func_name);
  g_free (f);
}
