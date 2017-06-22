/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <search.h>             /* for qsort, lfind */
#include <stdlib.h>             /* for free */
#include <string.h>             /* for strcmp */

#include <glib.h>               /* for g_free */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"

/**
 * @brief This function climbs up in the context list and searches for a given
 * @brief function.
 */
static nasl_func *
get_func (lex_ctxt * ctxt, const char *name)
{
  lex_ctxt *c;

  for (c = ctxt; c != NULL; c = c->up_ctxt)
    {
      nasl_func *v = g_hash_table_lookup (c->functions, name);

      if (v)
        return v;
    }

  return NULL;
}

typedef int(*qsortcmp)(const void *, const void *);

nasl_func *
insert_nasl_func (lex_ctxt * lexic, const char *fname, tree_cell * decl_node, int lint_mode)
{
  int i;
  nasl_func *pf;
  tree_cell *pc;

  if (get_func (lexic, fname))
    {
      if (lint_mode == 0)
        nasl_perror (lexic,
                     "insert_nasl_func: function '%s' is already defined\n",
                     fname);
      return NULL;
    }
  pf = g_malloc0 (sizeof (nasl_func));
  pf->func_name = g_strdup (fname);

  if (decl_node != NULL && decl_node != FAKE_CELL)
    {
      int nb_named_args = 0;
      for (pc = decl_node->link[0]; pc != NULL; pc = pc->link[0])
        if (pc->x.str_val == NULL)
          pf->nb_unnamed_args++;
        else
          nb_named_args++;

      pf->args_names = g_malloc0 (sizeof (char *) * (nb_named_args + 1));
      for (i = 0, pc = decl_node->link[0]; pc != NULL; pc = pc->link[0])
        if (pc->x.str_val != NULL)
          pf->args_names[i++] = g_strdup (pc->x.str_val);

      pf->block = decl_node->link[1];
      ref_cell (pf->block);
    }
  /* Allow variable number of arguments for user defined functions */
  if (decl_node != NULL)
    pf->nb_unnamed_args = 9999;

  g_hash_table_insert (lexic->functions, pf->func_name, pf);
  return pf;
}

tree_cell *
decl_nasl_func (lex_ctxt * lexic, tree_cell * decl_node, int lint_mode)
{
  if (decl_node == NULL || decl_node == FAKE_CELL)
    {
      nasl_perror (lexic, "Cannot insert NULL or FAKE cell as function\n");
      return NULL;
    }

  if (insert_nasl_func (lexic, decl_node->x.str_val, decl_node, lint_mode) == NULL)
    return NULL;
  else
    return FAKE_CELL;
}

nasl_func *
get_func_ref_by_name (lex_ctxt * ctxt, const char *name)
{
  nasl_func *f;

  if ((f = get_func (ctxt, name)))
    return f;
  else
    return NULL;
}

static int
stringcompare (const void *a, const void *b)
{
  char **s1 = (char **) a, **s2 = (char **) b;
  return strcmp (*s1, *s2);
}

extern FILE *nasl_trace_fp;

tree_cell *
nasl_func_call (lex_ctxt * lexic, const nasl_func * f, tree_cell * arg_list)
{
  int nb_u = 0, nb_n = 0, nb_a = 0;
  tree_cell *pc = NULL, *pc2 = NULL, *retc = NULL;
  lex_ctxt *lexic2 = NULL;
  char *trace_buf = NULL;
  int trace_buf_len = 0, tn;
#define TRACE_BUF_SZ	255

#if 0
  nasl_dump_tree (arg_list);
#endif

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
    else
      {
        size_t num = g_strv_length (f->args_names);
        if (lfind
            (&pc->x.str_val, f->args_names, &num, sizeof (char *),
             stringcompare) != NULL)
          nb_n++;
      }

  if (nb_n + nb_u > f->nb_unnamed_args + (int) g_strv_length (f->args_names))
    nasl_perror (lexic, "Too many args for function '%s' [%dN+%dU > %dN+%dU]\n",
                 f->func_name, nb_n, nb_u, g_strv_length (f->args_names),
                 f->nb_unnamed_args);
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
              tn = snprintf (trace_buf + trace_buf_len, TRACE_BUF_SZ -
                             trace_buf_len, "%s%d: %s", nb_a > 0 ? ", " : "",
                             nb_u, dump_cell_val (pc2));
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
      g_free (trace_buf);
    }

  /* 4. Chain new context to old (lexic) */
  lexic2->up_ctxt = lexic;
  /* 5. Execute */
  if (f->flags & FUNC_FLAG_INTERNAL)
    {
      tree_cell *(*pf2) (lex_ctxt *) = f->block;
      retc = pf2 (lexic2);
    }
  else
    {
      retc = nasl_exec (lexic2, f->block);
      deref_cell (retc);
      retc = FAKE_CELL;
    }

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
  free_lex_ctxt (lexic2);
  return NULL;
}

tree_cell *
nasl_return (lex_ctxt * ctxt, tree_cell * retv)
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
  if (! f) return;

  g_free (f->func_name);

  if (!(f->flags & FUNC_FLAG_INTERNAL))
    {
      g_strfreev (f->args_names);
      deref_cell (f->block);
    }
  g_free (f);
}
