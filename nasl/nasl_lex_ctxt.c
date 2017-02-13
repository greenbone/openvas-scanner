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

#include <glib.h>  /* for g_free() */

#include "nasl_func.h"
#include "nasl_tree.h"
#include "nasl_var.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"

lex_ctxt *
init_empty_lex_ctxt ()
{
  lex_ctxt *c = g_malloc0 (sizeof (lex_ctxt));
  int i;

  c->ctx_vars.hash_elt = g_malloc0 (sizeof (named_nasl_var) * VAR_NAME_HASH);
  c->ctx_vars.num_elt = NULL;
  c->ctx_vars.max_idx = 0;
  for (i = 0; i < FUNC_NAME_HASH; i++)
    c->functions[i] = NULL;
  c->oid = NULL;
  c->ret_val = NULL;
  c->fct_ctxt = 0;
  return c;
}

void
free_lex_ctxt (lex_ctxt * c)
{
  int i;

#if 0
  if (c->exit_flag && c->up_ctxt != NULL)
    ((lex_ctxt *) c->up_ctxt)->exit_flag = 1;
#endif
  deref_cell (c->ret_val);
  free_array (&c->ctx_vars);
  for (i = 0; i < FUNC_NAME_HASH; i++)
    {
      free_func_chain (c->functions[i]);
    }
  g_free (c);
}

void
dump_ctxt (lex_ctxt * c)
{
  int i;
  named_nasl_var *v;
  nasl_func *f;

  printf ("--------<CTXT>--------\n");
  if (c->fct_ctxt)
    printf ("Is a function context\n");
  if (c->up_ctxt == NULL)
    printf ("Is the top level context\n");
  if (c->ret_val)
    {
      printf ("Return value\n");
      nasl_dump_tree (c->ret_val);
    }

  printf ("Variables:\n");
  for (i = 0; i < VAR_NAME_HASH; i++)
    for (v = c->ctx_vars.hash_elt[i]; v != NULL; v = v->next_var)
      printf ("%s\t", v->var_name);
  putchar ('\n');

  printf ("Functions:\n");
  for (i = 0; i < FUNC_NAME_HASH; i++)
    for (f = c->functions[i]; f != NULL; f = f->next_func)
      printf ("%s\t", f->func_name);
  putchar ('\n');

  printf ("----------------------\n");
}
