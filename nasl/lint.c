/* Nessus Attack Scripting Language "lint"
 *
 * Copyright (C) 2004 Michel Arboi
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

#include "nasl.h"
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"
#include "nasl_init.h"

#ifndef NASL_DEBUG
#define NASL_DEBUG 0
#endif

tree_cell *
nasl_lint_def (lex_ctxt * lexic, tree_cell * st, int lint_mode)
{
  int i;
  tree_cell *ret = FAKE_CELL;

  switch (st->type)
    {
    case NODE_FUN_DEF:
      if (lint_mode == 0)
        {
          if (decl_nasl_func (lexic, st, lint_mode) == NULL)
            ret = NULL;
          return ret;
        }

      /* x.str_val = function name, [0] = argdecl, [1] = block */
      decl_nasl_func (lexic, st, lint_mode);

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_def (lexic, st->link[i], lint_mode)) == NULL)
            return NULL;
      return ret;
    }
}


tree_cell *
nasl_lint_call (lex_ctxt * lexic, tree_cell * st)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  nasl_func *pf;


  switch (st->type)
    {
    case NODE_FUN_CALL:
      pf = get_func_ref_by_name (lexic, st->x.str_val);
      if (pf == NULL)
        {
          nasl_perror (lexic, "Undefined function '%s'\n", st->x.str_val);
          return NULL;
        }

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_call (lexic, st->link[i])) == NULL)
            return NULL;
      return ret;
    }
}


tree_cell *
nasl_lint (lex_ctxt * lexic, tree_cell * st)
{

  lex_ctxt * lexic_aux;
  tree_cell *ret = FAKE_CELL;
  int lint_mode = 1;

  lexic_aux = g_memdup (lexic, sizeof(struct struct_lex_ctxt));
  /* first loads all defined functions*/

  if ((ret = nasl_lint_def (lexic_aux, st, lint_mode)) == NULL)
    {
      g_free (lexic_aux);
      return ret;
    }
  /* check if a called function was defined */

  if ((ret = nasl_lint_call (lexic_aux, st)) == NULL)
     {
      g_free (lexic_aux);
      return ret;
     }

  /* now check that each function was loaded just once */
  lint_mode = 0;
  nasl_lint_def (lexic, st, lint_mode);

  g_free (lexic_aux);
  return ret;
}
