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

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"


/* It adds to a list the inc files, which have never been called. */
void
check_called_files (gpointer key, gpointer value, GSList **unusedfiles)
{
  if (key != NULL)
    if (!g_strcmp0 (value,("NO")))
      *unusedfiles = g_slist_append(*unusedfiles, key);
}

/* It lookups into a list for never called files, and it shows a msg. */
void
print_uncall_files (gpointer filename, gpointer lexic)
{
  if (filename != NULL)
    {
      nasl_perror (lexic, "The included file '%s' is never used.",
                   (char*)filename);
      lexic = NULL;
    }
}

tree_cell *
nasl_lint_def (lex_ctxt * lexic, tree_cell * st,
               int lint_mode, GHashTable **include_files)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  const char *incname = NULL;

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

      incname = nasl_get_filename (st->x.str_val);
      g_hash_table_replace (*include_files, g_strdup (incname), g_strdup("NO"));
      /* fallthrough */

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_def (lexic, st->link[i], lint_mode,
                                    include_files)) == NULL)
            return NULL;
      return ret;
    }
}

tree_cell *
nasl_lint_call (lex_ctxt * lexic, tree_cell * st, int *defined_flag,
                GHashTable **include_files)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  nasl_func *pf;
  const char *incname = NULL;

  switch (st->type)
    {
    case CONST_DATA:
    case CONST_STR:
      if (st->x.str_val != NULL && *defined_flag == 1)
        {
          decl_nasl_func (lexic, st, 1);
          *defined_flag = 0;
        }
      return FAKE_CELL;

    case NODE_FUN_CALL:
      pf = get_func_ref_by_name (lexic, st->x.str_val);
      if (pf == NULL)
        {
          lexic->line_nb = st->line_nb;
          nasl_perror (lexic, "Undefined function '%s'\n", st->x.str_val);
          return NULL;
        }

      if (*include_files && st->x.str_val)
       {
         if (g_hash_table_lookup (*include_files,
                                  g_strdup (nasl_get_filename (st->x.str_val))))
           {
             incname = nasl_get_filename (st->x.str_val);
             g_hash_table_replace (*include_files, g_strdup (incname),
                                   g_strdup("YES"));
           }
       }
      if (g_strcmp0 (st->x.str_val, "defined_func") == 0)
        *defined_flag = 1;
      /* fallthrough */

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_call (lexic, st->link[i], defined_flag,
                                     include_files)) == NULL)
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
  int defined_flag = 0;
  GHashTable *include_files = NULL;
  GSList *unusedfiles = NULL;

  include_files = g_hash_table_new_full
    (g_str_hash, g_str_equal, g_free, g_free);

  lexic_aux = init_empty_lex_ctxt ();
  lexic_aux->script_infos = lexic->script_infos;
  lexic_aux->oid = lexic->oid;

  /* First loads all defined functions. */
  if ((ret = nasl_lint_def (lexic_aux, st, lint_mode, &include_files)) == NULL)
    {
      free_lex_ctxt (lexic_aux);
      return ret;
    }

  /* Check if a called function was defined. */
  if ((ret = nasl_lint_call (lexic_aux, st, &defined_flag,
                             &include_files)) == NULL)
    {
      free_lex_ctxt (lexic_aux);
      return ret;
    }

  /* Check if the included files are used or not. */
  g_hash_table_foreach (include_files, (GHFunc)check_called_files,
                        &unusedfiles);
  if (unusedfiles != NULL)
    g_slist_foreach (unusedfiles, (GFunc)print_uncall_files, lexic);
  if ((g_slist_length (unusedfiles)) > 0)
    {
      g_hash_table_remove_all (include_files);
      g_slist_free (unusedfiles);
      free_lex_ctxt (lexic_aux);
      return NULL;
    }
  g_hash_table_remove_all (include_files);
  g_slist_free (unusedfiles);

  /* Now check that each function was loaded just once. */
  lint_mode = 0;
  nasl_lint_def (lexic, st, lint_mode, &include_files);

  free_lex_ctxt (lexic_aux);
  return ret;
}
