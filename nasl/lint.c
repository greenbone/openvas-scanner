/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2004 Michel Arboi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "lint.h"

#include "exec.h"
#include "nasl.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_init.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/**
 * @brief Define struct to store information about a called function.
 */
typedef struct st_func_info
{
  gchar *func_name;   /**< Function name */
  gchar *caller_func; /**< Name of the function from where it is called */
  gchar *caller_file; /**< Name of the file from where it is called */
} func_info;

char *nasl_name;

int errors_cnt;
static void
init_errors_cnt ()
{
  errors_cnt = 0;
}
static void
inc_errors_cnt ()
{
  errors_cnt++;
  return;
}
static int
get_errors_cnt ()
{
  return errors_cnt;
}

/**
 * @brief Free a func_info structure.
 *
 * @param[in] defined_var List with all defined variables
 *
 */
static void
free_list_func (func_info *data)
{
  g_free (data->func_name);
  g_free (data->caller_func);
  g_free (data->caller_file);
  memset (data, '\0', sizeof (func_info));
}

/**
 * @brief Add keywords to the varnames list.
 *
 * @param[in,out] defined_var List with all defined variables
 *
 */
static void
add_predef_varname (GSList **defined_var)
{
  int i;
  gchar *keywords[] = {"ACT_UNKNOWN",  "description",    "NULL", "SCRIPT_NAME",
                       "COMMAND_LINE", "_FCT_ANON_ARGS", NULL};

  for (i = 0; keywords[i] != NULL; i++)
    *defined_var = g_slist_prepend (*defined_var, keywords[i]);
  add_nasl_library (defined_var);
}

/**
 * @brief This function is called by g_slist_find_custom.
 *
 * @param[in] lelem Element of GSList.
 * @param[in] data func_info structure to be found.
 *
 * @return 0 on success, non 0 otherwise.
 */
static gint
list_cmp1 (gconstpointer lelem, gconstpointer data)
{
  if (data)
    {
      gchar *lala = g_strdup (((func_info *) lelem)->func_name);
      return (g_strcmp0 (lala, data));
    }
  return -1;
}

/**
 * @brief Check if an undefined called function is needed or not.
 *        This is the case in which the function is called from a
 *        nested and defined function but never called.
 * @return 1 if the function is needed, 0 otherwise.
 */
static gint
reverse_search (GSList **def_func_tree, GSList *finfo)
{
  func_info *fdata = finfo->data;
  GSList *finfo_aux;

  // The file name is the original file to be tested. It is not an include.
  if (!g_strcmp0 (fdata->caller_file, nasl_name)
      && !g_str_has_suffix (nasl_name, ".inc"))
    return 1;

  // The function is it self.
  if (!g_strcmp0 (fdata->func_name, fdata->caller_func))
    return 0;

  // I go up in the tree of called and defined functions.
  if ((finfo_aux = g_slist_find_custom (*def_func_tree, fdata->caller_func,
                                        (GCompareFunc) list_cmp1))
      != NULL)
    if (reverse_search (def_func_tree, finfo_aux))
      return 1;

  return 0;
}

/**
 * @brief This function is called by g_slist_find_custom.
 *
 * @param[in] lelem Element of GSList.
 * @param[in] data str to be found in the list.
 *
 * @return 0 on success, non 0 otherwise.
 */
static gint
list_cmp (gconstpointer lelem, gconstpointer data)
{
  if (data)
    return (g_strcmp0 (lelem, data));
  return -1;
}

/**
 * @brief This function is called by g_hash_table_foreach to check if
 *        an include file was used or not. If the file is not used, it is added
 *        to a list.
 *
 * @param[in] key Element key of GHashTable.
 * @param[in] value Element value for a key of GHashTable.
 * @param[in] unusedfiles List with unused .inc files.
 *
 */
static void
check_called_files (gpointer key, gpointer value, GSList **unusedfiles)
{
  if (key != NULL)
    // only check for includes not for main file
    if (nasl_get_include_order ((const char *) key) > 0
        && g_strcmp0 (value, "YES") != 0)
      *unusedfiles = g_slist_prepend (*unusedfiles, key);
}

/**
 * @brief It shows a msg for unused included files.
 *
 * @param[in] filename Filename of the not used inc file.
 * @param[in] lexic nasl context.
 *
 */
static void
print_uncall_files (gpointer filename, gpointer lexic)
{
  if (filename != NULL)
    {
      nasl_perror (lexic, "The included file '%s' is never used.",
                   (char *) filename);
      inc_errors_cnt ();
      lexic = NULL;
    }
}

/**
 * @brief Loads all defined functions. Also, It constructs a tree of called
 *        functions to help recognize a not defined function which is never
 *        called (nested functions).
 */
static tree_cell *
nasl_lint_def (lex_ctxt *lexic, tree_cell *st, int lint_mode,
               GHashTable **include_files, GHashTable **func_fnames_tab,
               gchar *err_fname, GSList **called_funcs, GSList **def_func_tree)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  char *incname = NULL;
  gchar *tmp_filename = NULL;
  nasl_func *pf;
  static gchar *current_fun_def = NULL;

  if (st->type == NODE_FUN_CALL)
    {
      pf = get_func_ref_by_name (lexic, st->x.str_val);
      if (pf == NULL)
        {
          g_hash_table_insert (*func_fnames_tab, g_strdup (st->x.str_val),
                               g_strdup (err_fname));
        }

      /* Save in a list the name of the called function, the file where it
         is called from, and the function where it is called from. This will
         help to know if a called function is really needed, or it was just
         called by another defined function which is never called. */
      func_info *finfo = g_malloc0 (sizeof (func_info));
      finfo->func_name = g_strdup (st->x.str_val);
      finfo->caller_file = g_strdup (err_fname ? err_fname : nasl_name);
      finfo->caller_func = g_strdup (current_fun_def);
      *def_func_tree = g_slist_prepend (*def_func_tree, finfo);
      /* Check if function parameters are used multiple times. Only check
       * this if we are in lint mode 1 to not check it multiple times. */
      if (lint_mode == 1)
        {
          GSList *func_params = NULL;
          int linenum = st->line_nb;
          tree_cell *args = st->link[0];
          for (; args != NULL; args = args->link[1])
            {
              if (args->x.str_val)
                {
                  /* Check if param was already used */
                  if (!g_slist_find_custom (func_params, args->x.str_val,
                                            (GCompareFunc) list_cmp))
                    func_params =
                      g_slist_prepend (func_params, args->x.str_val);
                  else
                    {
                      g_message ("%s: Error at or near line %d. "
                                 "Parameter \"%s\" passed to function \"%s\" "
                                 "was provided multiple times.",
                                 finfo->caller_file, linenum, args->x.str_val,
                                 finfo->func_name);
                      g_slist_free (func_params);
                      return NULL;
                    }
                }
            }
          g_slist_free (func_params);
        }
    }

  switch (st->type)
    {
    case NODE_FUN_DEF:
      /* with lint_mode = 0 check if this function was declared twice*/
      if (lint_mode == 0)
        {
          if (decl_nasl_func (lexic, st, lint_mode) == NULL)
            ret = NULL;
          return ret;
        }
      /* Check if it was already added */
      if (!g_slist_find_custom (*called_funcs, st->x.str_val,
                                (GCompareFunc) list_cmp))
        {
          return FAKE_CELL;
        }

      /* x.str_val = function name, [0] = argdecl, [1] = block */
      decl_nasl_func (lexic, st, lint_mode);
      current_fun_def = g_strdup (st->x.str_val);
      incname = g_strdup (nasl_get_filename (st->x.str_val));
      g_hash_table_replace (*include_files, incname, g_strdup ("NO"));
      tmp_filename = g_strdup (nasl_get_filename (NULL));
      err_fname = g_strdup (incname);
      /* fallthrough */

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_def (lexic, st->link[i], lint_mode,
                                    include_files, func_fnames_tab, err_fname,
                                    called_funcs, def_func_tree))
              == NULL)
            return NULL;

      if (st->type == NODE_FUN_DEF)
        {
          if (tmp_filename)
            nasl_set_filename (tmp_filename);
          g_free (tmp_filename);
        }
      return ret;
    }
}

/**
 * @brief Checks if a given Arguments is within a given Argument List
 *
 * @param st Argument List, should be of Type NODE_ARG
 * @param name Name of the Argument to search for
 * @return char* Value of the given Argument name
 */
static char *
get_argument_by_name (tree_cell *st, char *name)
{
  if (st == NULL)
    return NULL;

  if (st->type != NODE_ARG)
    return NULL;

  tree_cell *cp;
  for (cp = st; cp != NULL; cp = cp->link[1])
    {
      if (!g_strcmp0 (cp->x.str_val, name))
        return cp->link[0]->x.str_val;
    }

  return NULL;
}

/**
 * @brief Validates parameters of a script_xref function call
 *
 * @param lexic
 * @param st Function Parameters should be of type NODE_ARG
 * @return tree_cell*
 */
static tree_cell *
validate_script_xref (lex_ctxt *lexic, tree_cell *st)
{
  char *name = get_argument_by_name (st, "name");
  char *value = get_argument_by_name (st, "value");
  char *csv = get_argument_by_name (st, "csv");

  if (((value == NULL) && (csv == NULL)) || name == NULL)
    {
      nasl_perror (lexic,
                   "script_xref() syntax error - should be"
                   " script_xref(name:<name>, value:<value>) or"
                   " script_xref(name:<name>, value:<value>, csv:<CSVs>) or"
                   " script_xref(name:<name>, csv:<CSVs>)\n");
      if (name == NULL)
        {
          nasl_perror (lexic, "  <name> is empty\n");
        }
      else
        {
          nasl_perror (lexic, "  <name> is %s\n", name);
        }
      if ((value == NULL) && (csv == NULL))
        {
          nasl_perror (lexic, "  <value> and <csv> is empty)\n");
        }
      else
        {
          nasl_perror (lexic, "  <value> is %s\n)", value);
          nasl_perror (lexic, "  <csv> is %s\n)", csv);
        }
      return NULL;
    }
  return FAKE_CELL;
}

/**
 * @brief Validate functions
 *
 * @param lexic
 * @param st
 * @return tree_cell * NULL if it is invalid, FAKE_CELL if it is valid
 */
static tree_cell *
validate_function (lex_ctxt *lexic, tree_cell *st)
{
  lexic->line_nb = st->line_nb;
  if (st != NULL)
    {
      if (!g_strcmp0 (st->x.str_val, "script_xref"))
        return validate_script_xref (lexic, st->link[0]);
    }
  else
    return NULL;

  return FAKE_CELL;
}

/**
 * @brief Returns 1 if the function is at least used once by another caller than
 * filename otherwise 0.
 */
static int
is_deffunc_used (const char *funcname, const char *filename,
                 GSList *def_func_tree)
{
  func_info *element;
  GSList *current = def_func_tree;

  if (current == NULL)
    return 0;

  do
    {
      element = current->data;
      if (g_strcmp0 (element->func_name, funcname) == 0
          && g_strcmp0 (element->caller_file, filename) != 0)
        return 1;
      current = current->next;
    }
  while (current != NULL && current->next != NULL);
  return 0;
}

int features = 0;

void
nasl_lint_feature_flags (int flag)
{
  features = flag;
}

/**
 * @brief Check if a called function was defined.
 */
static tree_cell *
nasl_lint_call (lex_ctxt *lexic, tree_cell *st, GHashTable **include_files,
                GHashTable **func_fnames_tab, gchar *err_fname,
                GSList **called_funcs, GSList **def_func_tree)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  nasl_func *pf;
  char *incname = NULL;
  int f_inc_ord, c_inc_order, rc = 0;
  static int defined_flag = 0;

  /** This checks if a defined function is called. If it is never called
   * it does not go deeper.
   */
  if (st->type == NODE_FUN_DEF)
    {
      if (!g_slist_find_custom (*called_funcs, st->x.str_val,
                                (GCompareFunc) list_cmp))
        {
          return FAKE_CELL;
        }
    }

  switch (st->type)
    {
    case CONST_DATA:
    case CONST_STR:
      if (st->x.str_val != NULL && defined_flag == 1)
        {
          decl_nasl_func (lexic, st, 1);
          defined_flag = 0;
        }
      return FAKE_CELL;

    case NODE_FUN_CALL:
      pf = get_func_ref_by_name (lexic, st->x.str_val);

      if (pf == NULL)
        {
          incname = g_hash_table_lookup (*func_fnames_tab, st->x.str_val);

          nasl_set_filename (incname ? incname : "unknown");
          lexic->line_nb = st->line_nb;

          GSList *called_f_aux;
          called_f_aux = g_slist_find_custom (*def_func_tree, st->x.str_val,
                                              (GCompareFunc) list_cmp1);
          if (called_f_aux != NULL)
            {
              if (reverse_search (def_func_tree, called_f_aux))
                {
                  nasl_perror (lexic, "Undefined function '%s'\n",
                               st->x.str_val);
                  return NULL;
                }
            }
        }
      else
        {
          // only check functions that are not internal
          if ((features & NLFF_STRICT_INCLUDES)
              && func_is_internal (st->x.str_val) == NULL)
            {
              // get incname verify include order when not 0
              incname = (char *) nasl_get_filename (st->x.str_val);
              if (incname != NULL)
                {
                  f_inc_ord = nasl_get_include_order (incname);
                  c_inc_order = nasl_get_include_order (st->name);
                  // if caller definition is not the main file but included
                  // before the function definition warn about an include error
                  if (c_inc_order > 0 && c_inc_order < f_inc_ord)
                    {
                      nasl_perror (
                        lexic, "%s must be included after %s (usage of %s).",
                        st->name, incname, st->x.str_val);
                      rc = -1;
                    }
                }
            }
          // Check if function parameters are right
          if (validate_function (lexic, st) == NULL)
            return NULL;
        }
      if (*include_files && st->x.str_val)
        {
          if (g_hash_table_lookup (*include_files,
                                   nasl_get_filename (st->x.str_val)))
            {
              incname = g_strdup (nasl_get_filename (st->x.str_val));
              if (is_deffunc_used (st->x.str_val, incname, *def_func_tree))
                {
                  g_hash_table_replace (*include_files, incname,
                                        g_strdup ("YES"));
                }
            }
        }
      if (g_strcmp0 (st->x.str_val, "defined_func") == 0)
        defined_flag = 1;
      /* fallthrough */

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = nasl_lint_call (lexic, st->link[i], include_files,
                                     func_fnames_tab, err_fname, called_funcs,
                                     def_func_tree))
              == NULL)
            return NULL;
      return rc == 0 ? ret : NULL;
    }
}

/**
 * @brief Consider all cases in which a variable is set, and add it to a list.
 *        If a variable is read, it checks if it was previously added to the
 *        list.
 */
static tree_cell *
nasl_lint_defvar (lex_ctxt *lexic, tree_cell *st, GHashTable **include_files,
                  GHashTable **func_fnames_tab, gchar *err_fname,
                  GSList **defined_var, GSList **called_funcs)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  static int defined_fn_mode = 0;
  static int defined_var_mode = 0;
  static int def_glob_var = 0;
  static GSList *local_var_list = NULL;

  /** This checks if a defined function is called. If it is never called
   * it does not go deeper.
   */
  if (st->type == NODE_FUN_DEF)
    {
      if (!g_slist_find_custom (*called_funcs, st->x.str_val,
                                (GCompareFunc) list_cmp))
        {
          return FAKE_CELL;
        }
    }

  if ((defined_fn_mode == 1 || def_glob_var) && st->type != NODE_DECL)
    {
      defined_fn_mode = 0;
      def_glob_var = 0;
    }

  /* A variable will be defined, then set the mode variable. */
  if ((st->type == NODE_AFF || st->type == EXPR_NOT || st->type == EXPR_INCR
       || st->type == NODE_PLUS_EQ)
      && defined_var_mode == 0)
    defined_var_mode = 1;
  else if ((st->type == NODE_FUN_DEF || st->type == NODE_LOCAL
            || st->type == NODE_FUN_CALL)
           && defined_fn_mode == 0)
    {
      defined_fn_mode = 1;
      defined_var_mode = 0;
    }

  else if (st->type == NODE_GLOBAL)
    def_glob_var = 1;

  /* The variable is being defined. Therefore is save into the
   * global list only if was not previously added in local list.
   */
  else if ((st->type == NODE_VAR || st->type == NODE_ARRAY_EL)
           && (defined_var_mode == 1 || defined_fn_mode == 1))
    {
      if (st->x.str_val != NULL)
        {
          if (!g_slist_find_custom (local_var_list, st->x.str_val,
                                    (GCompareFunc) list_cmp))
            *defined_var = g_slist_prepend (*defined_var, st->x.str_val);
          defined_var_mode = 0;
        }
    }
  /** It is a local variable and it is added in special list,
   *  which will be cleaned at the end of the function.
   */
  else if (st->type == NODE_DECL && st->x.str_val != NULL)
    {
      if (defined_fn_mode == 1)
        {
          local_var_list = g_slist_prepend (local_var_list, st->x.str_val);
        }
      if (def_glob_var == 1)
        {
          *defined_var = g_slist_prepend (*defined_var, st->x.str_val);
        }
    }
  /* Special case foreach. */
  else if (st->type == NODE_FOREACH)
    {
      // Hacky way of checking if we are in a function definition by checking
      // if local_var_list is non empty. Otherwise all variables declared in a
      // foreach call are considered file scope which leads to false negatives.
      if (st->x.str_val != NULL && local_var_list != NULL)
        {
          local_var_list = g_slist_prepend (local_var_list, st->x.str_val);
        }
      else if (st->x.str_val != NULL)
        {
          *defined_var = g_slist_prepend (*defined_var, st->x.str_val);
        }
    }

  // The variable is used. It checks if the variable was defined
  // Also check for NODE_ARRAY_EL to catch use of undeclared array.
  // E.g "if(foo[0]) {}" and foo was not declared previously.
  else if ((st->type == NODE_VAR || st->type == NODE_ARRAY_EL)
           && defined_var_mode == 0)
    {
      if (!g_slist_find_custom (*defined_var, st->x.str_val,
                                (GCompareFunc) list_cmp)
          && !g_slist_find_custom (local_var_list, st->x.str_val,
                                   (GCompareFunc) list_cmp))
        {
          lexic->line_nb = st->line_nb;
          nasl_perror (lexic, "The variable %s was not declared",
                       st->x.str_val);
          inc_errors_cnt ();
        }
    }

  for (i = 0; i < 4; i++)
    if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
      if ((ret = nasl_lint_defvar (lexic, st->link[i], include_files,
                                   func_fnames_tab, err_fname, defined_var,
                                   called_funcs))
          == NULL)
        return NULL;

  /** Leaving the function definition, the local variables list
   *  is cleaned.
   */
  if (st->type == NODE_FUN_DEF)
    {
      g_slist_free (local_var_list);
      local_var_list = NULL;
    }

  return ret;
}
/**
 * @brief Make a list of all called functions.
 */
static tree_cell *
make_call_func_list (lex_ctxt *lexic, tree_cell *st, GSList **called_funcs)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  nasl_func *pf = NULL;

  switch (st->type)
    {
    case NODE_FUN_CALL:
      pf = get_func_ref_by_name (lexic, st->x.str_val);
      if (st->x.str_val && !pf)
        {
          *called_funcs =
            g_slist_prepend (*called_funcs, g_strdup (st->x.str_val));
        }
      /* fallthrough */

    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = make_call_func_list (lexic, st->link[i], called_funcs))
              == NULL)
            return NULL;
      return ret;
    }
}

/**
 * @brief Sanity check of the script_xref parameters in the description block
 */
static tree_cell *
check_description_block_xref (lex_ctxt *lexic, tree_cell *st)
{
  int i;
  tree_cell *ret = FAKE_CELL;

  switch (st->type)
    {
    case CONST_STR:
      if (g_strrstr (st->x.str_val, ", ") != NULL)
        {
          g_message ("%s: An error in script_xrefs function was found. "
                     "Spaces after a comma are not allow in xrefs names "
                     "or values: '%s'",
                     nasl_get_filename (st->x.str_val), st->x.str_val);
          return NULL;
        }
      /* fallthrough */
    default:
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = check_description_block_xref (lexic, st->link[i])) == NULL)
            return NULL;
    }
  return ret;
}

/**
 * @brief Sanity check of the description block
 * @return FAKE_CELL if success, NULL otherwise.
 */
static tree_cell *
check_description_block (lex_ctxt *lexic, tree_cell *st)
{
  int i;
  tree_cell *ret = FAKE_CELL;

  if (st->type == NODE_FUN_CALL)
    if (!g_strcmp0 (st->x.str_val, "script_xref"))
      if ((ret = check_description_block_xref (lexic, st)) == NULL)
        return NULL;

  for (i = 0; i < 4; i++)
    if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
      if ((ret = check_description_block (lexic, st->link[i])) == NULL)
        return NULL;

  return ret;
}

/**
 * @brief Sanity check of the description block
 *
 * @return pointer to the description block tree cell.
 */
static tree_cell *
find_description_block (lex_ctxt *lexic, tree_cell *st)
{
  int i;
  tree_cell *ret = FAKE_CELL;
  tree_cell *st_aux = NULL;

  if (st && st->type == NODE_IF_ELSE)
    {
      for (i = 0; i < 4; i++)
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          {
            st_aux = st->link[i];
            if (st_aux->type == NODE_VAR
                && !g_strcmp0 (st_aux->x.str_val, "description"))
              return st;
          }
    }
  else
    for (i = 0; i < 4; i++)
      {
        if (st->link[i] != NULL && st->link[i] != FAKE_CELL)
          if ((ret = find_description_block (lexic, st->link[i])) == NULL)
            return NULL;
        return ret;
      }
  return NULL;
}

/**
 * @brief Search for errors in a nasl script
 *
 * @param[in] lexic nasl context.
 * @param[in] st structure tree of a nasl script.
 *
 * @return FAKE_CELL if no error was found, otherwise NULL or tree_cell which
 *  has number of errors as x.i_val.
 */
tree_cell *
nasl_lint (lex_ctxt *lexic, tree_cell *st)
{
  lex_ctxt *lexic_aux;
  tree_cell *ret = FAKE_CELL;
  int lint_mode = 1;
  GHashTable *include_files = NULL;
  GHashTable *func_fnames_tab = NULL;
  GSList *unusedfiles = NULL;
  GSList *called_funcs = NULL;
  GSList *def_func_tree = NULL;
  gchar *err_fname = NULL;
  tree_cell *desc_block = FAKE_CELL;
  init_errors_cnt ();

  nasl_name = g_strdup (nasl_get_filename (st->x.str_val));
  include_files =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  func_fnames_tab =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  lexic_aux = init_empty_lex_ctxt ();
  lexic_aux->script_infos = lexic->script_infos;
  lexic_aux->oid = lexic->oid;

  /* Check description block sanity. */
  desc_block = find_description_block (lexic_aux, st);
  if (desc_block != NULL && desc_block != FAKE_CELL)
    {
      /* FAKE_CELL if success, NULL otherwise which counts as error */
      if (check_description_block (lexic_aux, desc_block) == NULL)
        {
          inc_errors_cnt ();
        }
    }
  /* Make a list of all called functions */
  make_call_func_list (lexic_aux, st, &called_funcs);

  /* Loads all defined functions. */
  if (nasl_lint_def (lexic_aux, st, lint_mode, &include_files, &func_fnames_tab,
                     err_fname, &called_funcs, &def_func_tree)
      == NULL)
    {
      inc_errors_cnt ();
    }
  /* Check if a called function was defined. */

  if (nasl_lint_call (lexic_aux, st, &include_files, &func_fnames_tab,
                      err_fname, &called_funcs, &def_func_tree)
      == NULL)
    {
      inc_errors_cnt ();
    }

  /* Check if the included files are used or not. */
  g_hash_table_foreach (include_files, (GHFunc) check_called_files,
                        &unusedfiles);
  if (unusedfiles != NULL)
    g_slist_foreach (unusedfiles, (GFunc) print_uncall_files, lexic_aux);
  if ((g_slist_length (unusedfiles)) > 0)
    {
      inc_errors_cnt ();
    }

  /* Now check that each function was loaded just once. */
  lint_mode = 0;
  if (nasl_lint_def (lexic, st, lint_mode, &include_files, &func_fnames_tab,
                     err_fname, &called_funcs, &def_func_tree)
      == NULL)
    {
      inc_errors_cnt ();
    }

  /* Check if a variable was declared. */
  GSList *defined_var = NULL;
  add_predef_varname (&defined_var);
  ret = nasl_lint_defvar (lexic_aux, st, &include_files, &func_fnames_tab,
                          err_fname, &defined_var, &called_funcs);
  g_slist_free (defined_var);
  defined_var = NULL;

  g_slist_free (called_funcs);
  called_funcs = NULL;
  g_slist_free_full (def_func_tree, (GDestroyNotify) free_list_func);
  def_func_tree = NULL;
  g_hash_table_destroy (include_files);
  include_files = NULL;
  g_hash_table_destroy (func_fnames_tab);
  func_fnames_tab = NULL;
  g_free (err_fname);
  g_slist_free (unusedfiles);
  unusedfiles = NULL;
  free_lex_ctxt (lexic_aux);

  if (get_errors_cnt () > 0)
    {
      ret = alloc_typed_cell (NODE_VAR);
      ret->x.i_val = get_errors_cnt ();
    }

  return ret;
}
