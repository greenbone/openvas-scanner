/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_NASL_LEX_CTXT_H
#define NASL_NASL_LEX_CTXT_H

#include <glib.h>

/* for tree_cell */
#include "nasl_tree.h"

/* for nasl_array */
#include "nasl_var.h"

/* for nasl_func */
#include "nasl_func.h"

typedef struct struct_lex_ctxt
{
  struct struct_lex_ctxt *up_ctxt;
  tree_cell *ret_val;      /* return value or exit flag */
  unsigned fct_ctxt : 1;   /* This is a function context */
  unsigned break_flag : 1; /* Break from loop */
  unsigned cont_flag : 1;  /* Next iteration in loop */
  unsigned always_signed : 1;
  struct script_infos *script_infos;
  const char *oid;
  int recv_timeout;
  int line_nb;
  /* Named variables hash set + anonymous variables array */
  nasl_array ctx_vars;
  /* Functions hash table */
  GHashTable *functions;
} lex_ctxt;

#define NASL_COMPAT_LEX_CTXT "NASL compat lex context"

lex_ctxt *
init_empty_lex_ctxt (void);

void
free_lex_ctxt (lex_ctxt *);

void
dump_ctxt (lex_ctxt *);

nasl_func *
get_func_ref_by_name (lex_ctxt *, const char *);

tree_cell *
decl_nasl_func (lex_ctxt *, tree_cell *, int);

nasl_func *
insert_nasl_func (lex_ctxt *, const char *, tree_cell *, int);

tree_cell *
nasl_func_call (lex_ctxt *, const nasl_func *, tree_cell *);

tree_cell *
get_variable_by_name (lex_ctxt *, const char *);

tree_cell *
get_array_elem (lex_ctxt *, const char * /*array name */, tree_cell *);

anon_nasl_var *
add_numbered_var_to_ctxt (lex_ctxt *, int, tree_cell *);

named_nasl_var *
add_named_var_to_ctxt (lex_ctxt *, const char *, tree_cell *);

tree_cell *
nasl_read_var_ref (lex_ctxt *, tree_cell *);

tree_cell *
nasl_incr_variable (lex_ctxt *, tree_cell *, int, int);

tree_cell *
nasl_return (lex_ctxt *, tree_cell *);

tree_cell *
decl_local_variables (lex_ctxt *, tree_cell *);

tree_cell *
decl_global_variables (lex_ctxt *, tree_cell *);

tree_cell *
cell2atom (lex_ctxt *, tree_cell *);

long int
get_int_var_by_num (lex_ctxt *, int, int);

char *
get_str_var_by_num (lex_ctxt *, int);

long int
get_int_var_by_name (lex_ctxt *, const char *, int);

char *
get_str_var_by_name (lex_ctxt *, const char *);

int
get_var_size_by_name (lex_ctxt *, const char *);

int
get_var_type_by_name (lex_ctxt *, const char *);

int
get_var_size_by_num (lex_ctxt *, int);

int
get_var_type_by_num (lex_ctxt *, int);

#endif
