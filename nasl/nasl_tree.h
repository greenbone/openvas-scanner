/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
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
 */

#ifndef NASLTREE_H_INCLUDED
#define NASLTREE_H_INCLUDED


enum node_type
{
  NODE_EMPTY = 0,
  NODE_IF_ELSE,                 /* [0] = cond, [1] = if_block, [2] = else_block */
  NODE_INSTR_L,                 /* Block. [0] = first instr, [1] = tail */
  NODE_FOR,                     /* [0] = start expr, [1] = cond, [2] = end_expr, [3] = block */
  NODE_WHILE,                   /* [0] = cond, [1] = block */
  NODE_FOREACH,
  NODE_REPEAT_UNTIL,
  NODE_REPEATED,                /* [0] = func call, [1] = repeat nb */
  NODE_FUN_DEF,                 /* [0] = argdecl, [1] = block */
  NODE_FUN_CALL,                /* [0] = arglist */
  NODE_DECL,                    /* [0] = next arg in list */
  NODE_ARG,                     /* val = name can be NULL, [0] = val, [1] = next arg */
  NODE_RETURN,                  /* ret val */
  NODE_BREAK,
  NODE_CONTINUE,

  NODE_ARRAY_EL,                /* val = array name, [0] = index */
  NODE_AFF,                     /* [0] = lvalue, [1] = rvalue */
  NODE_VAR,                     /* val = variable name */
  NODE_LOCAL,                   /* [0] = argdecl */
  NODE_GLOBAL,

  NODE_PLUS_EQ,
  NODE_MINUS_EQ,
  NODE_MULT_EQ,
  NODE_DIV_EQ,
  NODE_MODULO_EQ,

  NODE_L_SHIFT_EQ,
  NODE_R_SHIFT_EQ,
  NODE_R_USHIFT_EQ,

  EXPR_AND,
  EXPR_OR,
  EXPR_NOT,

  EXPR_PLUS,
  EXPR_MINUS,
  EXPR_U_MINUS,
  EXPR_MULT,
  EXPR_DIV,
  EXPR_MODULO,
  EXPR_EXPO,

  EXPR_BIT_AND,
  EXPR_BIT_OR,
  EXPR_BIT_XOR,
  EXPR_BIT_NOT,
  EXPR_INCR,
  EXPR_DECR,
  EXPR_L_SHIFT,
  EXPR_R_SHIFT,
  EXPR_R_USHIFT,

  COMP_MATCH,
  COMP_NOMATCH,
  COMP_RE_MATCH,
  COMP_RE_NOMATCH,

  COMP_LT,
  COMP_LE,
  COMP_EQ,
  COMP_NE,
  COMP_GT,
  COMP_GE,

  CONST_INT,
  CONST_STR,                    /* "impure" string */

  CONST_DATA,                   /* binary data / "pure" string */
  CONST_REGEX,                  /* Compiled regex */

  ARRAY_ELEM,                   /* val = char index or NULL if integer,
                                 * [0] = value, [1] = next element */
  /* For exec only */
  REF_VAR,
  REF_ARRAY,
  DYN_ARRAY
};

typedef struct TC
{
  short type;
  short line_nb;
  short ref_count;              /* Cell is freed when count reaches zero */
  int size;
  union
  {
    char *str_val;
    long int i_val;
    void *ref_val;              /* internal reference */
  } x;
  struct TC *link[4];
} tree_cell;

#define FAKE_CELL	((void*)1)
#define EXIT_CELL	((void*)2)

tree_cell *alloc_tree_cell (int, char *);
tree_cell *alloc_expr_cell (int, int, tree_cell *, tree_cell *);
tree_cell *alloc_RE_cell (int, int, tree_cell *, char *);
tree_cell *alloc_typed_cell (int);
int nasl_is_leaf (const tree_cell *);
char *get_line_nb (const tree_cell *);
tree_cell *dup_cell (const tree_cell *);
void nasl_dump_tree (const tree_cell *);
void ref_cell (tree_cell *);
void deref_cell (tree_cell *);
const char *nasl_type_name (int);
int cell_type (const tree_cell *);

char *dump_cell_val (const tree_cell *);


#endif
