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

#ifndef NASL_VAR_H_INCLUDED
#define NASL_VAR_H_INCLUDED

enum
{
  VAR2_UNDEF = 0,
  VAR2_INT,
  VAR2_STRING,
  VAR2_DATA,
  VAR2_ARRAY
};

#define VAR_NAME_HASH	17

typedef struct st_nasl_string
{
  unsigned char *s_val;
  int s_siz;
} nasl_string_t;

struct st_a_nasl_var;

typedef struct st_nasl_array
{
  int max_idx;                  /* max index - 1! */
  struct st_a_nasl_var **num_elt;       /* max_idx elements */
  struct st_n_nasl_var **hash_elt;      /* VAR_NAME_HASH elements */
} nasl_array;

#if NASL_DEBUG > 0
#define ALL_VARIABLES_NAMED
#endif

typedef struct st_a_nasl_var
{
  int var_type;
#ifdef ALL_VARIABLES_NAMED
  char *av_name;
#endif
  union
  {
    nasl_string_t v_str;        /* character string / data */
    long int v_int;             /* integer */
    nasl_array v_arr;           /* array */
  } v;
} anon_nasl_var;

typedef struct st_n_nasl_var
{
  struct st_a_nasl_var u;
#ifndef ALL_VARIABLES_NAMED
  char *var_name;
#else
#define var_name	u.av_name
#endif
  struct st_n_nasl_var *next_var;       /* next variable with same name hash */
} named_nasl_var;

typedef struct
{
  nasl_array *a;                /* array */
  int i1;                       /* index of numbered elements */
  int iH;                       /* index of hash */
  named_nasl_var *v;            /* current variable in hash */
} nasl_iterator;

tree_cell *nasl_affect (tree_cell *, tree_cell *);

void clear_unnamed_var (anon_nasl_var *);
const char *var2str (const anon_nasl_var *);

anon_nasl_var *nasl_get_var_by_num (void *, nasl_array *, int, int);

nasl_iterator nasl_array_iterator (void *, tree_cell *);
tree_cell *nasl_iterate_array (nasl_iterator *);
int add_var_to_list (nasl_array *, int, const anon_nasl_var *);
int add_var_to_array (nasl_array *, char *, const anon_nasl_var *);
int array_max_index (nasl_array *);
void free_array (nasl_array *);

tree_cell *copy_ref_array (const tree_cell *);
int hash_str2 (const char *, int);
tree_cell *var2cell (anon_nasl_var *);

tree_cell *make_array_from_elems (tree_cell *);
char *array2str (const nasl_array *);



#endif
