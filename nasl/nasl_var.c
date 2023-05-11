/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_var.h"

#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"

#include <glib.h>   /* for g_free */
#include <stdlib.h> /* for abort */
#include <string.h> /* for strlen */

/* Local prototypes */
static void
copy_array (nasl_array *, const nasl_array *, int);

/** @TODO Consider using GLibs string hash function. */
int
hash_str2 (const char *s, int n)
{
  unsigned long h = 0;
  const char *p;

  if (s == NULL)
    return 0;

  for (p = s; *p != '\0'; p++)
    h = (h << 3) + (unsigned char) *p;
  return h % n;
}

static int
hash_str (const char *s)
{
  return hash_str2 (s, VAR_NAME_HASH);
}

anon_nasl_var *
nasl_get_var_by_num (void *ctxt, nasl_array *a, int num, int create)
{
  anon_nasl_var *v = NULL;

  if (num < 0)
    {
      /* TBD: implement a min_index field, just like $[ in Perl */
      nasl_perror (ctxt, "Negative integer index %d are not supported yet!\n",
                   num);
      return NULL;
    }

  if (num < a->max_idx)
    v = a->num_elt[num];
  if (v != NULL || !create)
    return v;

  if (num >= a->max_idx)
    {
      a->num_elt = g_realloc (a->num_elt, sizeof (anon_nasl_var *) * (num + 1));
      bzero (a->num_elt + a->max_idx,
             sizeof (anon_nasl_var *) * (num + 1 - a->max_idx));
      a->max_idx = num + 1;
    }
  v = g_malloc0 (sizeof (anon_nasl_var));
  v->var_type = VAR2_UNDEF;

  a->num_elt[num] = v;
  return v;
}

static named_nasl_var *
get_var_by_name (nasl_array *a, const char *s)
{
  int h = hash_str (s);
  named_nasl_var *v;

  if (a->hash_elt == NULL)
    a->hash_elt = g_malloc0 (VAR_NAME_HASH * sizeof (named_nasl_var *));

  for (v = a->hash_elt[h]; v != NULL; v = v->next_var)
    if (v->var_name != NULL && strcmp (s, v->var_name) == 0)
      return v;

  v = g_malloc0 (sizeof (named_nasl_var));
  v->var_name = g_strdup (s);
  v->u.var_type = VAR2_UNDEF;
  v->next_var = a->hash_elt[h];

  a->hash_elt[h] = v;
  return v;
}

/**
 * @brief This function climbs up in the context list.
 */
static named_nasl_var *
get_var_ref_by_name (lex_ctxt *ctxt, const char *name, int climb)
{
  named_nasl_var *v;
  int h = hash_str (name);
  lex_ctxt *c;

  if (!ctxt)
    return NULL;
  if (climb != 0)
    {
      for (c = ctxt; c != NULL; c = c->up_ctxt)
        if (c->ctx_vars.hash_elt != NULL)
          for (v = c->ctx_vars.hash_elt[h]; v != NULL; v = v->next_var)
            if (v->var_name != NULL && strcmp (name, v->var_name) == 0)
              return v;
    }
  else
    {
      if (ctxt->ctx_vars.hash_elt != NULL)
        for (v = ctxt->ctx_vars.hash_elt[h]; v != NULL; v = v->next_var)
          if (v->var_name != NULL && strcmp (name, v->var_name) == 0)
            return v;
    }

  if (ctxt->ctx_vars.hash_elt == NULL)
    ctxt->ctx_vars.hash_elt =
      g_malloc0 (sizeof (named_nasl_var *) * VAR_NAME_HASH);

  v = g_malloc0 (sizeof (named_nasl_var));
  v->var_name = g_strdup (name);
  v->u.var_type = VAR2_UNDEF;
  v->next_var = ctxt->ctx_vars.hash_elt[h];
  ctxt->ctx_vars.hash_elt[h] = v;

  return v;
}

static anon_nasl_var *
get_var_ref_by_num (lex_ctxt *ctxt, int num)
{
  anon_nasl_var *v;

  if (num < 0) /* safer */
    {
      nasl_perror (ctxt, "Negative index %d is invalid for array\n", num);
      return NULL;
    }

  if (ctxt->ctx_vars.max_idx <= num)
    {
      ctxt->ctx_vars.num_elt = g_realloc (ctxt->ctx_vars.num_elt,
                                          sizeof (anon_nasl_var *) * (num + 1));
      bzero (ctxt->ctx_vars.num_elt + ctxt->ctx_vars.max_idx,
             sizeof (anon_nasl_var *) * (num + 1 - ctxt->ctx_vars.max_idx));
      ctxt->ctx_vars.max_idx = num + 1;
    }

  v = ctxt->ctx_vars.num_elt[num];
  if (v != NULL)
    return v;

  v = g_malloc0 (sizeof (anon_nasl_var));
  v->var_type = VAR2_UNDEF;
  ctxt->ctx_vars.num_elt[num] = v;
  return v;
}

tree_cell *
var2cell (anon_nasl_var *v)
{
  tree_cell *tc = alloc_typed_cell (REF_VAR);
  tc->x.ref_val = v; /* No need to free this later! */
  return tc;
}

tree_cell *
get_variable_by_name (lex_ctxt *ctxt, const char *name)
{
  if (name == NULL)
    return NULL;
  /* Broken: Need also code in get_array_elem */
  if (strcmp (name, "_FCT_ANON_ARGS") == 0)
    {
      tree_cell *retc = alloc_typed_cell (DYN_ARRAY);
      nasl_array *a = retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
      copy_array (a, &ctxt->ctx_vars, 0);
      return retc;
    }
  else
    {
      named_nasl_var *v = get_var_ref_by_name (ctxt, name, 1);
      return var2cell (&v->u);
    }
 /*NOTREACHED*/}

 static const char *
 get_var_name (anon_nasl_var *v)
 {
   static char str[16];
#ifdef ALL_VARIABLES_NAMED
   if (v->av_name != NULL)
     return v->av_name;
#endif
   snprintf (str, sizeof (str), "[%p]", (void *) v);
   return str;
 }

 tree_cell *
 get_array_elem (lex_ctxt *ctxt, const char *name, tree_cell *idx)
 {
   named_nasl_var *nv;
   anon_nasl_var *u, *av, fake_var;
   tree_cell *tc, idx0;

   /* Fake variable */
   if (strcmp (name, "_FCT_ANON_ARGS") == 0)
     {
       lex_ctxt *c;
       for (c = ctxt; c != NULL && !c->fct_ctxt; c = c->up_ctxt)
         ;
       if (c == NULL)
         return NULL;
       fake_var.var_type = VAR2_ARRAY;
       fake_var.v.v_arr = c->ctx_vars;
       fake_var.v.v_arr.hash_elt = NULL; /* mask named elements */
       u = &fake_var;
     }
   else
     {
       named_nasl_var *v = get_var_ref_by_name (ctxt, name, 1);
       u = &v->u;
     }

   if (idx == NULL)
     {
       /* Treat it as zero */
       memset (&idx0, '\0', sizeof (idx0));
       idx = &idx0;
       idx->type = CONST_INT;
     }

   switch (u->var_type)
     {
     case VAR2_UNDEF:
       /* We define the array here */
       u->var_type = VAR2_ARRAY;
       /* fallthrough */
     case VAR2_ARRAY:
       switch (idx->type)
         {
         case CONST_INT:
           av = nasl_get_var_by_num (ctxt, &u->v.v_arr, idx->x.i_val,
                                     /* avoid dangling pointers */
                                     strcmp (name, "_FCT_ANON_ARGS"));
           return var2cell (av);

         case CONST_STR:
         case CONST_DATA:
           nv = get_var_by_name (&u->v.v_arr, idx->x.str_val);
           return var2cell (nv != NULL ? &nv->u : NULL);

         default:
           nasl_perror (ctxt,
                        "get_array_elem: unhandled index type 0x%x for "
                        "variable %s\n",
                        idx->type, name);
           return NULL;
         }
       /*NOTREACHED*/ break;

     case VAR2_INT:
       nasl_perror (ctxt, "get_array_elem: variable %s is an integer\n", name);
       return NULL;

     case VAR2_STRING:
     case VAR2_DATA:
       if (idx->type == CONST_INT)
         {
           int l = u->v.v_str.s_siz;

           if (idx->x.i_val >= l)
             {
               nasl_perror (ctxt,
                            "get_array_elem: requesting character after end "
                            "of string %s (%d >= %d)\n",
                            name, idx->x.i_val, l);
               tc = alloc_expr_cell (idx->line_nb, CONST_DATA /*CONST_STR */,
                                     NULL, NULL);
               tc->x.str_val = g_strdup ("");
               tc->size = 0;
               return tc;
             }
           else
             {
               if (idx->x.i_val < 0)
                 {
                   nasl_perror (ctxt,
                                "get_array_elem: Negative index (%d) passed to "
                                "\"%s\"!\n",
                                idx->x.i_val, name);
                   return NULL;
                 }
               tc = alloc_expr_cell (idx->line_nb, CONST_DATA /*CONST_STR */,
                                     NULL, NULL);
               tc->x.str_val = g_malloc0 (2);
               tc->x.str_val[0] = u->v.v_str.s_val[idx->x.i_val];
               tc->x.str_val[1] = '\0';
               tc->size = 1;
               return tc;
             }
         }
       else
         {
           nasl_perror (ctxt,
                        "get_array_elem: Cannot use a non integer index"
                        " (type 0x%x) in string. Variable: %s\n",
                        idx->type, name);
           return NULL;
         }
       /*NOTREACHED*/ break;

     default:
       nasl_perror (ctxt, "Severe bug: unknown variable type 0x%x %s\n",
                    u->var_type, get_line_nb (idx));
       return NULL;
     }
   /*NOTREACHED*/ return NULL;
 }

 static void
 free_var_chain (named_nasl_var *);
 static void
 free_anon_var (anon_nasl_var *);

 /**
  * Note: the function does not free the nasl_array structure.
  * Do it if necessary
  */
 void
 free_array (nasl_array *a)
 {
   int i;

   if (a == NULL)
     return;
   if (a->num_elt != NULL)
     {
       for (i = 0; i < a->max_idx; i++)
         free_anon_var (a->num_elt[i]);
       g_free (a->num_elt);
       a->num_elt = NULL;
     }
   a->max_idx = 0;
   if (a->hash_elt != NULL)
     {
       for (i = 0; i < VAR_NAME_HASH; i++)
         free_var_chain (a->hash_elt[i]);
       g_free (a->hash_elt);
       a->hash_elt = NULL;
     }
 }

 static void
 free_var_chain (named_nasl_var *v)
 {
   if (v == NULL)
     return;
   free_var_chain (v->next_var);
   g_free (v->var_name);
   switch (v->u.var_type)
     {
     case VAR2_STRING:
     case VAR2_DATA:
       g_free (v->u.v.v_str.s_val);
       break;
     case VAR2_ARRAY:
       free_array (&v->u.v.v_arr);
       break;
     }
   g_free (v->u.string_form);
   g_free (v);
 }

 static void
 free_anon_var (anon_nasl_var *v)
 {
   if (v == NULL)
     return;
   switch (v->var_type)
     {
     case VAR2_STRING:
     case VAR2_DATA:
       g_free (v->v.v_str.s_val);
       break;
     case VAR2_ARRAY:
       free_array (&v->v.v_arr);
       break;
     }
   g_free (v->string_form);
   g_free (v);
 }

 static void
 clear_anon_var (anon_nasl_var *v)
 {
   if (v == NULL)
     return;

   switch (v->var_type)
     {
     case VAR2_INT:
       v->v.v_int = 0;
       break;
     case VAR2_STRING:
     case VAR2_DATA:
       g_free (v->v.v_str.s_val);
       v->v.v_str.s_val = NULL;
       v->v.v_str.s_siz = 0;
       break;
     case VAR2_ARRAY:
       free_array (&v->v.v_arr);
       break;
     }
   v->var_type = VAR2_UNDEF;
 }

 static void
 copy_anon_var (anon_nasl_var *v1, const anon_nasl_var *v2)
 {
   /* TBD: free variable if necessary? */
   v1->var_type = v2->var_type;
   switch (v2->var_type)
     {
     case VAR2_STRING:
     case VAR2_DATA:
       if (v2->v.v_str.s_val != NULL)
         {
           v1->v.v_str.s_val = g_malloc0 (v2->v.v_str.s_siz + 1);
           memcpy (v1->v.v_str.s_val, v2->v.v_str.s_val, v2->v.v_str.s_siz);
           v1->v.v_str.s_siz = v2->v.v_str.s_siz;
         }
       else
         {
           v1->v.v_str.s_val = NULL;
           v1->v.v_str.s_siz = 0;
         }
       break;

     case VAR2_UNDEF:
       break;

     case VAR2_INT:
       v1->v.v_int = v2->v.v_int;
       break;

     case VAR2_ARRAY:
       copy_array (&v1->v.v_arr, &v2->v.v_arr, 1);
       break;

     default:
       nasl_perror (NULL, "copy_anon_var: unhandled type 0x%x\n", v2->var_type);
       clear_anon_var (v1);
     }
 }

 static anon_nasl_var *
 dup_anon_var (const anon_nasl_var *v)
 {
   anon_nasl_var *v1;

   if (v == NULL)
     return NULL;

   v1 = g_malloc0 (sizeof (anon_nasl_var));
   copy_anon_var (v1, v);
   return v1;
 }

 static named_nasl_var *
 dup_named_var (const named_nasl_var *v)
 {
   named_nasl_var *v1;

   if (v == NULL)
     return NULL;

   v1 = g_malloc0 (sizeof (named_nasl_var));
   copy_anon_var (&v1->u, &v->u);
   v1->var_name = g_strdup (v->var_name);
   return v1;
 }

 static void
 copy_array (nasl_array *a1, const nasl_array *a2, int copy_named)
 {
   int i;
   named_nasl_var *v1, *v2, *v;

   if (a1 == a2)
     return;

   if (a1 == NULL || a2 == NULL)
     {
       nasl_perror (NULL, "Internal inconsistency - null array\n");
       abort ();
     }

   free_array (a1);

   if (a2->num_elt != NULL)
     {
       a1->max_idx = a2->max_idx;
       a1->num_elt = g_malloc0 (sizeof (anon_nasl_var *) * a2->max_idx);
       for (i = 0; i < a2->max_idx; i++)
         a1->num_elt[i] = dup_anon_var (a2->num_elt[i]);
     }
   if (copy_named && a2->hash_elt != NULL)
     {
       a1->hash_elt = g_malloc0 (VAR_NAME_HASH * sizeof (named_nasl_var *));
       for (i = 0; i < VAR_NAME_HASH; i++)
         {
           v1 = NULL;
           for (v2 = a2->hash_elt[i]; v2 != NULL; v2 = v2->next_var)
             {
               v = dup_named_var (v2);
               v->next_var = v1;
               a1->hash_elt[i] = v;
               v1 = v;
             }
         }
     }
 }

 tree_cell *
 copy_ref_array (const tree_cell *c1)
 {
   tree_cell *c2;
   nasl_array *a2;

   if (c1 == NULL || c1 == FAKE_CELL || c1->type != REF_ARRAY)
     return NULL;

   c2 = alloc_typed_cell (DYN_ARRAY);
   c2->x.ref_val = a2 = g_malloc0 (sizeof (nasl_array));
   copy_array (a2, c1->x.ref_val, 1);
   return c2;
 }

 extern FILE *nasl_trace_fp;

 static tree_cell *
 affect_to_anon_var (anon_nasl_var *v1, tree_cell *rval)
 {
   anon_nasl_var *v2 = NULL, v0;
   nasl_array *a = NULL;
   int t2;
   void *p;

   if (v1 == NULL || v1 == FAKE_CELL)
     return NULL;

   if (rval == NULL || rval == FAKE_CELL)
     {
       clear_anon_var (v1);
       if (nasl_trace_enabled ())
         nasl_trace (NULL, "NASL> %s <- undef\n", get_var_name (v1));
       return NULL;
     }

   switch (rval->type)
     {
     case CONST_INT:
       t2 = VAR2_INT;
       break;
     case CONST_STR:
       t2 = VAR2_STRING;
       break;
     case CONST_DATA:
       t2 = VAR2_DATA;
       break;

     case REF_VAR:
       v2 = rval->x.ref_val;
       if (v2 == NULL)
         {
           t2 = 0;
           a = NULL;
           break;
         }

       if (v2 == v1)
         return FAKE_CELL;

       t2 = v2->var_type;
       if (t2 == VAR2_ARRAY)
         a = &v2->v.v_arr; /* ? */
       break;

     case REF_ARRAY:
     case DYN_ARRAY:
       a = rval->x.ref_val;
       t2 = VAR2_ARRAY;
       if (v1->var_type == VAR2_ARRAY && &v1->v.v_arr == a)
         return FAKE_CELL;
       break;

     default:
       nasl_perror (NULL, "Cannot affect rvalue 0x%x to variable\n",
                    rval->type);
       return NULL;
     }

   /*
    * Bug #146: when executing
    *    x = 'abc'; x = x;  or   x = make_list(...); x = x[0];
    * the rvalue will be freed before it is copied to the lvalue
    */
   v0 = *v1;

   /* Bug #146: this fake clear is necessary if we copy an array */
   memset (v1, 0, sizeof (*v1));
   /* Bug #146: no risk with the type, we already copied it */
   v1->var_type = t2;

   if (rval->type != REF_VAR && rval->type != REF_ARRAY
       && rval->type != DYN_ARRAY)
     switch (t2)
       {
       case VAR2_INT:
         v1->v.v_int = rval->x.i_val;
         break;
       case VAR2_STRING:
       case VAR2_DATA:
         if (rval->x.str_val == NULL)
           {
             v1->v.v_str.s_val = NULL;
             v1->v.v_str.s_siz = 0;
           }
         else
           {
             p = g_malloc0 (rval->size + 1);
             memcpy (p, rval->x.str_val, rval->size);
             v1->v.v_str.s_siz = rval->size;
             v1->v.v_str.s_val = p;
           }
         break;
       }
   else /* REF_xxx */
     switch (t2)
       {
       case VAR2_INT:
         v1->v.v_int = v2->v.v_int;
         break;
       case VAR2_STRING:
       case VAR2_DATA:
         if (v2->v.v_str.s_val == NULL)
           {
             v1->v.v_str.s_val = NULL;
             v1->v.v_str.s_siz = 0;
           }
         else
           {
             p = g_malloc0 (v2->v.v_str.s_siz + 1);
             memcpy (p, v2->v.v_str.s_val, v2->v.v_str.s_siz);
             v1->v.v_str.s_siz = v2->v.v_str.s_siz;
             v1->v.v_str.s_val = p;
           }
         break;
       case VAR2_ARRAY:
         copy_array (&v1->v.v_arr, a, 1);
         break;
       }

   if (nasl_trace_fp != NULL)
     switch (t2)
       {
       case VAR2_INT:
         nasl_trace (NULL, "NASL> %s <- %lu\n", get_var_name (v1), v1->v.v_int);
         break;
       case VAR2_STRING:
       case VAR2_DATA:
         nasl_trace (NULL, "NASL> %s <- \"%s\"\n", get_var_name (v1),
                     v1->v.v_str.s_val);
         break;
       case VAR2_ARRAY:
         nasl_trace (NULL, "NASL> %s <- (VAR2_ARRAY)\n", get_var_name (v1));
         break;
       default:
         nasl_trace (NULL, "NASL> %s <- (Type 0x%x)\n", get_var_name (v1), t2);
         break;
       }

   clear_anon_var (&v0);
   return FAKE_CELL;
 }

 tree_cell *
 nasl_affect (tree_cell *lval, tree_cell *rval)
 {
   anon_nasl_var *v1 = NULL;

   if (lval == NULL)
     {
       nasl_perror (NULL, "nasl_effect: invalid lvalue\n");
       return NULL;
     }

   if (lval->type != REF_VAR)
     {
       nasl_perror (NULL, "nasl_affect: cannot affect to non variable %s\n",
                    nasl_type_name (lval->type));
       return NULL;
     }

   v1 = lval->x.ref_val;
   return affect_to_anon_var (v1, rval);
 }

 static named_nasl_var *
 create_named_var (const char *name, tree_cell *val)
 {
   named_nasl_var *v = g_malloc0 (sizeof (named_nasl_var));
   tree_cell *tc;

   if (name != NULL)
     v->var_name = g_strdup (name);

   if (val == NULL || val == FAKE_CELL)
     {
       v->u.var_type = VAR2_UNDEF;
       return v;
     }

   tc = affect_to_anon_var (&v->u, val);
   /* Here we might test the return value */
   deref_cell (tc);
   return v;
 }

 static anon_nasl_var *
 create_anon_var (tree_cell *val)
 {
   anon_nasl_var *v = g_malloc0 (sizeof (anon_nasl_var));
   tree_cell *tc;

   if (val == NULL || val == FAKE_CELL)
     {
       v->var_type = VAR2_UNDEF;
       return v;
     }

   tc = affect_to_anon_var (v, val);
   /* Here we might test the return value */
   deref_cell (tc);
   return v;
 }

 tree_cell *
 decl_local_variables (lex_ctxt *lexic, tree_cell *vars)
 {
   tree_cell *t;

   for (t = vars; t != NULL; t = t->link[0])
     if (t->x.str_val == NULL)
       nasl_perror (lexic, "decl_local_variables: null name!\n");
     else
       add_named_var_to_ctxt (lexic, t->x.str_val, NULL);
   return FAKE_CELL;
 }

 tree_cell *
 decl_global_variables (lex_ctxt *lexic, tree_cell *vars)
 {
   lex_ctxt *c = lexic;

   while (c->up_ctxt != NULL)
     c = c->up_ctxt;
   return decl_local_variables (c, vars);
 }

 anon_nasl_var *
 add_numbered_var_to_ctxt (lex_ctxt *lexic, int num, tree_cell *val)
 {
   anon_nasl_var *v;
   nasl_array *a = &lexic->ctx_vars;

   if (a->max_idx > num)
     {
       v = a->num_elt[num];
       if (v != NULL && v->var_type != VAR2_UNDEF)
         {
           if (val != NULL)
             nasl_perror (lexic, "Cannot add existing variable %d\n", num);
           return NULL;
         }
       free_anon_var (a->num_elt[num]);
     }
   else
     {
       a->num_elt =
         g_realloc (a->num_elt, (num + 1) * sizeof (anon_nasl_var *));
       bzero (a->num_elt + a->max_idx,
              sizeof (anon_nasl_var *) * (num + 1 - a->max_idx));
       a->max_idx = num + 1;
     }
   a->num_elt[num] = v = create_anon_var (val);
   return v;
 }

 named_nasl_var *
 add_named_var_to_ctxt (lex_ctxt *lexic, const char *name, tree_cell *val)
 {
   int h = hash_str (name);
   named_nasl_var *v;

   /* Duplicated code ? */
   for (v = lexic->ctx_vars.hash_elt[h]; v != NULL; v = v->next_var)
     if (v->var_name != NULL && strcmp (name, v->var_name) == 0)
       {
         if (val != NULL)
           nasl_perror (lexic, "Cannot add existing variable %s\n", name);
         return NULL;
       }
   v = create_named_var (name, val);
   if (v == NULL)
     return NULL;
   v->next_var = lexic->ctx_vars.hash_elt[h];
   lexic->ctx_vars.hash_elt[h] = v;
   return v;
 }

 tree_cell *
 nasl_read_var_ref (lex_ctxt *lexic, tree_cell *tc)
 {
   tree_cell *ret;
   anon_nasl_var *v;

   if (tc == NULL || tc == FAKE_CELL)
     {
       nasl_perror (lexic,
                    "nasl_read_var_ref: cannot read NULL or FAKE cell\n");
       return NULL;
     }
   if (tc->type != REF_VAR)
     {
       nasl_perror (lexic,
                    "nasl_read_var_ref: argument (type=%d) is not REF_VAR %s\n",
                    tc->type, get_line_nb (tc));
       return NULL;
     }

   v = tc->x.ref_val;
   if (v == NULL)
     return NULL;

   ret = alloc_typed_cell (NODE_EMPTY);
   ret->line_nb = tc->line_nb;

   switch (v->var_type)
     {
     case VAR2_INT:
       ret->type = CONST_INT;
       ret->x.i_val = v->v.v_int;
       if (nasl_trace_enabled ())
         nasl_trace (lexic, "NASL> %s -> %lu\n", get_var_name (v),
                     ret->x.i_val);
       return ret;

     case VAR2_STRING:
       ret->type = CONST_STR;
       /* Fix bad string length */
       if (v->v.v_str.s_siz <= 0 && v->v.v_str.s_val[0] != '\0')
         {
           v->v.v_str.s_siz = strlen ((char *) v->v.v_str.s_val);
           nasl_perror (lexic, "nasl_read_var_ref: Bad string length fixed\n");
         }
       /* fallthrough */
     case VAR2_DATA:
       ret->type = v->var_type == VAR2_STRING ? CONST_STR : CONST_DATA;
       if (v->v.v_str.s_val == NULL)
         {
           ret->x.str_val = NULL;
           ret->size = 0;
         }
       else
         {
           ret->x.str_val = g_malloc0 (v->v.v_str.s_siz + 1);
           memcpy (ret->x.str_val, v->v.v_str.s_val, v->v.v_str.s_siz);
           ret->size = v->v.v_str.s_siz;
         }
       if (nasl_trace_enabled ())
         nasl_trace (lexic, "NASL> %s -> \"%s\"\n", get_var_name (v),
                     ret->x.str_val);
       return ret;

     case VAR2_ARRAY:
       ret->type = REF_ARRAY;
       ret->x.ref_val = &v->v.v_arr;
       return ret;

     case VAR2_UNDEF:
       if (nasl_trace_enabled ())
         nasl_trace (lexic, "NASL> %s -> undef\n", get_var_name (v),
                     v->var_type);
       break;

     default:
       nasl_perror (lexic, "nasl_read_var_ref: unhandled variable type %d\n",
                    v->var_type);
       if (nasl_trace_enabled ())
         nasl_trace (lexic, "NASL> %s -> ???? (Var type %d)\n",
                     get_var_name (v), v->var_type);
       break;
     }
   deref_cell (ret);
   return NULL;
 }

 tree_cell *
 nasl_incr_variable (lex_ctxt *lexic, tree_cell *tc, int pre, int val)
 {
   anon_nasl_var *v;
   int old_val = 0, new_val;
   tree_cell *retc;

   if (tc->type != REF_VAR)
     {
       nasl_perror (
         lexic, "nasl_incr_variable: argument (type=%d) is not REF_VAR %s\n",
         tc->type, get_line_nb (tc));
       return NULL;
     }

   v = tc->x.ref_val;

   switch (v->var_type)
     {
     case VAR2_INT:
       old_val = v->v.v_int;
       break;
     case VAR2_STRING:
     case VAR2_DATA:
       old_val =
         v->v.v_str.s_val == NULL ? 0 : atoi ((char *) v->v.v_str.s_val);
       break;
     case VAR2_UNDEF:
       old_val = 0;
       break;

     default:
       nasl_perror (lexic,
                    "nasl_incr_variable: variable %s has bad type %d %s\n",
                    /*get_var_name(v) */ "", get_line_nb (tc));
       return NULL;
     }
   new_val = old_val + val;

   clear_anon_var (v);
   v->var_type = VAR2_INT;
   v->v.v_int = new_val;

   retc = alloc_typed_cell (CONST_INT);
   retc->x.i_val = pre ? new_val : old_val;

   return retc;
 }

 static long int
 var2int (anon_nasl_var *v, int defval)
 {
   if (v == NULL)
     return defval;

   switch (v->var_type)
     {
     case VAR2_INT:
       return v->v.v_int;

     case VAR2_STRING:
     case VAR2_DATA:
       return atol ((char *) v->v.v_str.s_val);

     case VAR2_UNDEF:
     case VAR2_ARRAY:
     default:
       return defval;
     }
 /*NOTREACHED*/}

 char *
 array2str (const nasl_array *a)
 {
   GString *str;
   int i, n1 = 0;
   anon_nasl_var *u;
   named_nasl_var *v;

   if (a == NULL)
     return NULL;

   str = g_string_new ("[ ");
   if (a->num_elt != NULL)
     for (i = 0; i < a->max_idx; i++)
       if ((u = a->num_elt[i]) != NULL && u->var_type != VAR2_UNDEF)
         {
           if (n1 > 0)
             g_string_append (str, ", ");
           n1++;
           switch (u->var_type)
             {
             case VAR2_INT:
               g_string_append_printf (str, "%d: %ld", i, u->v.v_int);
               break;
             case VAR2_STRING:
             case VAR2_DATA:
               if (u->v.v_str.s_siz < 64)
                 g_string_append_printf (str, "%d: '%s'", i, u->v.v_str.s_val);
               else
                 g_string_append_printf (str, "%d: '%s'...", i,
                                         u->v.v_str.s_val);
               break;
             default:
               g_string_append_printf (str, "%d: ????", i);
               break;
             }
         }

   if (a->hash_elt != NULL)
     for (i = 0; i < VAR_NAME_HASH; i++)
       for (v = a->hash_elt[i]; v != NULL; v = v->next_var)
         if (v->u.var_type != VAR2_UNDEF)
           {
             u = &v->u;
             if (n1 > 0)
               g_string_append (str, ", ");
             n1++;
             switch (u->var_type)
               {
               case VAR2_INT:
                 g_string_append_printf (str, "%s: %ld", v->var_name,
                                         u->v.v_int);
                 break;
               case VAR2_STRING:
               case VAR2_DATA:
                 if (u->v.v_str.s_siz < 64)
                   g_string_append_printf (str, "%s: '%s'", v->var_name,
                                           u->v.v_str.s_val);
                 else
                   g_string_append_printf (str, "%s: '%s'...", v->var_name,
                                           u->v.v_str.s_val);
                 break;
               default:
                 g_string_append_printf (str, "%s: ????", v->var_name);
                 break;
               }
           }

   g_string_append (str, " ]");
   return g_string_free (str, FALSE);
 }

 const char *
 var2str (anon_nasl_var *v)
 {
   if (v == NULL)
     return NULL;

   if (v->string_form)
     return v->string_form;
   switch (v->var_type)
     {
     case VAR2_INT:
       v->string_form = g_strdup_printf ("%ld", v->v.v_int);
       break;
     case VAR2_STRING:
     case VAR2_DATA:
       v->string_form = g_malloc0 (v->v.v_str.s_siz + 1);
       memcpy (v->string_form,
               (char *) v->v.v_str.s_val ? (char *) v->v.v_str.s_val : "",
               v->v.v_str.s_siz + 1);
       break;
     case VAR2_UNDEF:
       break;
     case VAR2_ARRAY:
       v->string_form = array2str (&v->v.v_arr);
       break;
     default:
       v->string_form = g_strdup ("");
       break;
     }
   return v->string_form;
 }

 long int
 get_int_var_by_num (lex_ctxt *lexic, int num, int defval)
 {
   anon_nasl_var *v = get_var_ref_by_num (lexic, num);
   return var2int (v, defval);
 }

 long int
 get_int_var_by_name (lex_ctxt *lexic, const char *name, int defval)
 {
   named_nasl_var *v = get_var_ref_by_name (lexic, name, 0);
   return var2int (&v->u, defval);
 }

 char *
 get_str_var_by_num (lex_ctxt *lexic, int num)
 {
   anon_nasl_var *v = get_var_ref_by_num (lexic, num);
   return (char *) var2str (v);
 }

 char *
 get_str_var_by_name (lex_ctxt *lexic, const char *name)
 {
   named_nasl_var *v = get_var_ref_by_name (lexic, name, 0);
   return (char *) var2str (&v->u);
 }
 static int
 get_var_size (const anon_nasl_var *v)
 {
   if (v == NULL)
     return 0;
   switch (v->var_type)
     {
     case VAR2_DATA:
     case VAR2_STRING:
       return v->v.v_str.s_siz;
     }
   return 0;
 }

 int
 get_var_size_by_name (lex_ctxt *lexic, const char *name)
 {
   named_nasl_var *v = get_var_ref_by_name (lexic, name, 0);
   return get_var_size (&v->u);
 }

 int
 get_var_size_by_num (lex_ctxt *lexic, int num)
 {
   anon_nasl_var *v = get_var_ref_by_num (lexic, num);
   return get_var_size (v);
 }

 /**
  * @brief Returns NASL variable/cell type, VAR2_UNDEF if value is NULL.
  */
 int
 get_var_type_by_num (lex_ctxt *lexic, int num)
 {
   anon_nasl_var *v = get_var_ref_by_num (lexic, num);
   return v == NULL ? VAR2_UNDEF : v->var_type;
 }

 int
 get_var_type_by_name (lex_ctxt *lexic, const char *name)
 {
   named_nasl_var *v = get_var_ref_by_name (lexic, name, 0);
   return v == NULL ? VAR2_UNDEF : v->u.var_type;
 }

 nasl_iterator
 nasl_array_iterator (void *ctxt, tree_cell *c)
 {
   nasl_iterator it;
   anon_nasl_var *v;

   it.a = NULL;
   it.v = NULL;
   it.i1 = 0;
   it.iH = 0;

   if (c == NULL || c == FAKE_CELL)
     return it;

   if (c->type == REF_VAR)
     {
       v = c->x.ref_val;
       if (v == NULL || v->var_type != VAR2_ARRAY)
         return it;
       it.a = g_malloc0 (sizeof (nasl_array));
       copy_array (it.a, &v->v.v_arr, 1);
     }
   else if (c->type == REF_ARRAY || c->type == DYN_ARRAY)
     {
       it.a = g_malloc0 (sizeof (nasl_array));
       copy_array (it.a, c->x.ref_val, 1);
     }
   else
     {
       nasl_perror (ctxt, "nasl_array_iterator: unhandled type %d (0x%x)\n",
                    c->type, c->type);
     }

   return it;
 }

 tree_cell *
 nasl_iterate_array (nasl_iterator *it)
 {
   anon_nasl_var *av;

   if (it == NULL || it->a == NULL)
     return NULL;

   if (it->i1 >= 0)
     {
       while (it->i1 < it->a->max_idx)
         {
           av = it->a->num_elt[it->i1++];
           if (av != NULL && av->var_type != VAR2_UNDEF)
             return var2cell (av);
         }
       it->i1 = -1;
     }

   if (it->a->hash_elt == NULL)
     return NULL;

   if (it->v != NULL)
     it->v = it->v->next_var;
   do
     {
       while (it->v == NULL)
         if (it->iH >= VAR_NAME_HASH)
           return NULL;
         else
           it->v = it->a->hash_elt[it->iH++];

       while (it->v != NULL && it->v->u.var_type == VAR2_UNDEF)
         it->v = it->v->next_var;
     }
   while (it->v == NULL);

   return var2cell (&it->v->u);
 }

 int
 add_var_to_list (nasl_array *a, int i, const anon_nasl_var *v)
 {
   anon_nasl_var *v2 = NULL;

   if (i < 0)
     {
       nasl_perror (
         NULL, "add_var_to_list: negative index are not (yet) supported\n");
       return -1;
     }

   if (i >= a->max_idx)
     {
       a->num_elt = g_realloc (a->num_elt, sizeof (anon_nasl_var *) * (i + 1));
       bzero (a->num_elt + a->max_idx,
              sizeof (anon_nasl_var *) * (i + 1 - a->max_idx));
       a->max_idx = i + 1;
     }

   if (a->num_elt)
     {
       free_anon_var (a->num_elt[i]);
       v2 = dup_anon_var (v); /* May return NULL */
       a->num_elt[i] = v2;
     }
   if (v2 == NULL)
     return 0;
   else
     return 1;
 }

 int
 add_var_to_array (nasl_array *a, char *name, const anon_nasl_var *v)
 {
   named_nasl_var *v2;
   int h = hash_str (name);

   if (a->hash_elt == NULL)
     {
       a->hash_elt = g_malloc0 (VAR_NAME_HASH * sizeof (named_nasl_var *));
     }

   v2 = g_malloc0 (sizeof (named_nasl_var));
   v2->var_name = g_strdup (name);
   v2->u.var_type = VAR2_UNDEF;
   v2->next_var = a->hash_elt[h];
   a->hash_elt[h] = v2;

   copy_anon_var (&(v2->u), v);
   return 0;
 }

 /**
  * The name is not great: this function does not returns the index of the
  * last element, but the index of the next free slot
  */
 int
 array_max_index (nasl_array *a)
 {
   int i;

   for (i = a->max_idx - 1; i >= 0; i--)
     if (a->num_elt[i] != NULL && a->num_elt[i]->var_type != VAR2_UNDEF)
       {
         /* Fixing max_index will realloc() at next store.
          * I am not sure it is a good idea
          * Wait and see */
         a->max_idx = i + 1;
         return i + 1;
       }
   return 0;
 }

 /**
  * make_array_from_list is used by the parser only
  * The list of elements is freed after use
  */
 tree_cell *
 make_array_from_elems (tree_cell *el)
 {
   int n;
   tree_cell *c, *c2;
   nasl_array *a;
   anon_nasl_var *v;

   v = g_malloc0 (sizeof (anon_nasl_var));
   a = g_malloc0 (sizeof (nasl_array));
   /* Either the elements are all "named", or they are "numbered". No mix! */
   if (el->x.str_val == NULL) /* numbered */
     {
       for (n = 0, c = el; c != NULL; c = c->link[1])
         n++;
       a->max_idx = n;
       a->num_elt = g_malloc0 (sizeof (anon_nasl_var *) * n);
       a->hash_elt = NULL;
     }
   else
     {
       a->num_elt = NULL;
       a->hash_elt = g_malloc0 (VAR_NAME_HASH * sizeof (named_nasl_var *));
     }

   for (n = 0, c = el; c != NULL; c = c->link[1])
     {
       c2 = c->link[0];
       if (c2 != NULL && c2 != FAKE_CELL)
         {
           switch (c2->type)
             {
             case CONST_INT:
               v->var_type = VAR2_INT;
               v->v.v_int = c2->x.i_val;
               break;
             case CONST_STR:
             case CONST_DATA:
               v->var_type = c2->type == CONST_STR ? VAR2_STRING : VAR2_DATA;
               if (c2->x.str_val == NULL)
                 {
                   v->v.v_str.s_val = NULL;
                   v->v.v_str.s_siz = 0;
                 }
               else
                 {
                   v->v.v_str.s_siz = c2->size;
                   v->v.v_str.s_val = (unsigned char *) c2->x.str_val;
                 }
               break;
             default:
               nasl_perror (NULL,
                            "make_array_from_list: unhandled cell type %s at "
                            "position %d\n",
                            nasl_type_name (c2->type), n);
               v->var_type = VAR2_UNDEF;
               break;
             }
         }

       if (c->x.str_val == NULL)
         add_var_to_list (a, n++, v);
       else
         add_var_to_array (a, c->x.str_val, v);
     }

   g_free (v);
   c = alloc_typed_cell (DYN_ARRAY);
   c->x.ref_val = a;
   deref_cell (el);
   return c;
 }
