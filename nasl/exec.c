/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include "exec.h"

#include "../misc/plugutils.h"
#include "lint.h"
#include "nasl.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_init.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <errno.h>       /* for errno */
#include <glib.h>        /* for g_get_current_dir and others */
#include <glib/gstdio.h> /* for g_chdir */
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h>     /* for prefs_get */
#include <gvm/util/nvticache.h> /* for nvticache_get_kb */
#include <regex.h>
#include <stdlib.h> /* for srand48 */
#include <string.h> /* for strlen */
#include <string.h> /* for memmem */
#include <unistd.h> /* for getpid */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

extern int
naslparse (naslctxt *, int *);

static int
cell2bool (lex_ctxt *lexic, tree_cell *c)
{
  tree_cell *c2;
  int flag;

  if (c == NULL || c == FAKE_CELL)
    return 0;

  switch (c->type)
    {
    case CONST_INT:
      return c->x.i_val != 0;

    case CONST_STR:
    case CONST_DATA:
      return c->size != 0;

    case REF_ARRAY:
    case DYN_ARRAY:
      /*nasl_perror(lexic, "cell2bool: converting array to boolean does not make
       * sense!\n"); */
      return 1;

    default:
      c2 = nasl_exec (lexic, c);
      flag = cell2bool (lexic, c2);
      deref_cell (c2);
      return flag;
    }
}

static long int
cell2int3 (lex_ctxt *lexic, tree_cell *c, int warn, named_nasl_var *v)
{
  tree_cell *c2 = NULL;
  long int x;
  char *p = NULL;

  if (c == NULL || c == FAKE_CELL) /*  Do not SEGV on undefined variables */
    return 0;

  switch (c->type)
    {
    case CONST_INT:
      return c->x.i_val;

    case CONST_STR:
    case CONST_DATA:
      x = strtol (c->x.str_val, &p, 0);
      if (*p != '\0' && warn)
        if (warn)
          {
            if (v)
              nasl_perror (lexic,
                           "Converting the non numeric string '%s' in variable "
                           "'%s' to integer does not make sense in this "
                           "context",
                           c->x.str_val,
                           v->var_name != NULL ? v->var_name : "(null)");
            else
              nasl_perror (lexic,
                           "Converting the non numeric string '%s' to "
                           "integer does not make sense in this context",
                           c->x.str_val);
          }
      return x;

    case REF_VAR:
      v = c->x.ref_val;
      /* fallthrough */

    default:
      c2 = nasl_exec (lexic, c);
      x = cell2int3 (lexic, c2, warn, v);
      deref_cell (c2);
      return x;
    }
}

static long int
cell2int (lex_ctxt *lexic, tree_cell *c)
{
  return cell2int3 (lexic, c, 0, NULL);
}

static long int
cell2intW (lex_ctxt *lexic, tree_cell *c)
{
  return cell2int3 (lexic, c, 1, NULL);
}

static tree_cell *
int2cell (long int x)
{
  tree_cell *c = alloc_expr_cell (0, CONST_INT, NULL, NULL);
  c->x.i_val = x;
  return c;
}

static tree_cell *
bool2cell (long int x)
{
  return int2cell (x != 0);
}

static char *
cell2str (lex_ctxt *lexic, tree_cell *c)
{
  char *p;
  tree_cell *c2;
  nasl_array *a;

  if (c == NULL || c == FAKE_CELL)
    return NULL;

  switch (c->type)
    {
    case CONST_INT:
      return g_strdup_printf ("%ld", c->x.i_val);

    case CONST_STR:
    case CONST_DATA:
      if (c->x.str_val == NULL)
        p = g_strdup ("");
      else
        {
          p = g_malloc0 (c->size + 1);
          memcpy (p, c->x.str_val, c->size);
        }
      return p;

    case REF_ARRAY:
    case DYN_ARRAY:
      a = c->x.ref_val;
      return array2str (a);

    default:
      c2 = nasl_exec (lexic, c);
      p = cell2str (lexic, c2);
      deref_cell (c2);
      if (p == NULL)
        p = g_strdup ("");
      return p;
    }
}

/**
 * @return A 'referenced' cell.
 */
tree_cell *
cell2atom (lex_ctxt *lexic, tree_cell *c1)
{
  tree_cell *c2 = NULL, *ret = NULL;
  if (c1 == NULL || c1 == FAKE_CELL)
    return c1;

  switch (c1->type)
    {
    case CONST_INT:
    case CONST_STR:
    case CONST_DATA:
    case REF_ARRAY:
    case DYN_ARRAY:
      ref_cell (c1);
      return c1;
    default:
      c2 = nasl_exec (lexic, c1);
      ret = cell2atom (lexic, c2);
      deref_cell (c2);
      return ret;
    }
}

long int
cell_cmp (lex_ctxt *lexic, tree_cell *c1, tree_cell *c2)
{
  int flag, typ, typ1, typ2;
  long int x1, x2;
  char *s1, *s2;
  int len_s1, len_s2, len_min;

  if (c1 == NULL || c1 == FAKE_CELL)
    nasl_perror (lexic, "cell_cmp: c1 == NULL !\n");
  if (c2 == NULL || c2 == FAKE_CELL)
    nasl_perror (lexic, "cell_cmp: c2 == NULL !\n");

  /* We first convert the cell to atomic types. */
  c1 = cell2atom (lexic, c1);
  c2 = cell2atom (lexic, c2);

  /*
   * Comparing anything to something else which is entirely different
   * may lead to unpredictable results.
   * Here are the rules:
   * 1. No problem with same types, although we do not compare arrays yet
   * 2. No problem with CONST_DATA / CONST_STR
   * 3. When an integer is compared to a string, the integer is converted
   * 4. When NULL is compared to an integer, it is converted to 0
   * 5. When NULL is compared to a string, it is converted to ""
   * 6. NULL is "smaller" than anything else (i.e. an array)
   * Anything else is an error
   */
  typ1 = cell_type (c1);
  typ2 = cell_type (c2);

  if (typ1 == 0 && typ2 == 0) /* Two NULL */
    {
      deref_cell (c1);
      deref_cell (c2);
      return 0;
    }

  if (typ1 == typ2) /* Same type, no problem */
    typ = typ1;
  else if ((typ1 == CONST_DATA || typ1 == CONST_STR)
           && (typ2 == CONST_DATA || typ2 == CONST_STR))
    typ = CONST_DATA; /* Same type in fact (string) */
  /* We convert an integer into a string before compare */
  else if ((typ1 == CONST_INT && (typ2 == CONST_DATA || typ2 == CONST_STR))
           || (typ2 == CONST_INT && (typ1 == CONST_DATA || typ1 == CONST_STR)))
    typ = CONST_DATA;
  else if (typ1 == 0) /* 1st argument is null */
    if (typ2 == CONST_INT || typ2 == CONST_DATA || typ2 == CONST_STR)
      typ = typ2; /* We convert it to 0 or "" */
    else
      {
        deref_cell (c1);
        deref_cell (c2);
        return -1; /* NULL is smaller than anything else */
      }
  else if (typ2 == 0) /* 2nd argument is null */
    if (typ1 == CONST_INT || typ1 == CONST_DATA || typ1 == CONST_STR)
      typ = typ1; /* We convert it to 0 or "" */
    else
      {
        deref_cell (c1);
        deref_cell (c2);
        return 1; /* Anything else is greater than NULL  */
      }
  else
    {
      gchar *n1, *n2;

      n1 = cell2str (lexic, c1);
      n2 = cell2str (lexic, c2);
      nasl_perror (lexic,
                   "cell_cmp: comparing '%s' of type %s and '%s' of "
                   "type %s does not make sense\n",
                   n1, nasl_type_name (typ1), n2, nasl_type_name (typ2));
      g_free (n1);
      g_free (n2);
      deref_cell (c1);
      deref_cell (c2);
      return 0;
    }

  switch (typ)
    {
    case CONST_INT:
      x1 = cell2int (lexic, c1);
      x2 = cell2int (lexic, c2);
      deref_cell (c1);
      deref_cell (c2);
      return x1 - x2;

    case CONST_STR:
    case CONST_DATA:
      s1 = cell2str (lexic, c1);
      if (typ1 == CONST_STR || typ1 == CONST_DATA)
        len_s1 = c1->size;
      else if (s1 == NULL)
        len_s1 = 0;
      else
        len_s1 = strlen (s1);

      s2 = cell2str (lexic, c2);
      if (typ2 == CONST_STR || typ2 == CONST_DATA)
        len_s2 = c2->size;
      else if (s2 == NULL)
        len_s2 = 0;
      else
        len_s2 = strlen (s2);

      len_min = len_s1 < len_s2 ? len_s1 : len_s2;
      flag = 0;

      if (len_min > 0)
        flag = memcmp (s1, s2, len_min);
      if (flag == 0)
        flag = len_s1 - len_s2;

      g_free (s1);
      g_free (s2);
      deref_cell (c1);
      deref_cell (c2);
      return flag;

    case REF_ARRAY:
    case DYN_ARRAY:
      g_message ("cell_cmp: cannot compare arrays yet");
      deref_cell (c1);
      deref_cell (c2);
      return 0;

    default:
      g_message ("cell_cmp: don't known how to compare %s and %s",
                 nasl_type_name (typ1), nasl_type_name (typ2));
      deref_cell (c1);
      deref_cell (c2);
      return 0;
    }
}

FILE *nasl_trace_fp = NULL;

lex_ctxt *truc = NULL;

static void
nasl_dump_expr (FILE *fp, const tree_cell *c)
{
  if (c == NULL)
    fprintf (fp, "NULL");
  else if (c == FAKE_CELL)
    fprintf (fp, "FAKE");
  else
    switch (c->type)
      {
      case NODE_VAR:
        fprintf (fp, "%s", c->x.str_val);
        break;
      case EXPR_AND:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") && (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_OR:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") || (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_NOT:
        fprintf (fp, "! (");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ")");
        break;
      case EXPR_PLUS:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") + (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_MINUS:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") - (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case EXPR_INCR:
        if (c->link[0] == NULL)
          {
            fprintf (fp, " ++");
            nasl_dump_expr (fp, c->link[1]);
          }
        else
          {
            nasl_dump_expr (fp, c->link[0]);
            fprintf (fp, "++ ");
          }
        break;
      case EXPR_DECR:
        if (c->link[0] == NULL)
          {
            fprintf (fp, " --");
            nasl_dump_expr (fp, c->link[1]);
          }
        else
          {
            nasl_dump_expr (fp, c->link[0]);
            fprintf (fp, "-- ");
          }
        break;

      /** @todo Refactor, remove upcoming code duplicates. */
      case EXPR_EXPO:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") ** (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case EXPR_U_MINUS:
        fprintf (fp, " - (");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ")");
        break;

      case EXPR_MULT:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") * (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_DIV:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") / (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_MODULO:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") %% (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_BIT_AND:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") & (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_BIT_OR:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") | (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_BIT_XOR:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") ^ (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_BIT_NOT:
        fprintf (fp, "~ (");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ")");
        break;
      case EXPR_L_SHIFT:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") << (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_R_SHIFT:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") >> (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case EXPR_R_USHIFT:
        fprintf (fp, "(");
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, ") >>> (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;
      case COMP_MATCH:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " >< ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case COMP_NOMATCH:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " >!< ");
        nasl_dump_expr (fp, c->link[1]);
        break;

      case COMP_RE_MATCH:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " =~ ");
        nasl_dump_expr (fp, c->link[1]);
        break;

      case COMP_RE_NOMATCH:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " !~ ");
        nasl_dump_expr (fp, c->link[1]);
        break;

      case COMP_LT:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " < ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case COMP_LE:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " <= ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case COMP_GT:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " > ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case COMP_GE:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " >= ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case COMP_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " == ");
        nasl_dump_expr (fp, c->link[1]);
        break;
      case CONST_INT:
        fprintf (fp, "%ld", c->x.i_val);
        break;
      case CONST_STR:
      case CONST_DATA:
        fprintf (fp, "\"%s\"", c->x.str_val);
        break;

      case NODE_ARRAY_EL:
        fprintf (fp, "%s[", c->x.str_val);
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "]");
        break;

      case NODE_FUN_CALL:
        fprintf (fp, "%s(...)", c->x.str_val);
        break;

      case NODE_AFF:
        nasl_dump_expr (fp, c->link[0]);
        putc ('=', fp);
        nasl_dump_expr (fp, c->link[1]);
        break;

      case NODE_PLUS_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "+= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_MINUS_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "-= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_MULT_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "*= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_DIV_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "/= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_MODULO_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, "%%= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_L_SHIFT_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " <<= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_R_SHIFT_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " >>= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      case NODE_R_USHIFT_EQ:
        nasl_dump_expr (fp, c->link[0]);
        fprintf (fp, " >>>= (");
        nasl_dump_expr (fp, c->link[1]);
        fprintf (fp, ")");
        break;

      default:
        fprintf (fp, "*%d*", c->type);
        break;
      }
}

static void
nasl_short_dump (FILE *fp, const tree_cell *c)
{
  if (c == NULL || c == FAKE_CELL)
    return;

  switch (c->type)
    {
    case NODE_IF_ELSE:
      fprintf (fp, "NASL:%04d> if (", c->line_nb);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, ") { ... }");
      if (c->link[2] != NULL)
        fprintf (fp, " else { ... }");
      putc ('\n', fp);
      break;

    case NODE_FOR:
      fprintf (fp, "NASL:%04d> for (", c->line_nb);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, "; ");
      nasl_dump_expr (fp, c->link[1]);
      fprintf (fp, "; ");
      nasl_dump_expr (fp, c->link[2]);
      fprintf (fp, ") { ... }\n");
      break;

    case NODE_WHILE:
      fprintf (fp, "NASL:%04d> while (", c->line_nb);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, ") { ... }\n");
      break;

    case NODE_FOREACH:
      fprintf (fp, "NASL:%04d> foreach %s (", c->line_nb, c->x.str_val);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, ") { ... }\n");
      break;

    case NODE_REPEAT_UNTIL:
      fprintf (fp, "NASL:%04d> repeat { ... } until (", c->line_nb);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, ")\n");
      break;

    case NODE_REPEATED:
      fprintf (fp, "NASL:%04d> ... x ", c->line_nb);
      nasl_dump_expr (fp, c->link[1]);
      putc ('\n', fp);
      break;

    case NODE_RETURN:
      fprintf (fp, "NASL:%04d> return ", c->line_nb);
      nasl_dump_expr (fp, c->link[0]);
      fprintf (fp, ";\n");
      break;

    case NODE_BREAK:
      fprintf (fp, "NASL:%04d> break\n", c->line_nb);
      break;

    case NODE_CONTINUE:
      fprintf (fp, "NASL:%04d> continue\n", c->line_nb);
      break;

    case NODE_AFF:
    case NODE_PLUS_EQ:
    case NODE_MINUS_EQ:
    case NODE_MULT_EQ:
    case NODE_DIV_EQ:
    case NODE_MODULO_EQ:
    case NODE_R_SHIFT_EQ:
    case NODE_R_USHIFT_EQ:
    case NODE_L_SHIFT_EQ:
      fprintf (fp, "NASL:%04d> ", c->line_nb);
      nasl_dump_expr (fp, c);
      fprintf (fp, ";\n");
      break;

    case NODE_FUN_CALL:
      fprintf (fp, "NASL:%04d> %s(...)\n", c->line_nb, c->x.str_val);
      break;

    case NODE_LOCAL:
      fprintf (fp, "NASL:%04d> local_var ...\n", c->line_nb);
      break;

    case NODE_GLOBAL:
      fprintf (fp, "NASL:%04d> global_var ...\n", c->line_nb);
      break;
    }
}

/** @todo This is an algorithm for calculating x^y, replace it if possible. */
static long int
expo (long int x, long int y)
{
  long int z;

  if (y == 0)
    return 1;
  else if (y < 0)
    if (x == 1)
      return 1;
    else
      return 0;
  else if (y == 1)
    return x;

  z = expo (x, y / 2);
  if (y % 2 == 0)
    return z * z;
  else
    return x * z * z;
}

/**
 * @brief Execute a parse tree
 */
tree_cell *
nasl_exec (lex_ctxt *lexic, tree_cell *st)
{
  tree_cell *ret = NULL, *ret2 = NULL, *tc1 = NULL, *tc2 = NULL, *tc3 = NULL,
            *idx = NULL, *args;
  int flag, z;
  char *s1 = NULL, *s2 = NULL, *s3 = NULL, *p = NULL;
  char *p1, *p2;
  int len1, len2;
  nasl_func *pf = NULL;
  long int x, y, n;
  int i, lint_mode = 0;

  if (st)
    if (st->line_nb != 0)
      lexic->line_nb = st->line_nb;
  /* return */
  if (lexic->ret_val != NULL)
    {
      ref_cell (lexic->ret_val);
      return lexic->ret_val;
    }

  /* break or continue */
  if (lexic->break_flag || lexic->cont_flag)
    return FAKE_CELL;

  if (st == FAKE_CELL)
    return FAKE_CELL;

  if (st == NULL)
    {
      return NULL;
    }

  if (nasl_trace_fp != NULL)
    nasl_short_dump (nasl_trace_fp, st);

  switch (st->type)
    {
    case NODE_IF_ELSE:
      ret = nasl_exec (lexic, st->link[0]);
#ifdef STOP_AT_FIRST_ERROR
      if (ret == NULL)
        return NULL;
#endif
      if (cell2bool (lexic, ret))
        ret2 = nasl_exec (lexic, st->link[1]);
      else if (st->link[2] != NULL) /* else branch */
        ret2 = nasl_exec (lexic, st->link[2]);
      else /* No else */
        ret2 = FAKE_CELL;
      deref_cell (ret);
      return ret2;

    case NODE_INSTR_L: /* Block. [0] = first instr, [1] = tail */
      ret = nasl_exec (lexic, st->link[0]);
      if (st->link[1] == NULL || lexic->break_flag || lexic->cont_flag)
        return ret;
      deref_cell (ret);
      ret = nasl_exec (lexic, st->link[1]);
      return ret;

    case NODE_FOR:
      /* [0] = start expr, [1] = cond, [2] = end_expr, [3] = block */
      ret2 = nasl_exec (lexic, st->link[0]);
#ifdef STOP_AT_FIRST_ERROR
      if (ret2 == NULL)
        return NULL;
#endif
      deref_cell (ret2);
      for (;;)
        {
          /* Break the loop if 'return' */
          if (lexic->ret_val != NULL)
            {
              ref_cell (lexic->ret_val);
              return lexic->ret_val;
            }

          /* condition */
          if ((ret = nasl_exec (lexic, st->link[1])) == NULL)
            return NULL; /* We can return here, as NULL is false */
          flag = cell2bool (lexic, ret);
          deref_cell (ret);
          if (!flag)
            break;
          /* block */
          ret = nasl_exec (lexic, st->link[3]);
#ifdef STOP_AT_FIRST_ERROR
          if (ret == NULL)
            return NULL;
#endif
          deref_cell (ret);

          /* break */
          if (lexic->break_flag)
            {
              lexic->break_flag = 0;
              return FAKE_CELL;
            }

          lexic->cont_flag = 0; /* No need to test if set */

          /* end expression */
          ret = nasl_exec (lexic, st->link[2]);
#ifdef STOP_AT_FIRST_ERROR
          if (ret == NULL)
            return NULL;
#endif
          deref_cell (ret);
        }
      return FAKE_CELL;

    case NODE_WHILE:
      /* [0] = cond, [1] = block */
      for (;;)
        {
          /* return? */
          if (lexic->ret_val != NULL)
            {
              ref_cell (lexic->ret_val);
              return lexic->ret_val;
            }
          /* Condition */
          if ((ret = nasl_exec (lexic, st->link[0])) == NULL)
            return NULL; /* NULL is false */
          flag = cell2bool (lexic, ret);
          deref_cell (ret);
          if (!flag)
            break;
          /* Block */
          ret = nasl_exec (lexic, st->link[1]);
#ifdef STOP_AT_FIRST_ERROR
          if (ret == NULL)
            return NULL;
#endif
          deref_cell (ret);

          /* break */
          if (lexic->break_flag)
            {
              lexic->break_flag = 0;
              return FAKE_CELL;
            }
          lexic->cont_flag = 0;
        }
      return FAKE_CELL;

    case NODE_REPEAT_UNTIL:
      /* [0] = block, [1] = cond  */
      for (;;)
        {
          /* return? */
          if (lexic->ret_val != NULL)
            {
              ref_cell (lexic->ret_val);
              return lexic->ret_val;
            }
          /* Block */
          ret = nasl_exec (lexic, st->link[0]);
#ifdef STOP_AT_FIRST_ERROR
          if (ret == NULL)
            return NULL;
#endif
          deref_cell (ret);

          /* break */
          if (lexic->break_flag)
            {
              lexic->break_flag = 0;
              return FAKE_CELL;
            }
          lexic->cont_flag = 0;

          /* Condition */
          ret = nasl_exec (lexic, st->link[1]);
#ifdef STOP_AT_FIRST_ERROR
          if (ret == NULL)
            return NULL;
#endif
          flag = cell2bool (lexic, ret);
          deref_cell (ret);
          if (flag)
            break;
        }
      return FAKE_CELL;

    case NODE_FOREACH:
      /* str_val = index name, [0] = array, [1] = block */
      {
        nasl_iterator ai;
        tree_cell *v, *a, *val;

        v = get_variable_by_name (lexic, st->x.str_val);
        if (v == NULL)
          return NULL; /* We cannot go on if we have no variable to iterate */
        a = nasl_exec (lexic, st->link[0]);
        ai = nasl_array_iterator (lexic, a);
        while ((val = nasl_iterate_array (&ai)) != NULL)
          {
            tc1 = nasl_affect (v, val);
            ret = nasl_exec (lexic, st->link[1]);
            deref_cell (val);
            deref_cell (tc1);
#ifdef STOP_AT_FIRST_ERROR
            if (ret == NULL)
              break;
#endif
            deref_cell (ret);

            /* return */
            if (lexic->ret_val != NULL)
              break;
            /* break */
            if (lexic->break_flag)
              {
                lexic->break_flag = 0;
                break;
              }
            lexic->cont_flag = 0;
          }
        free_array (ai.a);
        g_free (ai.a);
        deref_cell (a);
        deref_cell (v);
      }
      return FAKE_CELL;

    case NODE_FUN_DEF:
      /* x.str_val = function name, [0] = argdecl, [1] = block */
      /* 3rd arg is only for lint. Hier is always 0 */
      ret = decl_nasl_func (lexic, st, lint_mode);
      return ret;

    case NODE_FUN_CALL:
      pf = get_func_ref_by_name (lexic, st->x.str_val);
      if (pf == NULL)
        {
          nasl_perror (lexic, "Undefined function '%s'\n", st->x.str_val);
          return NULL;
        }
      args = st->link[0];
      ret = nasl_func_call (lexic, pf, args);
      return ret;

    case NODE_REPEATED:
      n = cell2intW (lexic, st->link[1]);
      if (n <= 0)
        return NULL;

#ifdef STOP_AT_FIRST_ERROR
      for (tc1 = NULL, i = 1; i <= n; i++)
        {
          deref_cell (tc1);
          if ((tc1 = nasl_exec (lexic, st->link[0])) == NULL)
            return NULL;
        }
      return tc1;
#else
      for (i = 1; i <= n; i++)
        {
          tc1 = nasl_exec (lexic, st->link[0]);
          deref_cell (tc1);
        }
      return FAKE_CELL;
#endif

      /*
       * I wonder...
       * Will nasl_exec be really called with NODE_EXEC or NODE_ARG?
       */
    case NODE_DECL: /* Used in function declarations */
      /* [0] = next arg in list */
      /* TBD? */
      return st; /* ? */

    case NODE_ARG: /* Used function calls */
      /* val = name can be NULL, [0] = val, [1] = next arg */
      ret = nasl_exec (lexic, st->link[0]); /* Is this wise? */
      return ret;

    case NODE_RETURN:
      /* [0] = ret val */
      ret = nasl_return (lexic, st->link[0]);
      return ret;

    case NODE_BREAK:
      lexic->break_flag = 1;
      return FAKE_CELL;

    case NODE_CONTINUE:
      lexic->cont_flag = 1;
      return FAKE_CELL;

    case NODE_ARRAY_EL: /* val = array name, [0] = index */
      idx = cell2atom (lexic, st->link[0]);
      ret = get_array_elem (lexic, st->x.str_val, idx);
      deref_cell (idx);
      return ret;

      /** @todo There is a lot of duplicated code in following cases, could be
       * refactored. */
    case NODE_AFF:
      /* [0] = lvalue, [1] = rvalue */
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      ret = nasl_affect (tc1, tc2);
      deref_cell (tc1); /* Must free VAR_REF */
      deref_cell (ret);
      return tc2; /* So that "a = b = e;" works */

    case NODE_PLUS_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_PLUS, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2; /* So that "a = b += e;" works */

    case NODE_MINUS_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_MINUS, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2; /* So that "a = b -= e;" works */

    case NODE_MULT_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_MULT, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_DIV_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_DIV, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_MODULO_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_MODULO, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_L_SHIFT_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_L_SHIFT, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_R_SHIFT_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_R_SHIFT, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_R_USHIFT_EQ:
      tc1 = nasl_exec (lexic, st->link[0]);
      tc2 = nasl_exec (lexic, st->link[1]);
      tc3 = alloc_expr_cell (0, EXPR_R_USHIFT, tc1, tc2);
      ret2 = nasl_exec (lexic, tc3);
      ret = nasl_affect (tc1, ret2);
      deref_cell (tc3); /* Frees tc1 and tc2 */
      deref_cell (ret);
      return ret2;

    case NODE_VAR:
      /* val = variable name */
      ret = get_variable_by_name (lexic, st->x.str_val);
      return ret;

    case NODE_LOCAL: /* [0] = argdecl */
      ret = decl_local_variables (lexic, st->link[0]);
      return ret;

    case NODE_GLOBAL: /* [0] = argdecl */
      ret = decl_global_variables (lexic, st->link[0]);
      return ret;

    case EXPR_AND:
      x = cell2bool (lexic, st->link[0]);
      if (!x)
        return bool2cell (0);

      y = cell2bool (lexic, st->link[1]);
      return bool2cell (y);

    case EXPR_OR:
      x = cell2bool (lexic, st->link[0]);
      if (x)
        return bool2cell (x);
      y = cell2bool (lexic, st->link[1]);
      return bool2cell (y);

    case EXPR_NOT:
      x = cell2bool (lexic, st->link[0]);
      return bool2cell (!x);

    case EXPR_INCR:
    case EXPR_DECR:
      x = (st->type == EXPR_INCR) ? 1 : -1;
      if (st->link[0] == NULL)
        {
          y = 1; /* pre */
          tc1 = st->link[1];
        }
      else
        {
          y = 0; /* post */
          tc1 = st->link[0];
        }
      tc2 = nasl_exec (lexic, tc1);
      if (tc2 == NULL)
        return NULL;
      ret = nasl_incr_variable (lexic, tc2, y, x);
      deref_cell (tc2);
      return ret;

    case EXPR_PLUS:
      s1 = s2 = NULL;
      tc1 = cell2atom (lexic, st->link[0]);
#ifdef STOP_AT_FIRST_ERROR
      if (tc1 == NULL || tc1 == FAKE_CELL)
        return NULL;
#endif
      tc2 = cell2atom (lexic, st->link[1]);
      if (tc2 == NULL || tc2 == FAKE_CELL)
        {
#ifdef STOP_AT_FIRST_ERROR
          deref_cell (tc1);
          return NULL;
#else
          return tc1;
#endif
        }

      if (tc1 == NULL || tc1 == FAKE_CELL)
        return tc2;

      /*
       * Anything added to a string is converted to a string
       * Otherwise anything added to an intger is converted into an integer
       */
      if (tc1->type == CONST_DATA || tc2->type == CONST_DATA)
        flag = CONST_DATA;
      else if (tc1->type == CONST_STR || tc2->type == CONST_STR)
        flag = CONST_STR;
      else if (tc1->type == CONST_INT || tc2->type == CONST_INT)
        flag = CONST_INT;
      else
        flag = NODE_EMPTY;
      switch (flag)
        {
          long sz;
        case CONST_INT:
          x = tc1->x.i_val;
          y = cell2int (lexic, tc2);
          ret = int2cell (x + y);
          break;

        case CONST_STR:
        case CONST_DATA:
          s1 = s2 = NULL;
          if (tc1->type == CONST_STR || tc1->type == CONST_DATA)
            len1 = tc1->size;
          else
            {
              s1 = cell2str (lexic, tc1);
              len1 = (s1 == NULL ? 0 : strlen (s1));
            }

          if (tc2->type == CONST_STR || tc2->type == CONST_DATA)
            len2 = tc2->size;
          else
            {
              s2 = cell2str (lexic, tc2);
              len2 = (s2 == NULL ? 0 : strlen (s2));
            }

          sz = len1 + len2;
          s3 = g_malloc0 (sz + 1);
          if (len1 > 0)
            memcpy (s3, s1 != NULL ? s1 : tc1->x.str_val, len1);
          if (len2 > 0)
            memcpy (s3 + len1, s2 != NULL ? s2 : tc2->x.str_val, len2);
          g_free (s1);
          g_free (s2);
          ret = alloc_typed_cell (flag);
          ret->x.str_val = s3;
          ret->size = sz;
          break;

        default:
          ret = NULL;
          break;
        }
      deref_cell (tc1);
      deref_cell (tc2);
      return ret;

    case EXPR_MINUS: /* Infamous duplicated code */
      s1 = s2 = NULL;
      tc1 = cell2atom (lexic, st->link[0]);
#ifdef STOP_AT_FIRST_ERROR
      if (tc1 == NULL || tc1 == FAKE_CELL)
        return NULL;
#endif
      tc2 = cell2atom (lexic, st->link[1]);
      if (tc2 == NULL || tc2 == FAKE_CELL)
        {
#ifdef STOP_AT_FIRST_ERROR
          deref_cell (tc1);
          return NULL;
#else
          return tc1;
#endif
        }

      if (tc1 == NULL || tc1 == FAKE_CELL)
        {
          if (tc2->type == CONST_INT)
            {
              y = cell2int (lexic, tc2);
              ret = int2cell (-y);
            }
          else
            ret = NULL;
          deref_cell (tc2);
          return ret;
        }

      /*
       * Anything subtracted from a string is converted to a string
       * Otherwise anything subtracted from integer is converted into an
       * integer
       */
      if (tc1->type == CONST_DATA || tc2->type == CONST_DATA)
        flag = CONST_DATA;
      else if (tc1->type == CONST_STR || tc2->type == CONST_STR)
        flag = CONST_STR;
      else if (tc1->type == CONST_INT || tc2->type == CONST_INT)
        flag = CONST_INT;
      else
        flag = NODE_EMPTY;
      switch (flag)
        {
        case CONST_INT:
          x = cell2int (lexic, tc1);
          y = cell2int (lexic, tc2);
          ret = int2cell (x - y);
          break;

        case CONST_STR:
        case CONST_DATA:
          if (tc1->type == CONST_STR || tc1->type == CONST_DATA)
            {
              p1 = tc1->x.str_val;
              len1 = tc1->size;
            }
          else
            {
              p1 = s1 = cell2str (lexic, tc1);
              len1 = (s1 == NULL ? 0 : strlen (s1));
            }

          if (tc2->type == CONST_STR || tc2->type == CONST_DATA)
            {
              p2 = tc2->x.str_val;
              len2 = tc2->size;
            }
          else
            {
              p2 = s2 = cell2str (lexic, tc2);
              len2 = (s2 == NULL ? 0 : strlen (s2));
            }

          /* if p1 is null, last condition p=memem() will not be evaluated
           * and p remains NULL */
          if (len2 == 0 || len1 < len2
              || (p1 != NULL && (p = memmem (p1, len1, p2, len2)) == NULL))
            {
              s3 = g_malloc0 (len1 + 1);
              if (p1 != NULL)
                memcpy (s3, p1, len1);
              ret = alloc_typed_cell (flag);
              ret->x.str_val = s3;
              ret->size = len1;
            }
          else
            {
              long sz = len1 - len2;
              if (sz <= 0)
                {
                  sz = 0;
                  s3 = g_strdup ("");
                }
              else
                {
                  s3 = g_malloc0 (sz + 1);
                  if (p - p1 > 0)
                    memcpy (s3, p1, p - p1);
                  if (p != NULL && sz > p - p1)
                    memcpy (s3 + (p - p1), p + len2, sz - (p - p1));
                }
              ret = alloc_typed_cell (flag);
              ret->x.str_val = s3;
              ret->size = sz;
            }

          g_free (s1);
          g_free (s2);
          break;

        default:
          ret = NULL;
          break;
        }
      deref_cell (tc1);
      deref_cell (tc2);
      return ret;

    case EXPR_MULT:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (x * y);

    case EXPR_DIV:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      if (y != 0)
        return int2cell (x / y);
      else
        return int2cell (0);

    case EXPR_EXPO:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (expo (x, y));

    case EXPR_MODULO:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      if (y != 0)
        return int2cell (x % y);
      else
        return int2cell (0);

    case EXPR_BIT_AND:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (x & y);

    case EXPR_BIT_OR:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (x | y);

    case EXPR_BIT_XOR:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (x ^ y);

    case EXPR_BIT_NOT:
      x = cell2intW (lexic, st->link[0]);
      return int2cell (~x);

    case EXPR_U_MINUS:
      x = cell2intW (lexic, st->link[0]);
      return int2cell (-x);

      /* TBD: Handle shift for strings and arrays */
    case EXPR_L_SHIFT:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      return int2cell (x << y);

    case EXPR_R_SHIFT: /* arithmetic right shift */
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      z = x >> y;
#ifndef __GNUC__
      if (x < 0 && z >= 0) /* Fix it */
        z |= (~0) << (sizeof (x) * 8 - y);
#endif
      return int2cell (z);

    case EXPR_R_USHIFT:
      x = cell2intW (lexic, st->link[0]);
      y = cell2intW (lexic, st->link[1]);
      z = (unsigned) x >> (unsigned) y;
#ifndef __GNUC__
      if (x < 0 && z <= 0) /* Fix it! */
        z &= ~((~0) << (sizeof (x) * 8 - y));
#endif
      return int2cell (z);

    case COMP_MATCH:
    case COMP_NOMATCH:
      tc1 = cell2atom (lexic, st->link[0]);
      tc2 = cell2atom (lexic, st->link[1]);
      s1 = s2 = NULL;

      if (tc1 == NULL || tc1 == FAKE_CELL)
        {
          p1 = "";
          len1 = 0;
        }
      else if (tc1->type == CONST_STR || tc1->type == CONST_DATA)
        {
          p1 = tc1->x.str_val;
          len1 = tc1->size;
        }
      else
        {
          p1 = s1 = cell2str (lexic, tc1);
          len1 = strlen (s1);
        }

      if (tc2 == NULL || tc2 == FAKE_CELL)
        {
          p2 = "";
          len2 = 0;
        }
      else if (tc2->type == CONST_STR || tc2->type == CONST_DATA)
        {
          p2 = tc2->x.str_val;
          len2 = tc2->size;
        }
      else
        {
          p2 = s2 = cell2str (lexic, tc2);
          len2 = strlen (s2);
        }

      if (len1 <= len2)
        flag = (memmem (p2, len2, p1, len1) != NULL);
      else
        flag = 0;

      g_free (s1);
      g_free (s2);
      deref_cell (tc1);
      deref_cell (tc2);
      if (st->type == COMP_MATCH)
        return bool2cell (flag);
      else
        return bool2cell (!flag);

    case COMP_RE_MATCH:
    case COMP_RE_NOMATCH:
      if (st->x.ref_val == NULL)
        {
          nasl_perror (lexic, "nasl_exec: bad regex at or near line %d\n",
                       st->line_nb);
          return NULL;
        }
      s1 = cell2str (lexic, st->link[0]);
      if (s1 == NULL)
        return 0;
      flag = regexec (st->x.ref_val, s1, 0, NULL, 0);
      g_free (s1);
      if (st->type == COMP_RE_MATCH)
        return bool2cell (flag != REG_NOMATCH);
      else
        return bool2cell (flag == REG_NOMATCH);

    case COMP_LT:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) < 0);

    case COMP_LE:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) <= 0);

    case COMP_EQ:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) == 0);

    case COMP_NE:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) != 0);

    case COMP_GT:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) > 0);

    case COMP_GE:
      return bool2cell (cell_cmp (lexic, st->link[0], st->link[1]) >= 0);

    case REF_ARRAY:
    case DYN_ARRAY:
    case CONST_INT:
    case CONST_STR:
    case CONST_DATA:
      ref_cell (st); /* nasl_exec returns a cell that should be deref-ed */
      return st;

    case REF_VAR:
      ret = nasl_read_var_ref (lexic, st);
      return ret;

    default:
      nasl_perror (lexic, "nasl_exec: unhandled node type %d\n", st->type);
      abort ();
      return NULL;
    }
}

/**
 * @brief Execute a NASL script.
 *
 * "mode" is a bit field:
 * bit #0 (1) is "description"
 * Bit #1 (2) is "parse only"
 *
 * @param   script_infos    The plugin script_infos.
 * #param   mode            Flags for different execution modes (Description,
 *                          parse-only, always-signed, command-line, lint)
 *
 * @return 0 if the script was executed successfully, negative values if an
 * error occurred. Return number of errors if mode is NASL_LINT and no none
 * linting errors occurred.
 */
int
exec_nasl_script (struct script_infos *script_infos, int mode)
{
  naslctxt ctx;
  nasl_func *pf;
  int err = 0, to;
  tree_cell *ret;
  lex_ctxt *lexic;
  gchar *old_dir;
  gchar *newdir;
  tree_cell tc;
  const char *str, *name = script_infos->name, *oid = script_infos->oid;
  gchar *short_name = g_path_get_basename (name);
  int error_counter = 0;

  nasl_set_plugin_filename (short_name);
  g_free (short_name);

  srand48 (getpid () + getppid () + (long) time (NULL));

  old_dir = g_get_current_dir ();

  newdir = g_path_get_dirname (name);

  if (g_chdir (newdir) != 0)
    {
      g_message ("%s: Not able to change working directory to %s (%d [%s]).",
                 __func__, newdir, errno, strerror (errno));
      g_free (old_dir);
      g_free (newdir);
      return -1;
    }
  g_free (newdir);

  bzero (&ctx, sizeof (ctx));
  if (mode & NASL_ALWAYS_SIGNED)
    ctx.always_signed = 1;
  if ((mode & NASL_EXEC_DESCR) != 0)
    ctx.exec_descr = 1;
  if (nvticache_initialized ())
    ctx.kb = nvticache_get_kb ();
  else
    ctx.kb = plug_get_kb (script_infos);

  if (init_nasl_ctx (&ctx, name) == 0)
    {
      err = naslparse (&ctx, &error_counter);
      if (err != 0 || error_counter > 0)
        {
          g_message ("%s. There were %d parse errors.", name, error_counter);
          nasl_clean_ctx (&ctx);
          g_chdir (old_dir);
          g_free (old_dir);
          return -1;
        }
    }
  else
    {
      g_chdir (old_dir);
      g_free (old_dir);
      return -1;
    }

  lexic = init_empty_lex_ctxt ();
  lexic->script_infos = script_infos;
  lexic->oid = oid;
  nasl_set_filename (name);

  str = prefs_get ("checks_read_timeout");
  if (str != NULL)
    to = atoi (str);
  else
    to = 5;

  if (to <= 0)
    to = 5;

  lexic->recv_timeout = to;

  if (mode & NASL_LINT)
    {
      /* ret is set to the number of errors the linter finds.
      ret will be overwritten with -1 if any errors occur in the steps
      after linting so we do not break other behaviour dependent on a
      negative return value when doing more than just linting. */
      tree_cell *lintret = nasl_lint (lexic, ctx.tree);
      if (lintret == NULL)
        err--;
      else if (lintret != FAKE_CELL && lintret->x.i_val > 0)
        {
          err = lintret->x.i_val;
          g_free (lintret);
        }
    }
  else if (!(mode & NASL_EXEC_PARSE_ONLY))
    {
      char *p;

      bzero (&tc, sizeof (tc));
      tc.type = CONST_INT;
      tc.x.i_val = (mode & NASL_COMMAND_LINE) != 0;
      add_named_var_to_ctxt (lexic, "COMMAND_LINE", &tc);

      bzero (&tc, sizeof (tc));
      tc.type = CONST_INT;
      tc.x.i_val = (mode & NASL_EXEC_DESCR) != 0;
      add_named_var_to_ctxt (lexic, "description", &tc);

      tc.type = CONST_DATA;
      p = strrchr (name, '/');
      if (p == NULL)
        p = (char *) name;
      else
        p++;
      tc.x.str_val = p;
      tc.size = strlen (p);
      add_named_var_to_ctxt (lexic, "SCRIPT_NAME", &tc);

      truc = (lex_ctxt *) ctx.tree;
      if ((ret = nasl_exec (lexic, ctx.tree)) == NULL)
        err = -1;
      else
        deref_cell (ret);

      if ((pf = get_func_ref_by_name (lexic, "on_exit")) != NULL)
        nasl_func_call (lexic, pf, NULL);
    }

  if (g_chdir (old_dir) != 0)
    {
      g_free (old_dir);
      return -1;
    }
  g_free (old_dir);

  nasl_clean_ctx (&ctx);
  free_lex_ctxt (lexic);
  return err;
}
