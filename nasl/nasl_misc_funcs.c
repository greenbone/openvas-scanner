/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_misc_funcs.c
 * @brief This file contains all the misc. functions found in NASL
 */

#include "nasl_misc_funcs.h"

#include "../misc/ftp_funcs.h"     /* for ftp_log_in */
#include "../misc/heartbeat.h"     /* plug_get_host_open_port */
#include "../misc/network.h"       /* read_stream_connection_min */
#include "../misc/plugutils.h"     /* plug_get_host_open_port */
#include "../misc/vendorversion.h" /* for vendor_version_get */
#include "byteorder.h"
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_packet_forgery.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <errno.h> /* for errno */
#include <glib.h>
#include <gvm/util/compressutils.h> /* for gvm_uncompress */
#include <gvm/util/kb.h>            /* for KB_TYPE_STR */
#include <stdbool.h>                /* for boolean */
#include <stdlib.h>                 /* for lrand48 */
#include <string.h>                 /* for bzero */
#include <sys/time.h>               /* for gettimeofday */
#include <unistd.h>                 /* for usleep */

#define uint32 unsigned int

#define NASL_EXIT_DEPRECATED 66
#define NASL_EXIT_NOTVULN 99

/*---------------------------------------------------------------------*/
tree_cell *
nasl_rand (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc;
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = lrand48 ();
  return retc;
}

/*---------------------------------------------------------------------*/
tree_cell *
nasl_usleep (lex_ctxt *lexic)
{
  int slp = get_int_var_by_num (lexic, 0, 0);
  usleep (slp);
  return FAKE_CELL;
}

tree_cell *
nasl_sleep (lex_ctxt *lexic)
{
  int slp = get_int_var_by_num (lexic, 0, 0);
  sleep (slp);
  return FAKE_CELL;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_ftp_log_in (lex_ctxt *lexic)
{
  char *u, *p;
  int soc;
  tree_cell *retc;
  int res;

  soc = get_int_var_by_name (lexic, "socket", 0);
  if (soc <= 0)
    return NULL;

  u = get_str_var_by_name (lexic, "user");
  if (u == NULL)
    u = "";

  p = get_str_var_by_name (lexic, "pass");
  if (p == NULL)
    p = "";

  res = ftp_log_in (soc, u, p) == 0;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = res;

  return retc;
}

tree_cell *
nasl_ftp_get_pasv_address (lex_ctxt *lexic)
{
  int soc;
  struct sockaddr_in addr;
  tree_cell *retc;

  soc = get_int_var_by_name (lexic, "socket", 0);
  if (soc <= 0)
    return NULL;

  bzero (&addr, sizeof (addr));
  ftp_get_pasv_address (soc, &addr);

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ntohs (addr.sin_port);
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_telnet_init (lex_ctxt *lexic)
{
  int soc = get_int_var_by_num (lexic, 0, -1);
  int opts; /* number of options recorded */
  unsigned char buffer[1024];
#define iac buffer[0]
#define code buffer[1]
#define option buffer[2]
  tree_cell *retc;
  int n = 0, n2;
  int lm = 0;

  if (soc <= 0)
    {
      nasl_perror (lexic, "Syntax error in the telnet_init() function\n");
      nasl_perror (lexic,
                   "Correct syntax is : output = telnet_init(<socket>)\n");
      return NULL;
    }

  iac = 255;
  opts = 0;
  while (iac == 255)
    {
      n = read_stream_connection_min (soc, buffer, 3, 3);
      if ((iac != 255) || (n <= 0) || (n != 3))
        break;
      if ((code == 251) || (code == 252))
        code = 254; /* WILL , WONT -> DON'T */
      else if ((code == 253) || (code == 254))
        code = 252; /* DO,DONT -> WONT */
      write_stream_connection (soc, buffer, 3);
      if (lm == 0)
        {
          code = 253;
          option = 0x22;
          write_stream_connection (soc, buffer, 3);
          lm++;
        }
      opts++;
      if (opts > 100)
        break;
    }
  if (n <= 0)
    {
      if (opts == 0)
        return NULL;
      else
        n = 0;
    }

  if (opts > 100) /* remote telnet server is crazy */
    {
      nasl_perror (lexic, "More than 100 options received by telnet_init() "
                          "function! exiting telnet_init.\n");
      return NULL;
    }

  n2 = read_stream_connection (soc, buffer + n, sizeof (buffer) - n);
  if (n2 > 0)
    n += n2;
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = n;
  retc->x.str_val = g_malloc0 (n + 1);
  memcpy (retc->x.str_val, buffer, n + 1);
#undef iac
#undef data
#undef option

  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_start_denial (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  int to = lexic->recv_timeout;
  int port = plug_get_host_open_port (script_infos);
  int soc;
  int alive = 0;
  tree_cell *p;

  if (port)
    {
      soc = open_stream_connection (script_infos, port, OPENVAS_ENCAPS_IP, to);
      if (soc >= 0)
        {
          script_infos->denial_port = port;
          close_stream_connection (soc);

          return FAKE_CELL;
        }
    }

  p = nasl_tcp_ping (lexic);
  if (p != NULL)
    alive = p->x.i_val;

  script_infos->alive = alive;
  deref_cell (p);

  return FAKE_CELL;
}

tree_cell *
nasl_end_denial (lex_ctxt *lexic)
{
  int port = lexic->script_infos->denial_port;
  int soc;
  int to = lexic->recv_timeout;
  struct script_infos *script_infos = lexic->script_infos;
  kb_t kb = plug_get_kb (script_infos);
  tree_cell *retc = NULL;
  char *bogus_data;

  /*
   * We must wait the time the DoS does its effect
   */
  sleep (10);

  if (!port)
    {
      int ping = script_infos->alive;

      if (ping)
        return nasl_tcp_ping (lexic);
      else
        {
          retc = alloc_typed_cell (CONST_INT);
          retc->x.i_val = 1;
          return retc;
        }
    }
  else
    {
      retc = alloc_typed_cell (CONST_INT);

      soc = open_stream_connection (script_infos, port, OPENVAS_ENCAPS_IP, to);
      if (soc > 0)
        {
          /* Send some data */
          bogus_data = g_strdup_printf (
            "Network Security Scan by %s in progress", vendor_version_get ());
          if ((nsend (soc, bogus_data, strlen (bogus_data), 0)) >= 0)
            {
              g_free (bogus_data);
              retc->x.i_val = 1;
              close_stream_connection (soc);
              return retc;
            }
          g_free (bogus_data);
        }
    }

  // Services seem to not respond.
  // Last test with boreas
  if (check_host_still_alive (kb, plug_current_vhost ()) == 1)
    retc->x.i_val = 1;
  else
    retc->x.i_val = 0;
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_dump_ctxt (lex_ctxt *lexic)
{
  dump_ctxt (lexic->up_ctxt);
  return FAKE_CELL;
}

static void
simple_register_host_detail (lex_ctxt *lexic, char *name, char *value)
{
  char detail[128];
  const char *oid = lexic->oid;

  plug_set_key (lexic->script_infos, "HostDetails", ARG_STRING, name);
  plug_set_key (lexic->script_infos, "HostDetails/NVT", ARG_STRING,
                (void *) oid);

  g_snprintf (detail, sizeof (detail), "HostDetails/NVT/%s/%s", oid, name);
  plug_set_key (lexic->script_infos, detail, ARG_STRING, value);
}

tree_cell *
nasl_do_exit (lex_ctxt *lexic)
{
  int retcode = get_int_var_by_num (lexic, 0, 0);
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = retcode;

  if (retcode == NASL_EXIT_NOTVULN)
    simple_register_host_detail (lexic, "EXIT_CODE", "EXIT_NOTVULN");

  //  if (retcode == NASL_EXIT_DEPRECATED)
  // This return code is reserved for future handling.

  while (lexic != NULL)
    {
      lexic->ret_val = retc;
      ref_cell (retc);
      lexic = lexic->up_ctxt;
    }
  return retc;
}

/*---------------------------------------------------------------------*/

tree_cell *
nasl_isnull (lex_ctxt *lexic)
{
  int t;
  tree_cell *retc;

  t = get_var_type_by_num (lexic, 0);
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = (t == VAR2_UNDEF);
  return retc;
}

/**
 * This function takes any kind & any number of arguments and makes
 * an array from them.
 * If an argument is an array, its index are lost
 */
tree_cell *
nasl_make_list (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  int i, j, vi;
  anon_nasl_var *v;
  named_nasl_var *vn;
  nasl_array *a, *a2;

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  for (i = vi = 0;
       (v = nasl_get_var_by_num (lexic, &lexic->ctx_vars, vi, 0)) != NULL; vi++)
    {
      switch (v->var_type)
        {
        case VAR2_INT:
        case VAR2_STRING:
        case VAR2_DATA:
          add_var_to_list (a, i++, v);
          break;

        case VAR2_ARRAY:
          a2 = &v->v.v_arr;

          for (j = 0; j < a2->max_idx; j++)
            if (add_var_to_list (a, i, a2->num_elt[j]) >= 1)
              i++;

          if (a2->hash_elt != NULL)
            {
              for (j = 0; j < VAR_NAME_HASH; j++)
                for (vn = a2->hash_elt[j]; vn != NULL; vn = vn->next_var)
                  if (vn->u.var_type != VAR2_UNDEF)
                    if (add_var_to_list (a, i, &vn->u) >= 1)
                      i++;
            }

          break;

        case VAR2_UNDEF:
          nasl_perror (lexic,
                       "nasl_make_list: undefined variable #%d skipped\n", i);
          continue;

        default:
          nasl_perror (
            lexic, "nasl_make_list: unhandled variable type 0x%x - skipped\n",
            v->var_type);
          continue;
        }
    }

  return retc;
}

/*
 * This function takes any _even_ number of arguments and makes
 * an array from them. In each pair, the 1st argument is the index, the
 * 2nd the value.
 * Illegal types are dropped with a warning
 */

tree_cell *
nasl_make_array (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  int vi;
  anon_nasl_var *v, *v2;
  nasl_array *a;

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  vi = 0;
  while ((v = nasl_get_var_by_num (lexic, &lexic->ctx_vars, vi++, 0)) != NULL)
    {
      v2 = nasl_get_var_by_num (lexic, &lexic->ctx_vars, vi++, 0);
      if (v2 == NULL)
        {
          nasl_perror (lexic, "make_array: odd number (%d) of argument?\n", vi);
          break;
        }

      switch (v2->var_type)
        {
        case VAR2_INT:
        case VAR2_STRING:
        case VAR2_DATA:
          switch (v->var_type)
            {
            case VAR2_INT:
              add_var_to_list (a, v->v.v_int, v2);
              break;
            case VAR2_STRING:
            case VAR2_DATA:
              add_var_to_array (a, (char *) var2str (v), v2);
              break;
            }
          break;
        case VAR2_UNDEF:
        default:
          nasl_perror (lexic, "make_array: bad value type %d for arg #%d\n",
                       v2->var_type, vi);
          break;
        }
    }

  return retc;
}

tree_cell *
nasl_keys (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  anon_nasl_var *v, myvar;
  named_nasl_var *vn;
  nasl_array *a, *a2;
  int i, j, vi;

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a2 = g_malloc0 (sizeof (nasl_array));

  bzero (&myvar, sizeof (myvar));

  for (i = vi = 0;
       (v = nasl_get_var_by_num (lexic, &lexic->ctx_vars, vi, 0)) != NULL; vi++)
    {
      if (v->var_type == VAR2_ARRAY)
        {
          a = &v->v.v_arr;
          /* First the numerical index */
          for (j = 0; j < a->max_idx; j++)
            if (a->num_elt[j] != NULL && a->num_elt[j]->var_type != VAR2_UNDEF)
              {
                myvar.var_type = VAR2_INT;
                myvar.v.v_int = j;
                add_var_to_list (a2, i++, &myvar);
              }
          /* Then the string index */
          if (a->hash_elt != NULL)
            for (j = 0; j < VAR_NAME_HASH; j++)
              for (vn = a->hash_elt[j]; vn != NULL; vn = vn->next_var)
                if (vn->u.var_type != VAR2_UNDEF)
                  {
                    myvar.var_type = VAR2_STRING;
                    myvar.v.v_str.s_val = (unsigned char *) vn->var_name;
                    myvar.v.v_str.s_siz = strlen (vn->var_name);
                    add_var_to_list (a2, i++, &myvar);
                  }
        }
      else
        nasl_perror (lexic, "nasl_keys: bad variable #%d skipped\n", vi);
    }

  return retc;
}

tree_cell *
nasl_max_index (lex_ctxt *lexic)
{
  tree_cell *retc;
  anon_nasl_var *v;
  nasl_array *a;

  v = nasl_get_var_by_num (lexic, &lexic->ctx_vars, 0, 0);
  if (v == NULL)
    return NULL;
  if (v->var_type != VAR2_ARRAY)
    return NULL;

  a = &v->v.v_arr;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = array_max_index (a);

  return retc;
}

tree_cell *
nasl_typeof (lex_ctxt *lexic)
{
  tree_cell *retc;
  anon_nasl_var *u;
  const char *s;

  retc = alloc_typed_cell (CONST_DATA);
  u = nasl_get_var_by_num (lexic, &lexic->ctx_vars, 0, 0);

  if (u == NULL)
    s = "null";
  else
    switch (u->var_type)
      {
      case VAR2_UNDEF:
        s = "undef";
        break;
      case VAR2_INT:
        s = "int";
        break;
      case VAR2_STRING:
        s = "string";
        break;
      case VAR2_DATA:
        s = "data";
        break;
      case VAR2_ARRAY:
        s = "array";
        break;
      default:
        s = "unknown";
        break;
      }
  retc->size = strlen (s);
  retc->x.str_val = g_strdup (s);
  return retc;
}

tree_cell *
nasl_defined_func (lex_ctxt *lexic)
{
  void *f;
  char *s;
  tree_cell *retc;

  s = get_str_var_by_num (lexic, 0);
  if (s == NULL)
    {
      nasl_perror (lexic, "defined_func: missing parameter\n");
      return NULL;
    }

  f = get_func_ref_by_name (lexic, s);
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = (f != NULL);
  return retc;
}

/* Sorts an array */

static lex_ctxt *mylexic = NULL;

static int
var_cmp (const void *a, const void *b)
{
  anon_nasl_var **pv1 = (anon_nasl_var **) a, **pv2 = (anon_nasl_var **) b;
  tree_cell *t1, *t2;
  int ret;

  t1 = var2cell ((anon_nasl_var *) *pv1);
  t2 = var2cell ((anon_nasl_var *) *pv2);
  ret = cell_cmp (mylexic, t1, t2);
  deref_cell (t1);
  deref_cell (t2);

  return ret;
}

tree_cell *
nasl_sort_array (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  nasl_array *a;

  if (mylexic != NULL)
    {
      nasl_perror (lexic, "sort: this function is not reentrant!\n");
      return NULL;
    }
  mylexic = lexic;
  retc = nasl_make_list (lexic);
  if (retc != NULL)
    {
      a = retc->x.ref_val;
      if (a->num_elt != NULL)
        {
          qsort (a->num_elt, a->max_idx, sizeof (a->num_elt[0]), var_cmp);
        }
    }
  mylexic = NULL;
  return retc;
}

tree_cell *
nasl_unixtime (lex_ctxt *lexic)
{
  tree_cell *retc;

  (void) lexic;
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = time (NULL);
  return retc;
}

tree_cell *
nasl_gettimeofday (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct timeval t;
  char str[64];

  if (gettimeofday (&t, NULL) < 0)
    {
      nasl_perror (lexic, "gettimeofday: %s\n", strerror (errno));
      return NULL;
    }
  sprintf (str, "%u.%06u", (unsigned int) t.tv_sec, (unsigned int) t.tv_usec);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = strlen (str);
  retc->x.str_val = g_malloc0 (retc->size);
  strcpy (retc->x.str_val, str);
  return retc;
}

tree_cell *
nasl_localtime (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct tm ptm;
  time_t tictac;
  int utc;
  nasl_array *a;
  anon_nasl_var v;
  bool success;

  tictac = get_int_var_by_num (lexic, 0, 0);
  if (tictac == 0)
    tictac = time (NULL);
  utc = get_int_var_by_name (lexic, "utc", 0);

  success = true;
  if (utc)
    {
      if (gmtime_r (&tictac, &ptm) == NULL)
        {
          success = false;
        }
    }
  else
    {
      if (localtime_r (&tictac, &ptm) == NULL)
        {
          success = false;
        }
    }

  if (!success)
    {
      nasl_perror (lexic, "localtime(%d,utc=%d): %s\n", tictac, utc,
                   strerror (errno));
      return NULL;
    }

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;

  v.v.v_int = ptm.tm_sec;
  add_var_to_array (a, "sec", &v); /* seconds */
  v.v.v_int = ptm.tm_min;
  add_var_to_array (a, "min", &v); /* minutes */
  v.v.v_int = ptm.tm_hour;
  add_var_to_array (a, "hour", &v); /* hours */
  v.v.v_int = ptm.tm_mday;
  add_var_to_array (a, "mday", &v); /* day of the month */
  v.v.v_int = ptm.tm_mon + 1;
  add_var_to_array (a, "mon", &v); /* month */
  v.v.v_int = ptm.tm_year + 1900;
  add_var_to_array (a, "year", &v); /* year */
  v.v.v_int = ptm.tm_wday;
  add_var_to_array (a, "wday", &v); /* day of the week */
  v.v.v_int = ptm.tm_yday + 1;
  add_var_to_array (a, "yday", &v); /* day in the year */
  v.v.v_int = ptm.tm_isdst;
  add_var_to_array (a, "isdst", &v); /* daylight saving time */

  return retc;
}

tree_cell *
nasl_mktime (lex_ctxt *lexic)
{
  struct tm tm;
  tree_cell *retc;
  time_t tictac;

  tm.tm_sec = get_int_var_by_name (lexic, "sec", 0);   /* seconds */
  tm.tm_min = get_int_var_by_name (lexic, "min", 0);   /* minutes */
  tm.tm_hour = get_int_var_by_name (lexic, "hour", 0); /* hours */
  tm.tm_mday = get_int_var_by_name (lexic, "mday", 0); /* day of the month */
  tm.tm_mon = get_int_var_by_name (lexic, "mon", 1);   /* month */
  tm.tm_mon -= 1;
  tm.tm_year = get_int_var_by_name (lexic, "year", 0); /* year */
  if (tm.tm_year >= 1900)
    tm.tm_year -= 1900;
  tm.tm_isdst =
    get_int_var_by_name (lexic, "isdst", -1); /* daylight saving time */
  errno = 0;
  tictac = mktime (&tm);
  if (tictac == (time_t) (-1))
    {
      nasl_perror (lexic,
                   "mktime(sec=%02d min=%02d hour=%02d mday=%02d mon=%02d "
                   "year=%04d isdst=%d): %s\n",
                   tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon + 1,
                   tm.tm_year + 1900, tm.tm_isdst,
                   errno ? strerror (errno) : "invalid value?");
      return NULL;
    }
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = tictac;
  return retc;
}

tree_cell *
nasl_open_sock_kdc (lex_ctxt *lexic)
{
  tree_cell *retc;
  int ret, type, forced_type = KB_TYPE_INT;
  int timeout = 30, tcp = 0;
  unsigned short port = 88, *port_aux = NULL;
  char *hostname = NULL, *tcp_str; /* Domain name for windows */
  struct script_infos *script_infos;

  script_infos = lexic->script_infos;

  hostname = plug_get_key (script_infos, "Secret/kdc_hostname", &type, NULL, 0);
  if (!hostname || type != KB_TYPE_STR)
    return NULL;

  port_aux = (unsigned short *) plug_get_key (script_infos, "Secret/kdc_port",
                                              &forced_type, NULL, 0);
  if (port_aux)
    {
      port = *port_aux;
      g_free (port_aux);
    }
  if (port <= 0 || forced_type != KB_TYPE_INT)
    return NULL;

  tcp_str = plug_get_key (script_infos, "Secret/kdc_use_tcp", &type, NULL, 0);
  tcp = GPOINTER_TO_SIZE (tcp_str);
  g_free (tcp_str);
  if (tcp < 0 || type != KB_TYPE_INT)
    tcp = 0;

  if (tcp == 0)
    ret = open_sock_opt_hn (hostname, port, SOCK_DGRAM, IPPROTO_UDP, timeout);
  else
    ret = open_sock_opt_hn (hostname, port, SOCK_STREAM, IPPROTO_TCP, timeout);
  g_free (hostname);

  if (ret < 0)
    return NULL;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

tree_cell *
nasl_gunzip (lex_ctxt *lexic)
{
  tree_cell *retc;
  void *data, *uncompressed;
  unsigned long datalen, uncomplen;

  data = get_str_var_by_name (lexic, "data");
  if (data == NULL)
    return NULL;
  datalen = get_var_size_by_name (lexic, "data");
  if (datalen <= 0)
    return NULL;

  uncompressed = gvm_uncompress (data, datalen, &uncomplen);
  if (uncompressed == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = uncomplen;
  retc->x.str_val = uncompressed;

  return retc;
}

tree_cell *
nasl_gzip (lex_ctxt *lexic)
{
  tree_cell *retc;
  void *data, *compressed, *headerformat;
  unsigned long datalen, complen;

  data = get_str_var_by_name (lexic, "data");
  if (data == NULL)
    return NULL;
  datalen = get_var_size_by_name (lexic, "data");
  if (datalen <= 0)
    return NULL;

  headerformat = get_str_var_by_name (lexic, "headformat");
  if (!g_strcmp0 (headerformat, "gzip"))
    {
      compressed = gvm_compress_gzipheader (data, datalen, &complen);
      if (compressed == NULL)
        return NULL;
    }
  else
    {
      compressed = gvm_compress (data, datalen, &complen);
      if (compressed == NULL)
        return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = complen;
  retc->x.str_val = compressed;

  return retc;
}

tree_cell *
nasl_dec2str (lex_ctxt *lexic)
{
  /*converts integer to 4 byte buffer */
  (void) lexic;
  int num = get_int_var_by_name (lexic, "num", -1);
  if (num == -1)
    {
      nasl_perror (lexic, "Syntax : dec2str(num:<n>)\n");
      return NULL;
    }
  char *ret = g_malloc0 (sizeof (num));
  SIVAL (ret, 0, num);
  tree_cell *retc;
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = sizeof (num);
  retc->x.str_val = ret;
  return retc;
}

/**
 * This function returns 1 on little-endian systems, 0 otherwise
 */
tree_cell *
nasl_get_byte_order (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc;
  short w = 0x0001;
  char *p = (char *) &w;
  int val;

  val = (*p == 1);

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = val;
  return retc;
}
