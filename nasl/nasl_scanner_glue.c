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

/**
 * @file
 * This file contains all the functions that make the "glue" between
 * as NASL script and openvassd.
 * (script_*(), *kb*(), scanner_*())
 */

#include <ctype.h>              /* for isdigit */
#include <errno.h>              /* for errno */
#include <fcntl.h>              /* for open */
#include <stdlib.h>             /* for atoi */
#include <string.h>             /* for strcmp */
#include <sys/stat.h>           /* for stat */
#include <unistd.h>             /* for close */

#include <glib.h>

#include <gvm/base/logging.h>
#include <gvm/base/prefs.h>     /* for prefs_get */
#include <gvm/util/kb.h>        /* for KB_TYPE_INT */

#include "../misc/plugutils.h"          /* for plug_set_id */
#include "../misc/network.h"            /* for getpts */
#include "../misc/vendorversion.h"      /* for vendor_version_get */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"

#include "nasl_debug.h"
#include "nasl_scanner_glue.h"


#ifndef NASL_DEBUG
#define NASL_DEBUG 0
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/*------------------- Private utilities ---------------------------------*/

static int
isalldigit (char *str, int len)
{
  int i;
  char buf[1024];
  for (i = 0; i < len; i++)
    {
      if (!isdigit (str[i]))
        return 0;
    }

  snprintf (buf, sizeof (buf), "%d", atoi (str));
  if (strcmp (buf, str) != 0)
    return 0;
  else
    return 1;
}



/*-------------------[ script_*() functions ]----------------------------*/

 /*
  * These functions are used when the script registers itself to openvas
  * scanner.
  */

tree_cell *
script_timeout (lex_ctxt * lexic)
{
  nvti_t *nvti = lexic->script_infos->nvti;
  int to = get_int_var_by_num (lexic, 0, -65535);

  if (to == -65535)
    return FAKE_CELL;

  nvti_set_timeout (nvti, to ? to : -1);
  return FAKE_CELL;
}


tree_cell *
script_oid (lex_ctxt * lexic)
{
  nvti_set_oid (lexic->script_infos->nvti, get_str_var_by_num (lexic, 0));
  return FAKE_CELL;
}

/*
 * TODO: support multiple CVE entries
 */
tree_cell *
script_cve_id (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *cve = get_str_var_by_num (lexic, 0);
  int i;

  for (i = 0; cve != NULL; i++)
    {
      nvti_add_cve (script_infos->nvti, cve);
      cve = get_str_var_by_num (lexic, i + 1);
    }

  return FAKE_CELL;
}

/*
 * TODO: support multiple bugtraq entries
 */
tree_cell *
script_bugtraq_id (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *bid = get_str_var_by_num (lexic, 0);
  int i;

  for (i = 0; bid != NULL; i++)
    {
      nvti_add_bid (script_infos->nvti, bid);
      bid = get_str_var_by_num (lexic, i + 1);
    }

  return FAKE_CELL;
}


tree_cell *
script_xref (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *name = get_str_var_by_name (lexic, "name");
  char *value = get_str_var_by_name (lexic, "value");


  if (value == NULL || name == NULL)
    {
      nasl_perror (lexic,
                   "script_xref() syntax error - should be"
                   " script_xref(name:<name>, value:<value>)\n");
      if (name == NULL)
        {
          nasl_perror (lexic, "  <name> is empty\n");
        }
      else
        {
          nasl_perror (lexic, "  <name> is %s\n", name);
        }
      if (value == NULL)
        {
          nasl_perror (lexic, "  <value> is empty)\n");
        }
      else
        {
          nasl_perror (lexic, "  <value> is %s\n)", value);
        }
      return FAKE_CELL;
    }

  plug_set_xref (script_infos, name, value);

  return FAKE_CELL;
}

tree_cell *
script_tag (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *name = get_str_var_by_name (lexic, "name");
  char *value = get_str_var_by_name (lexic, "value");

  if (value == NULL || name == NULL)
    {
      nasl_perror (lexic, "script_tag() syntax error - should be"
                          " script_tag(name:<name>, value:<value>)\n");
      if (name == NULL)
        {
          nasl_perror (lexic, "  <name> is empty\n");
        }
      else
        {
          nasl_perror (lexic, "  <name> is %s\n", name);
        }
      if (value == NULL)
        {
          nasl_perror (lexic, "  <value> is empty)\n");
        }
      else
        {
          nasl_perror (lexic, "  <value> is %s\n)", value);
        }
      return FAKE_CELL;
    }

  if (strchr (value, '|'))
    {
      nasl_perror (lexic, "%s tag contains | separator", name);
      return FAKE_CELL;
    }
  plug_set_tag (script_infos, name, value);

  return FAKE_CELL;
}


tree_cell *
script_name (lex_ctxt * lexic)
{
  nvti_set_name (lexic->script_infos->nvti, get_str_var_by_num (lexic, 0));
  return FAKE_CELL;
}


tree_cell *
script_version (lex_ctxt * lexic)
{
  (void) lexic;
  return FAKE_CELL;
}

tree_cell *
script_copyright (lex_ctxt * lexic)
{
  nvti_set_copyright (lexic->script_infos->nvti, get_str_var_by_num (lexic, 0));
  return FAKE_CELL;
}

tree_cell *
script_category (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;

  int category = get_int_var_by_num (lexic, 0, -1);

  if (category < 0)
    {
      nasl_perror (lexic, "Argument error in function script_category()\n");
      nasl_perror (lexic, "Function usage is : script_category(<category>)\n");
      return FAKE_CELL;
    }
  nvti_set_category (script_infos->nvti, category);
  return FAKE_CELL;
}

tree_cell *
script_family (lex_ctxt * lexic)
{
  nvti_set_family (lexic->script_infos->nvti, get_str_var_by_num (lexic, 0));
  return FAKE_CELL;
}

tree_cell *
script_dependencies (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *dep = get_str_var_by_num (lexic, 0);
  int i;

  if (dep == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_dependencies()\n");
      nasl_perror (lexic, "Function usage is : script_dependencies(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of another script\n");

      return FAKE_CELL;
    }

  for (i = 0; dep != NULL; i++)
    {
      dep = get_str_var_by_num (lexic, i);
      if (dep != NULL)
        plug_set_dep (script_infos, dep);
    }

  return FAKE_CELL;
}


tree_cell *
script_require_keys (lex_ctxt * lexic)
{
  char *keys = get_str_var_by_num (lexic, 0);
  int i;

  if (keys == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_require_keys()\n");
      nasl_perror (lexic, "Function usage is : script_require_keys(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of a key\n");
      return FAKE_CELL;
    }

  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);
      nvti_add_required_keys (lexic->script_infos->nvti, keys);
    }

  return FAKE_CELL;
}

tree_cell *
script_mandatory_keys (lex_ctxt * lexic)
{
  char *keys = get_str_var_by_num (lexic, 0);
  char **splits = NULL, *re = get_str_var_by_name (lexic, "re");
  int i;

  if (keys == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in function script_mandatory_keys()\n");
      nasl_perror (lexic,
                   "Function usage is : script_mandatory_keys(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of a key\n");
      return FAKE_CELL;
    }

  if (re)
    {
      splits = g_strsplit (re, "=", 0);

      if (!splits[0] || !splits[1] || !*splits[1] || splits[2])
        {
          nasl_perror (lexic, "Erroneous re argument");
          return FAKE_CELL;
        }
    }
  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);

      if (splits && keys && !strcmp (keys, splits[0]))
        {
          nvti_add_mandatory_keys (lexic->script_infos->nvti, re);
          re = NULL;
        }
      else
        nvti_add_mandatory_keys (lexic->script_infos->nvti, keys);
    }
  if (re)
    nvti_add_mandatory_keys (lexic->script_infos->nvti, re);

  g_strfreev (splits);
  return FAKE_CELL;
}

tree_cell *
script_exclude_keys (lex_ctxt * lexic)
{
  char *keys = get_str_var_by_num (lexic, 0);
  int i;

  if (keys == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_exclude_keys()\n");
      nasl_perror (lexic, "Function usage is : script_exclude_keys(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of a key\n");
      return FAKE_CELL;
    }

  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);
      nvti_add_excluded_keys (lexic->script_infos->nvti, keys);
    }

  return FAKE_CELL;
}


tree_cell *
script_require_ports (lex_ctxt * lexic)
{
  char *port;
  int i;

  for (i = 0;; i++)
    {
      port = get_str_var_by_num (lexic, i);
      if (port != NULL)
        nvti_add_required_ports (lexic->script_infos->nvti, port);
      else
        break;
    }

  return FAKE_CELL;
}


tree_cell *
script_require_udp_ports (lex_ctxt * lexic)
{
  int i;
  char *port;

  for (i = 0;; i++)
    {
      port = get_str_var_by_num (lexic, i);
      if (port != NULL)
        nvti_add_required_udp_ports (lexic->script_infos->nvti, port);
      else
        break;
    }

  return FAKE_CELL;
}

tree_cell *
script_add_preference (lex_ctxt * lexic)
{
  char *name = get_str_local_var_by_name (lexic, "name");
  char *type = get_str_local_var_by_name (lexic, "type");
  char *value = get_str_local_var_by_name (lexic, "value");
  struct script_infos *script_infos = lexic->script_infos;

  if (name == NULL || type == NULL || value == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in the call to script_add_preference()\n");
    }
  else
    add_plugin_preference (script_infos, name, type, value);

  return FAKE_CELL;
}

tree_cell *
script_get_preference (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  char *value;

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in the function script_get_preference()\n");
      nasl_perror (lexic,
                   "Function usage is : pref = script_get_preference(<name>)\n");
      return FAKE_CELL;
    }

  value = get_plugin_preference (lexic->oid, pref);
  if (value != NULL)
    {
      retc = alloc_tree_cell ();
      if (isalldigit (value, strlen (value)))
        {
          retc->type = CONST_INT;
          retc->x.i_val = atoi (value);
        }
      else
        {
          retc->type = CONST_DATA;
          retc->size = strlen (value);
          retc->x.str_val = g_strdup (value);
        }
      g_free (value);
      return retc;
    }
  else
    return FAKE_CELL;
}

tree_cell *
script_get_preference_file_content (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  char *value;
  char *content;
  int contentsize = 0;

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in the function script_get_preference()\n");
      nasl_perror (lexic,
                   "Function usage is : pref = script_get_preference_file_content(<name>)\n");
      return NULL;
    }

  value = get_plugin_preference (lexic->oid, pref);
  if (value == NULL)
    return NULL;

  content = get_plugin_preference_file_content (script_infos, value);
  if (content == NULL)
    return FAKE_CELL;
  contentsize = get_plugin_preference_file_size (script_infos, value);
  if (contentsize <= 0)
    {
      nasl_perror (lexic, "script_get_preference_file_content: could not get "
                          " size of file from preference %s\n", pref);
      return NULL;
    }

  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->size = contentsize;
  retc->x.str_val = content;

  return retc;
}


tree_cell *
script_get_preference_file_location (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  const char *value, *local;
  int len;

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_location: no preference name!\n");
      return NULL;
    }

  value = get_plugin_preference (lexic->oid, pref);
  if (value == NULL)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_location: could not get preference %s\n",
                   pref);
      return NULL;
    }
  local = get_plugin_preference_fname (script_infos, value);
  if (local == NULL)
    return NULL;

  len = strlen (local);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = g_malloc0 (len + 1);
  memcpy (retc->x.str_val, local, len + 1);

  return retc;
}

/* Are safe checks enabled ? */
tree_cell *
safe_checks (lex_ctxt * lexic)
{
  (void) lexic;
  tree_cell *retc = alloc_tree_cell ();

  retc->type = CONST_INT;
  retc->x.i_val = prefs_get_bool ("safe_checks");

  return retc;
}

tree_cell *
scan_phase (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct scan_globals *globals = script_infos->globals;
  char *value;
  tree_cell *retc = alloc_tree_cell ();

  retc->type = CONST_INT;
  value = globals->network_scan_status;
  if (value)
    {
      if (strcmp (value, "busy") == 0)
        retc->x.i_val = 1;
      else
        retc->x.i_val = 2;
    }
  else
    retc->x.i_val = 0;

  return retc;
}

tree_cell *
network_targets (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct scan_globals *globals = script_infos->globals;
  char *value;
  tree_cell *retc;

  value = globals->network_targets;
  retc = alloc_typed_cell (CONST_DATA);
  if (value)
    {
      retc->x.str_val = strdup (value);
      retc->size = strlen (value);
    }
  else
    return NULL;

  return retc;
}

/**
 * @brief Return the OID of the current script.
 *
 * @param[in] lexic     NASL lexer.
 *
 * @return lex cell containing the OID as a string.
 */
tree_cell *
get_script_oid (lex_ctxt * lexic)
{
  const char *oid = lexic->oid;
  tree_cell *retc = NULL;

  if (oid)
    {
      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = g_strdup (oid);
      retc->size = strlen (oid);
    }

  return retc;
}

/*--------------------[ KB ]---------------------------------------*/

tree_cell *
get_kb_list (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  kb_t kb = plug_get_kb (script_infos);
  char *kb_mask = get_str_var_by_num (lexic, 0);
  tree_cell *retc;
  int num_elems = 0;
  nasl_array *a;
  struct kb_item *res, *top;

  if (kb_mask == NULL)
    {
      nasl_perror (lexic, "get_kb_list() usage : get_kb_list(<NameOfItem>)\n");
      return NULL;
    }

  if (kb == NULL)
    return NULL;

  retc = alloc_tree_cell ();
  retc->type = DYN_ARRAY;
  retc->x.ref_val = a = g_malloc0 (sizeof (nasl_array));

  if (strchr (kb_mask, '*'))
    top = res = kb_item_get_pattern (kb, kb_mask);
  else
    top = res = kb_item_get_all (kb, kb_mask);

  while (res != NULL)
    {
      anon_nasl_var v;
      bzero (&v, sizeof (v));

      if (res->type == KB_TYPE_INT)
        {
          v.var_type = VAR2_INT;
          v.v.v_int = res->v_int;
          add_var_to_array (a, res->name, &v);
          num_elems++;
        }
      else if (res->type == KB_TYPE_STR)
        {
          v.var_type = VAR2_DATA;
          v.v.v_str.s_val = (unsigned char *) res->v_str;
          v.v.v_str.s_siz = strlen (res->v_str);
          add_var_to_array (a, res->name, &v);
          num_elems++;
        }
      res = res->next;
    }

  kb_item_free (top);

  if (num_elems == 0)
    {
      deref_cell (retc);
      return FAKE_CELL;
    }
  return retc;
}

tree_cell *
get_kb_item (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;

  char *kb_entry = get_str_var_by_num (lexic, 0);
  char *val;
  tree_cell *retc;
  int type, single = get_int_var_by_num (lexic, 1, 0);
  size_t len;

  if (kb_entry == NULL)
    return NULL;

  val = plug_get_key (script_infos, kb_entry, &type, &len, !!single);


  if (val == NULL && type == -1)
    return NULL;


  retc = alloc_tree_cell ();
  if (type == KB_TYPE_INT)
    {
      retc->type = CONST_INT;
      retc->x.i_val = GPOINTER_TO_SIZE (val);
      g_free (val);
      return retc;
    }
  else
    {
      retc->type = CONST_DATA;
      if (val != NULL)
        {
          retc->size = len;
          retc->x.str_val = val;
        }
      else
        {
          retc->size = 0;
          retc->x.str_val = NULL;
        }
    }

  return retc;
}

tree_cell *
replace_kb_item (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *name = get_str_local_var_by_name (lexic, "name");
  int type = get_local_var_type_by_name (lexic, "value");

  if (name == NULL)
    {
      nasl_perror (lexic, "Syntax error with replace_kb_item() [null name]\n",
                   name);
      return FAKE_CELL;
    }

  if (type == VAR2_INT)
    {
      int value = get_int_local_var_by_name (lexic, "value", -1);
      if (value != -1)
        plug_replace_key (script_infos, name, ARG_INT,
                          GSIZE_TO_POINTER (value));
      else
        nasl_perror (lexic,
                     "Syntax error with replace_kb_item(%s) [value=-1]\n",
                     name);
    }
  else
    {
      char *value = get_str_local_var_by_name (lexic, "value");
      int len = get_local_var_size_by_name (lexic, "value");

      if (value == NULL)
        {
          nasl_perror (lexic,
                       "Syntax error with replace_kb_item(%s) [null value]\n",
                       name);
          return FAKE_CELL;
        }
      plug_replace_key_len (script_infos, name, ARG_STRING, value, len);
    }

  return FAKE_CELL;
}

tree_cell *
set_kb_item (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *name = get_str_local_var_by_name (lexic, "name");
  int type = get_local_var_type_by_name (lexic, "value");

  if (name == NULL)
    {
      nasl_perror (lexic, "Syntax error with set_kb_item() [null name]\n",
                   name);
      return FAKE_CELL;
    }

  if (type == VAR2_INT)
    {
      int value = get_int_local_var_by_name (lexic, "value", -1);
      if (value != -1)
        plug_set_key (script_infos, name, ARG_INT, GSIZE_TO_POINTER (value));
      else
        nasl_perror (lexic,
                     "Syntax error with set_kb_item() [value=-1 for name '%s']\n",
                     name);
    }
  else
    {
      char *value = get_str_local_var_by_name (lexic, "value");
      int len = get_local_var_size_by_name (lexic, "value");
      if (value == NULL)
        {
          nasl_perror (lexic,
                       "Syntax error with set_kb_item() [null value for name '%s']\n",
                       name);
          return FAKE_CELL;
        }
      plug_set_key_len (script_infos, name, ARG_STRING, value, len);
    }

  return FAKE_CELL;
}

/*------------------------[ Reporting a problem ]---------------------------*/


/**
 * Function is used when the script wants to report a problem back to openvassd.
 */
typedef void (*proto_post_something_t) (const char *, struct script_infos *, int,
                                        const char *, const char *);
/**
 * Function is used when the script wants to report a problem back to openvassd.
 */
typedef void (*post_something_t) (const char *, struct script_infos *, int, const char *);


static tree_cell *
security_something (lex_ctxt * lexic, proto_post_something_t proto_post_func,
                    post_something_t post_func)
{
  struct script_infos *script_infos = lexic->script_infos;

  char *proto = get_str_local_var_by_name (lexic, "protocol");
  char *data = get_str_local_var_by_name (lexic, "data");
  int port = get_int_local_var_by_name (lexic, "port", -1);
  char *dup = NULL;

  if (data != NULL)
    {
      int len = get_local_var_size_by_name (lexic, "data");
      int i;

      dup = g_memdup (data, len + 1);
      for (i = 0; i < len; i++)
        if (dup[i] == 0)
          dup[i] = ' ';
    }

  if (script_infos->standalone)
    {
      if (data != NULL)
        fprintf (stdout, "%s\n", dup);
      else
        fprintf (stdout, "Success\n");
    }

  if (proto == NULL)
    proto = get_str_local_var_by_name (lexic, "proto");

  if (port < 0)
    port = get_int_var_by_num (lexic, 0, -1);

  if (dup != NULL)
    {
      if (proto == NULL)
        post_func (lexic->oid, script_infos, port, dup);
      else
        proto_post_func (lexic->oid, script_infos, port, proto, dup);

      g_free (dup);
      return FAKE_CELL;
    }

  if (proto == NULL)
    post_func (lexic->oid, script_infos, port, NULL);
  else
    proto_post_func (lexic->oid, script_infos, port, proto, NULL);

  return FAKE_CELL;
}

/**
 * @brief Send a security message to the client.
 *
 * @param[in]  lexic  NASL lexer.
 *
 * @return FAKE_CELL.
 */
tree_cell *
security_message (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_alarm, post_alarm);
}

tree_cell *
log_message (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_log, post_log);
}

tree_cell *
error_message (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_error, post_error);
}

tree_cell *
nasl_get_preference (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *name;
  const char *value;

  name = get_str_var_by_num (lexic, 0);
  if (name == NULL)
    {
      nasl_perror (lexic, "get_preference: no name\n");
      return NULL;
    }
  value = prefs_get (name);
  if (value == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (value);
  retc->size = strlen (value);
  return retc;
}

tree_cell *
nasl_vendor_version (lex_ctxt * lexic)
{
  tree_cell *retc;
  gchar *version = g_strdup (vendor_version_get ());
  (void) lexic;
  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (version);
  retc->size = strlen (version);
  g_free (version);

  return retc;
}

/*-------------------------[ Reporting an open port ]---------------------*/

/**
 * If the plugin is a port scanner, it needs to report the list of open
 * ports back to openvas scanner, and it also needs to know which ports are
 * to be scanned.
 */
tree_cell *
nasl_scanner_get_port (lex_ctxt * lexic)
{
  tree_cell *retc;
  int idx = get_int_var_by_num (lexic, 0, -1);
  const char *prange = prefs_get ("port_range");
  static int num = 0;
  static u_short *ports = NULL;

  if (prange == NULL)
    return NULL;

  if (idx < 0)
    {
      nasl_perror (lexic, "Argument error in scanner_get_port()\n");
      nasl_perror (lexic, "Correct usage is : num = scanner_get_port(<num>)\n");
      nasl_perror (lexic,
                   "Where <num> should be 0 the first time you call it\n");
      return NULL;
    }

  if (ports == NULL)
    {
      ports = (u_short *) getpts ((char *)prange, &num);
      if (ports == NULL)
        {
          return NULL;
        }
    }

  if (idx >= num)
    {
      return NULL;
    }

  retc = alloc_tree_cell ();
  retc->type = CONST_INT;
  retc->x.i_val = ports[idx];
  return retc;
}


tree_cell *
nasl_scanner_add_port (lex_ctxt * lexic)
{
  struct script_infos *script_infos = lexic->script_infos;

  int port = get_int_local_var_by_name (lexic, "port", -1);
  char *proto = get_str_local_var_by_name (lexic, "proto");

  if (port >= 0)
    {
      scanner_add_port (script_infos, port, proto ? proto : "tcp");
    }

  return FAKE_CELL;
}

tree_cell *
nasl_scanner_status (lex_ctxt * lexic)
{
  /* Kept for backward compatibility. */
  (void) lexic;
  return FAKE_CELL;
}
