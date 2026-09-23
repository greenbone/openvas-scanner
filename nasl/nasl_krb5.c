// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#include "nasl_krb5.h"

#include "../misc/file_utils.h"
#include "../misc/openvas-krb5.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <gvm/base/networking.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NASL_PRINT_KRB_ERROR(lexic, credential, result)                   \
  do                                                                      \
    {                                                                     \
      char *error_str = okrb5_error_code_to_string (result);              \
      nasl_perror (                                                       \
        lexic, "%s[config_path: '%s' realm: '%s' user: '%s'] => %s (%d)", \
        __func__, credential.config_path.data, credential.realm.data,     \
        credential.user.user.data, error_str, result);                    \
      free (error_str);                                                   \
    }                                                                     \
  while (0)

// Is used for krb5_is_success, krb5_is_failure which allows the script author
// to verify if the last called krb5 function failed or not. This is strictly
// speaking a safety net for incorrect usage as most krb5 functions return
// the error code.
static OKrb5ErrorCode last_okrb5_result;

// cached_gss_context is used on cases that require an already existing session.
// NASL does currently not have the concept of a pointer nor struct so we need
// to store it as a global variable.
//
// We use one context per run, this means that per run (target + oid) there is
// only on credential allowed making it safe to be cached in that fashion.
static struct OKrb5GSSContext *cached_gss_context = NULL;

// Is used for `krb5_gss_update_context_out` and is essential a
// cache for the data from `krb5_gss_update_context`.
static struct OKrb5Slice *to_application = NULL;

// Is used for `krb5_gss_update_context_needs_more` which indicates to the
// script author that `krb5_gss_update_context` is not satisfied yet.
static bool gss_update_context_more = false;

// Returns the named script parameter as a slice, falling back to the given
// environment variable. A parameter value is propagated into the environment so
// that the krb5 library picks it up.
static struct OKrb5Slice
okrb5_slice_from_lex_or_env (lex_ctxt *lexic, const char *name,
                             const char *env_name)
{
  char *value = get_str_var_by_name (lexic, name);

  if (value == NULL || *value == '\0')
    {
      value = getenv (env_name);
    }
  else
    {
      setenv (env_name, value, 1);
    }

  return okrb5_slice_from_str (value);
}

// Like okrb5_slice_from_lex_or_env but warns when neither source provides a
// value.
static struct OKrb5Slice
okrb5_required_slice_from_lex_or_env (lex_ctxt *lexic, const char *name,
                                      const char *env_name)
{
  struct OKrb5Slice slice = okrb5_slice_from_lex_or_env (lexic, name, env_name);

  if (slice.len == 0)
    {
      nasl_perror (lexic, "Expected %s or env variable %s", name, env_name);
    }

  return slice;
}

// Builds the path of a krb5 file of the current target inside the managed
// directory of the scan.
//
// The name is built from hashes, so that it needs no sanitizing and stays
// within the file name limits. Identical names imply identical content, which
// allows concurrent scripts to publish the file without coordination.
static gchar *
okrb5_target_file_path (const char *prefix, const char *ip,
                        const OKrb5Credential *credential)
{
  const char *dir = file_utils_get_dir ();
  gchar *ip_hash;
  gchar *target;
  gchar *target_hash;
  gchar *name;
  gchar *path;

  if (dir == NULL)
    return NULL;

  target = g_strdup_printf (
    "%.*s|%.*s|%.*s", (int) credential->target.host_name.len,
    (char *) credential->target.host_name.data, (int) credential->realm.len,
    (char *) credential->realm.data, (int) credential->kdc.len,
    (char *) credential->kdc.data);

  ip_hash = file_utils_hash (ip);
  target_hash = file_utils_hash (target);
  name = g_strdup_printf ("%s_%s_%s", prefix, ip_hash, target_hash);
  path = g_build_filename (dir, name, NULL);

  g_free (target);
  g_free (ip_hash);
  g_free (target_hash);
  g_free (name);

  return path;
}

// Deletes the krb5 files of the given target, to be called once the target is
// finished. The files of all scripts are removed, not only those of the
// calling process.
void
nasl_okrb5_clean_files (const char *ip)
{
  gchar *ip_hash = file_utils_hash (ip);
  gchar *pattern;

  if (ip_hash == NULL)
    return;

  pattern = g_strdup_printf ("krb5*_%s_*", ip_hash);
  file_utils_delete_matching (pattern);

  g_free (pattern);
  g_free (ip_hash);
}

static OKrb5ErrorCode
build_krb5_credential (lex_ctxt *lexic, OKrb5Credential *credential)
{
  OKrb5ErrorCode code;
  char *kdc = NULL;
  char *ip_str;
  gchar *path;

  memset (credential, 0, sizeof (OKrb5Credential));

  credential->realm =
    okrb5_required_slice_from_lex_or_env (lexic, "realm", "KRB5_REALM");
  credential->kdc =
    okrb5_required_slice_from_lex_or_env (lexic, "kdc", "KRB5_KDC");
  credential->user.user =
    okrb5_required_slice_from_lex_or_env (lexic, "user", "KRB5_USER");
  credential->user.password =
    okrb5_required_slice_from_lex_or_env (lexic, "password", "KRB5_PASSWORD");
  credential->target.host_name =
    okrb5_required_slice_from_lex_or_env (lexic, "host", "KRB5_TARGET_HOST");

  ip_str = addr6_as_str (lexic->script_infos->ip);

  // The credential cache is not created here, the krb5 library initializes and
  // locks it itself.
  if (getenv ("KRB5CCNAME") == NULL
      && get_str_var_by_name (lexic, "ccache_path") == NULL)
    {
      path = okrb5_target_file_path ("krb5cc", ip_str, credential);
      if (path == NULL)
        {
          g_free (ip_str);
          return O_KRB5_CONF_NOT_CREATED;
        }
      setenv ("KRB5CCNAME", path, 1);
      g_free (path);
    }

  credential->config_path =
    okrb5_slice_from_lex_or_env (lexic, "config_path", "KRB5_CONFIG");
  if (credential->config_path.len == 0)
    {
      path = okrb5_target_file_path ("krb5conf", ip_str, credential);
      if (path == NULL)
        {
          g_free (ip_str);
          return O_KRB5_CONF_NOT_CREATED;
        }
      setenv ("KRB5_CONFIG", path, 1);
      g_free (path);
      // The environment owns the only copy which outlives this function.
      okrb5_set_slice_from_str (credential->config_path,
                                getenv ("KRB5_CONFIG"));
    }

  g_free (ip_str);

  if ((code = o_krb5_find_kdc (credential, &kdc)))
    {
      if (code != O_KRB5_REALM_NOT_FOUND && code != O_KRB5_CONF_NOT_FOUND)
        {
          NASL_PRINT_KRB_ERROR (lexic, (*credential), code);
          return code;
        }
      if ((code = o_krb5_add_realm (credential, credential->kdc.data)))
        {
          NASL_PRINT_KRB_ERROR (lexic, (*credential), code);
          return code;
        }
    }
  else
    {
      free (kdc);
    }

  if (credential->target.service.len == 0)
    {
      okrb5_set_slice_from_str (credential->target.service, "cifs");
    }

  memset (&credential->target.domain, 0, sizeof (struct OKrb5Slice));

  return O_KRB5_SUCCESS;
}

/**
 * @brief Returns the defined KDC of a given Realm
 *
 * This function returns the KDC of a given Realm. The Realm is defined in the
 * krb5.conf file. If there is no KDC for the given Realm, the function returns
 * NULL within the tree_cell to the script.
 *
 * The nasl function has two optional parameter:
 * - realm: The realm for which the KDC should be returned. If the realm is not
 * defined, then the env parameter `KRB5_REALM` is used.
 * - config_path: The path to the krb5.conf file. If the path is not defined,
 * then the env parameter `KRB5_CONFIG` is used.
 *
 * This function should only be used for debug purposes.
 *
 * @param[in] lexic     NASL lexer.
 *
 * @return lex cell containing the KDC as a string.
 */
tree_cell *
nasl_okrb5_find_kdc (lex_ctxt *lexic)
{
  tree_cell *retc;
  char *kdc = NULL;
  OKrb5Credential credential;

  if ((last_okrb5_result = build_krb5_credential (lexic, &credential)))
    return FAKE_CELL;

  if ((last_okrb5_result = o_krb5_find_kdc (&credential, &kdc)))
    {
      NASL_PRINT_KRB_ERROR (lexic, credential, last_okrb5_result);
      return FAKE_CELL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = kdc;
  retc->size = strlen (kdc);
  return retc;
}

tree_cell *
nasl_okrb5_add_realm (lex_ctxt *lexic)
{
  tree_cell *retc;
  OKrb5Credential credential = {0};
  char *kdc = get_str_var_by_name (lexic, "kdc");
  if (kdc == NULL)
    {
      kdc = getenv ("KRB5_KDC");
      if (kdc == NULL)
        {
          last_okrb5_result = O_KRB5_EXPECTED_NOT_NULL;
          NASL_PRINT_KRB_ERROR (lexic, credential, last_okrb5_result);
          goto exit;
        }
    }

  if ((last_okrb5_result = build_krb5_credential (lexic, &credential)))
    goto exit;

  if ((last_okrb5_result = o_krb5_add_realm (&credential, kdc)))
    {
      NASL_PRINT_KRB_ERROR (lexic, credential, last_okrb5_result);
    }
exit:
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = last_okrb5_result;
  return retc;
}

/**
 * @brief Returns 1 if the krb5 function was successful 0 otherwise
 *
 * The nasl function has one optional parameter:
 * - retval: the return value of the krb5 function. If the value is not defined,
 * the return value of the last krb5 function is used.
 *
 *
 * @param[in] lexic     NASL lexer.
 *
 * @return lex cell containing a number indicating success.
 */
tree_cell *
nasl_okrb5_is_success (lex_ctxt *lexic)
{
  OKrb5ErrorCode result = get_int_var_by_num (lexic, 0, last_okrb5_result);
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result == O_KRB5_SUCCESS;
  return retc;
}

/**
 * @brief Returns 0 if the krb5 function was successful and 1 if it failed
 *
 * The nasl function has one optional parameter:
 * - retval: the return value of the krb5 function. If the value is not defined,
 * the return value of the last krb5 function is used.
 *
 *
 * @param[in] lexic     NASL lexer.
 *
 * @return lex cell containing a number indicating success.
 */
tree_cell *
nasl_okrb5_is_failure (lex_ctxt *lexic)
{
  OKrb5ErrorCode result = get_int_var_by_num (lexic, 0, last_okrb5_result);
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result != O_KRB5_SUCCESS;
  return retc;
}

tree_cell *
nasl_okrb5_gss_init (lex_ctxt *lexic)
{
  (void) lexic;
  cached_gss_context = okrb5_gss_init_context ();
  if (cached_gss_context == NULL)
    {
      last_okrb5_result = O_KRB5_EXPECTED_NOT_NULL;
    }
  else
    {
      last_okrb5_result = O_KRB5_SUCCESS;
    };
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = last_okrb5_result;
  return retc;
}
tree_cell *
nasl_okrb5_gss_prepare_context (lex_ctxt *lexic)
{
  OKrb5Credential credential;
  OKrb5ErrorCode result = build_krb5_credential (lexic, &credential);

  if (result == O_KRB5_SUCCESS)
    {
      if (cached_gss_context == NULL)
        {
          cached_gss_context = okrb5_gss_init_context ();
        }
      result = o_krb5_gss_prepare_context (&credential, cached_gss_context);
    }
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result;
  last_okrb5_result = result;
  return retc;
}

tree_cell *
nasl_okrb5_gss_update_context (lex_ctxt *lexic)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  tree_cell *retc;
  struct OKrb5Slice from_application;

  if (to_application != NULL)
    {
      free (to_application->data);
      free (to_application);
      to_application = NULL;
    }

  from_application.data = (void *) get_str_var_by_num (lexic, 0);
  from_application.len = get_var_size_by_num (lexic, 0);

  if (cached_gss_context == NULL)
    {
      last_okrb5_result = O_KRB5_EXPECTED_NOT_NULL;
      goto result;
    }
  result =
    o_krb5_gss_update_context (cached_gss_context, &from_application,
                               &to_application, &gss_update_context_more);
result:
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result;
  last_okrb5_result = result;
  return retc;
}

void
nasl_okrb5_clean (void)
{
  if (to_application != NULL)
    {
      free (to_application->data);
      free (to_application);
      to_application = NULL;
    }
  if (cached_gss_context != NULL)
    {
      okrb5_gss_free_context (cached_gss_context);
      cached_gss_context = NULL;
    }
}

tree_cell *
nasl_okrb5_gss_update_context_needs_more (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = gss_update_context_more;
  return retc;
}

static inline tree_cell *
okrb5_slice_to_tree_cell (struct OKrb5Slice *slice)
{
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = slice->data;
  retc->size = slice->len;
  return retc;
}

tree_cell *
nasl_okrb5_gss_update_context_out (lex_ctxt *lexic)
{
  (void) lexic;
  if (to_application == NULL)
    {
      return FAKE_CELL;
    }
  tree_cell *out = okrb5_slice_to_tree_cell (to_application);
  // we need to prevent accidental free it as it is freed when the tree_cell is
  // cleaned up
  to_application = NULL;
  return out;
}

tree_cell *
nasl_okrb5_gss_session_key_context (lex_ctxt *lexic)
{
  (void) lexic;
  struct OKrb5Slice *session_key = NULL;
  if (cached_gss_context == NULL)
    {
      last_okrb5_result = O_KRB5_EXPECTED_NOT_NULL;
      return FAKE_CELL;
    }
  if ((last_okrb5_result =
         o_krb5_gss_session_key_context (cached_gss_context, &session_key))
      != O_KRB5_SUCCESS)
    {
      return FAKE_CELL;
    }
  return okrb5_slice_to_tree_cell (session_key);
}

tree_cell *
nasl_okrb5_error_code_to_string (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = okrb5_error_code_to_string (last_okrb5_result);
  retc->size = strlen (retc->x.str_val);
  return retc;
}
