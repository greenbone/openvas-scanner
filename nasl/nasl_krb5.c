// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#include "nasl_krb5.h"

#include "../misc/openvas-krb5.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <stdio.h>

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

#define SET_SLICE_FROM_LEX_OR_ENV(lexic, slice, name, env_name)            \
  do                                                                       \
    {                                                                      \
      okrb5_set_slice_from_str (slice, get_str_var_by_name (lexic, name)); \
      if (slice.len == 0)                                                  \
        {                                                                  \
          okrb5_set_slice_from_str (slice, getenv (env_name));             \
        }                                                                  \
    }                                                                      \
  while (0)

#define PERROR_SET_SLICE_FROM_LEX_OR_ENV(lexic, slice, name, env_name) \
  do                                                                   \
    {                                                                  \
      SET_SLICE_FROM_LEX_OR_ENV (lexic, slice, name, env_name);        \
      if (slice.len == 0)                                              \
        {                                                              \
          nasl_perror (lexic, "Expected %s or env variable %s", name,  \
                       env_name);                                      \
        }                                                              \
    }                                                                  \
  while (0)


static OKrb5Credential
build_krb5_credential (lex_ctxt *lexic)
{
  OKrb5Credential credential = {0};
  OKrb5ErrorCode code;

  char *kdc = NULL;

  SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.config_path, "config_path",
                             "KRB5_CONFIG");
  if (credential.config_path.len == 0)
    {
      okrb5_set_slice_from_str (credential.config_path, "/etc/krb5.conf");
    }

  PERROR_SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.realm, "realm",
                                    "KRB5_REALM");
  PERROR_SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.kdc, "kdc", "KRB5_KDC");
  PERROR_SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.user.user, "user",
                                    "KRB5_USER");
  PERROR_SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.user.password, "password",
                                    "KRB5_PASSWORD");
  PERROR_SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.target.host_name, "host",
                                    "KRB5_TARGET_HOST");
  // SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.target.service, "service",
  // "KRB5_TARGET_SERVICE");

  if ((code = o_krb5_find_kdc (&credential, &kdc)))
    {
      if (code != O_KRB5_REALM_NOT_FOUND && code != O_KRB5_CONF_NOT_FOUND)
        {
          NASL_PRINT_KRB_ERROR (lexic, credential, code);
        }
      else
        {
          if ((code = o_krb5_add_realm (&credential, credential.kdc.data)))
            {
              NASL_PRINT_KRB_ERROR (lexic, credential, code);
            }
        }
    }
  else
    {
      free (kdc);
    }
  if (credential.target.service.len == 0)
    {
      okrb5_set_slice_from_str (credential.target.service, "cifs");
    }
  SET_SLICE_FROM_LEX_OR_ENV (lexic, credential.kdc, "kdc", "KRB5_KDC");

  memset (&credential.target.domain, 0, sizeof (struct OKrb5Slice));

  return credential;
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

  credential = build_krb5_credential (lexic);

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
  OKrb5Credential credential;
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

  credential = build_krb5_credential (lexic);

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
  (void) lexic;

  OKrb5Credential credential;
  credential = build_krb5_credential (lexic);
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  if (cached_gss_context == NULL)
    {
      cached_gss_context = okrb5_gss_init_context ();
    }
  result = o_krb5_gss_prepare_context (&credential, cached_gss_context);
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
