#include "nasl_krb5.h"

#include "../misc/openvas-krb5.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <stdio.h>
// TODO: add string function for result
#define nasl_print_krb_error(lexic, credential, result)                      \
  nasl_perror (lexic, "%s[config_path: '%s' realm: '%s' user: '%s'] => %d",  \
               __func__, credential.config_path.data, credential.realm.data, \
               credential.user.user.data, result);

OKrb5ErrorCode last_okrb5_result;

#define set_slice_from_lex_or_env(lexic, slice, name, env_name)            \
  do                                                                       \
    {                                                                      \
      okrb5_set_slice_from_str (slice, get_str_var_by_name (lexic, name)); \
      if (slice.len == 0)                                                  \
        {                                                                  \
          okrb5_set_slice_from_str (slice, getenv (env_name));             \
        }                                                                  \
    }                                                                      \
  while (0)

#define perror_set_slice_from_lex_or_env(lexic, slice, name, env_name) \
  do                                                                   \
    {                                                                  \
      set_slice_from_lex_or_env (lexic, slice, name, env_name);        \
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
  OKrb5Credential credential;
  memset (&credential, 0, sizeof (OKrb5Credential));

  set_slice_from_lex_or_env (lexic, credential.config_path, "config_path",
                             "KRB5_CONFIG");
  if (credential.config_path.len == 0)
    {
      okrb5_set_slice_from_str (credential.config_path, "/etc/krb5.conf");
    }
  // TODO: enhance with redis check? maybe.

  perror_set_slice_from_lex_or_env (lexic, credential.realm, "realm",
                                    "KRB5_REALM");
  perror_set_slice_from_lex_or_env (lexic, credential.user.user, "user",
                                    "KRB5_USER");
  perror_set_slice_from_lex_or_env (lexic, credential.user.password, "password",
                                    "KRB5_PASSWORD");
  perror_set_slice_from_lex_or_env (lexic, credential.target.host_name, "host",
                                    "KRB5_TARGET_HOST");
  // set_slice_from_lex_or_env (lexic, credential.target.service, "service",
  // "KRB5_TARGET_SERVICE");
  if (credential.target.service.len == 0)
    {
      okrb5_set_slice_from_str (credential.target.service, "cifs");
    }
  set_slice_from_lex_or_env (lexic, credential.kdc, "kdc", "KRB5_KDC");

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
      nasl_print_krb_error (lexic, credential, last_okrb5_result);
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
  // TODO: create macro for that
  char *kdc = get_str_var_by_name (lexic, "kdc");
  if (kdc == NULL)
    {
      kdc = getenv ("KRB5_KDC");
      if (kdc == NULL)
        {
          last_okrb5_result = O_KRB5_EXPECTED_NOT_NULL;
          nasl_print_krb_error (lexic, credential, last_okrb5_result);
          goto exit;
        }
    }

  credential = build_krb5_credential (lexic);

  if ((last_okrb5_result = o_krb5_add_realm (&credential, kdc)))
    {
      nasl_print_krb_error (lexic, credential, last_okrb5_result);
    }

exit:
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = last_okrb5_result;
  return retc;
}

tree_cell *
nasl_okrb5_result (lex_ctxt *lexic)
{
  (void) lexic;
  // TODO: implement function to return string representation of result
  return NULL;
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

// TODO: may need a cacing mechanism for different configurations
// for now we just use one
struct OKrb5GSSContext *cached_gss_context = NULL;

tree_cell *
nasl_okrb5_gss_init (lex_ctxt *lexic)
{
  (void) lexic;
  if (cached_gss_context != NULL)
    {
      okrb5_gss_free_context (cached_gss_context);
    }
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

struct OKrb5Slice *to_application = NULL;
bool gss_update_context_more = false;

tree_cell *
nasl_okrb5_gss_update_context (lex_ctxt *lexic)
{
  (void) lexic;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  tree_cell *retc;
  struct OKrb5Slice from_application;

  if (to_application != NULL)
    {
      free (to_application->data);
      free (to_application);
      to_application = NULL;
    }

  okrb5_set_slice_from_str (from_application, get_str_var_by_num (lexic, 0));

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

tree_cell *
nasl_okrb5_gss_update_context_needs_more (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = gss_update_context_more;
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
  tree_cell *retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = to_application->data;
  retc->size = to_application->len;
  return retc;
}

/*
  context = okrb5_gss_init_context ();
  printf ("Using realm: %s\n", (char *) credentials.realm.data);
  if ((result = o_krb5_gss_prepare_context (&credentials, context)))
    {
      return 1;
    }
  printf ("Using realm: %s\n", (char *) credentials.realm.data);
  // first call always empty
  if ((result = o_krb5_gss_update_context (context, &from_application,
                                           &to_application, &more)))
    {
      return 1;
    }
  printf ("success: %d: outdata_len: %zu\n", result, to_application->len);

  for (size_t i = 0; i < to_application->len; i++)
    {
      printf ("%02x", ((char *) to_application->data)[i]);
    }
  printf ("\n");

*/

/*
*OKrb5ErrorCode
o_krb5_gss_session_key_context (struct OKrb5GSSContext *gss_context,
                                struct OKrb5Slice **out);

struct OKrb5GSSContext *okrb5_gss_init_context (void);

void okrb5_gss_free_context (struct OKrb5GSSContext *context);

OKrb5ErrorCode
o_krb5_gss_prepare_context (const OKrb5Credential *creds,
                            struct OKrb5GSSContext *gss_context);

OKrb5ErrorCode
o_krb5_gss_update_context (struct OKrb5GSSContext *gss_context,
                           const struct OKrb5Slice *in_data,
                           struct OKrb5Slice **out_data, bool *more);
*/
