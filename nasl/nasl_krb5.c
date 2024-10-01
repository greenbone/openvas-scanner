#include "nasl_krb5.h"

#include "../misc/openvas-krb5.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"
// TODO: add string function for result
#define nasl_print_krb_error(lexic, credential, result)                \
  nasl_perror (lexic, "%s[config_path: %s  realm: %s user: %s] => %d", \
               __func__, credential.config_path, credential.realm,     \
               credential.user, result);

OKrb5ErrorCode last_okrb5_result;
static OKrb5Credential
build_krb5_credential (lex_ctxt *lexic)
{
  OKrb5Credential credential;
  credential.user = NULL;
  credential.password = NULL;
  // neither values from get_str_var_by_name nor getenv must be freed
  if ((credential.config_path = get_str_var_by_name (lexic, "config_path"))
      == NULL)
    {
      credential.config_path = getenv ("KRB5_CONFIG");
      if (credential.config_path == NULL)
        {
          credential.config_path = "/etc/krb5.conf";
        }
    }
  if ((credential.realm = get_str_var_by_name (lexic, "realm")) == NULL)
    {
      credential.realm = getenv ("KRB5_REALM");
      if (credential.realm == NULL)
        {
          nasl_print_krb_error (lexic, credential, O_KRB5_REALM_NOT_FOUND);
        }
    }

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
      return NULL;
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
nasl_okrb5_result (lex_ctxt *lexic) {
  (void) lexic;
  // TODO: implement function to return string representation of result
  return NULL;
}

/**
 * @brief Returns 1 if the krb5 function was successful 0 otherwise
 *
 * The nasl function has one optional parameter:
 * - retval: the return value of the krb5 function. If the value is not defined, the return value of the last krb5 function is used.
 *
 *
 * @param[in] lexic     NASL lexer. 
 *
 * @return lex cell containing a number indicating success.
 */
tree_cell *
nasl_okrb5_is_success (lex_ctxt *lexic) {
  OKrb5ErrorCode result = get_int_var_by_name (lexic, "retval", last_okrb5_result);
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result == O_KRB5_SUCCESS;
  return retc;
}

/**
 * @brief Returns 0 if the krb5 function was successful and 1 if it failed
 *
 * The nasl function has one optional parameter:
 * - retval: the return value of the krb5 function. If the value is not defined, the return value of the last krb5 function is used.
 *
 *
 * @param[in] lexic     NASL lexer. 
 *
 * @return lex cell containing a number indicating success.
 */
tree_cell *
nasl_okrb5_is_failure (lex_ctxt *lexic) {
  OKrb5ErrorCode result = get_int_var_by_name (lexic, "retval", last_okrb5_result);
  tree_cell *retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = result != O_KRB5_SUCCESS;
  return retc;
}

