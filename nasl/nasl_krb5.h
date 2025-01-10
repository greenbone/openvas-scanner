// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"

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
nasl_okrb5_find_kdc (lex_ctxt *lexic);

/**
 * @brief Adds the given KDC to the given Realm
 *
 * This function returns 0 on success. To retrieve a human readable error
 * message, the function `okrb5_result` can be used.
 *
 * The nasl function has three optional parameter:
 * - realm: The realm for which the KDC should be returned. If the realm is not
 * defined, then the env parameter `KRB5_REALM` is used.
 * - kdc: The realm for which the KDC should be returned. If the realm is not
 * defined, then the env parameter `KRB5_KDC` is used.
 * - config_path: The path to the krb5.conf file. If the path is not defined,
 * then the env parameter `KRB5_CONFIG` is used.
 *
 * This function should only be used for debug purposes.
 *
 * @param[in] lexic     NASL lexer.
 *
 * @return lex cell containing a number indicating success or failure.
 */
tree_cell *
nasl_okrb5_add_realm (lex_ctxt *lexic);

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
nasl_okrb5_is_success (lex_ctxt *lexic);

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
nasl_okrb5_is_failure (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_init (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_prepare_context (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_update_context (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_update_context_needs_more (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_update_context_out (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_gss_session_key_context (lex_ctxt *lexic);

tree_cell *
nasl_okrb5_error_code_to_string (lex_ctxt *lexic);

void
nasl_okrb5_clean (void);
