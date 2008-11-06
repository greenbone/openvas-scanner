/* OpenVAS
* $Id$
* Description: Implements OpenVAS Transfer Protocol 1.0.
*
* Authors:
* Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
*
* Copyright:
* Copyright (C) 2008 Intevation GmbH
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 or later,
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*/

#include <string.h>

#include <corevers.h>
#include <network.h>

#include "otp_1_0.h"
#include <gpgme.h>

/* Find the enum identifier for the client request which is given
 * as string.
 */
client_request_t otp_1_0_get_client_request(str)
  char * str;
{
  if (!strcmp(str, "ATTACHED_FILE")) return(CREQ_ATTACHED_FILE);
  if (!strcmp(str, "CERTIFICATES")) return(CREQ_CERTIFICATES);
  if (!strcmp(str, "LONG_ATTACK")) return(CREQ_LONG_ATTACK);
  if (!strcmp(str, "OPENVAS_VERSION")) return(CREQ_OPENVAS_VERSION);
  if (!strcmp(str, "PLUGIN_INFO")) return(CREQ_PLUGIN_INFO);
  if (!strcmp(str, "PREFERENCES")) return(CREQ_PREFERENCES);
  if (!strcmp(str, "RULES")) return(CREQ_RULES);
  if (!strcmp(str, "SESSIONS_LIST")) return(CREQ_SESSIONS_LIST);
  if (!strcmp(str, "SESSION_DELETE")) return(CREQ_SESSION_DELETE);
  if (!strcmp(str, "SESSION_RESTORE")) return(CREQ_SESSION_RESTORE);
  if (!strcmp(str, "STOP_ATTACK")) return(CREQ_STOP_ATTACK);
  if (!strcmp(str, "STOP_WHOLE_TEST")) return(CREQ_STOP_WHOLE_TEST);

  return(CREQ_UNKNOWN);
}

/* Send server response OPENVAS_VERSION
 */
void otp_1_0_server_openvas_version(globals)
  struct arglist * globals;
{
  auth_printf(globals,
              "SERVER <|> OPENVAS_VERSION <|> %s <|> SERVER\n",
              OPENVAS_VERSION);
}

/* Send server response to certificate request by client.
 */
void otp_1_0_server_send_certificates(struct arglist* globals)
{
  auth_printf(globals, "SERVER <|> CERTIFICATES\n");
  // TODO: felix CR#17 - implement certificate sending here 
  
  // Certificate retrieval
  // Send dummystrings, basically 
  gpgme_error_t err;
  gpgme_ctx_t ctx = init_openvas_gpgme_ctx();

  err = gpgme_op_keylist_ext_start(ctx, NULL, 0, 0);
  if (err)
    {
       log_write("otp_1_0_send_certificates: trouble finding gpgme keys.\n");
    }

  while (!err)
    {
       gpgme_key_t key;
       err = gpgme_op_keylist_next (ctx, &key);
       if (err)
          break;
       log_write ("keyinfo  %s, %d, %s fpr: %s sk %s, ot %c\n", key->issuer_name, key->secret, key->uids->name, key->subkeys->fpr, key->subkeys->keyid, key->owner_trust);//, key.name, key.email);
       auth_printf(globals, "%s <|> %s <|> %s <|> %d \n", key->subkeys->fpr,
                                     key->uids->name, "untrusted", 0); //+ asci armored key
       gpgme_key_release (key);
    }

  if (!err)
    {
    if (gpg_err_code (err) != GPG_ERR_EOF)
      {
        log_write("otp_1_0_send_certificates: gpgme can not list keys: %s\n", gpgme_strerror (err));
      }
    }

  gpgme_release(ctx);
  // certificate retrieval end

  auth_printf(globals, "<|> SERVER\n");
}
