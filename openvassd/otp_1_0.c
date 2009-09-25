/* OpenVAS
* $Id$
* Description: Implements OpenVAS Transfer Protocol 1.0.
*
* Authors:
* Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
*
* Copyright:
* Copyright (C) 2009 Greenbone Networks GmbH
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

#include <includes.h>

#include <string.h>

#include <corevers.h>
#include <network.h>

#include <nasl.h> /* for nasl_get_all_certifcates */
#include <openvas/base/certificate.h> /* for certificate_t */

#include "otp_1_0.h"

#include <glib.h>

/**
 * Find the enum identifier for the client request which is given
 * as string.
 * @param str Enum identifier of OTP command (a client_request_t).
 * @see client_request_t
 */
client_request_t otp_1_0_get_client_request(char* str)
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

/**
 * Send server response OPENVAS_VERSION
 */
void otp_1_0_server_openvas_version(globals)
  struct arglist * globals;
{
  auth_printf(globals,
              "SERVER <|> OPENVAS_VERSION <|> %s <|> SERVER\n",
              OPENVAS_VERSION);
}


/**
 * Send server response to certificate request by client.
 */
void otp_1_0_server_send_certificates(struct arglist* globals)
{
  auth_printf(globals, "SERVER <|> CERTIFICATES\n");

  /** @todo base/certificates.c offers certificates (list) functionality. */
  GSList* certificates = nasl_get_all_certificates();
  GSList* cert_list_elem = g_slist_nth(certificates, 0);

  // Iterate over certificates
  while(cert_list_elem != NULL)
    {
      certificate_t* cert = cert_list_elem->data;
      
      // Replace newlines by semicolons
      gchar* pos = cert->public_key;
      while(pos[0] != '\0')
        {
        if(pos[0] == '\n') pos[0] = ';';
        pos++;
        }

      char* trustlevel = (cert->trusted == TRUE)? "trusted" : "notrust";
      cert_list_elem = g_slist_next(cert_list_elem);
      auth_printf(globals, "%s <|> %s <|> %s <|> %d <|> %s\n", cert->fingerprint,
                              cert->owner, trustlevel,
                              (int)strlen(cert->public_key),
                              cert->public_key);
      // Release each element
      certificate_free (cert);
    }
  
  // Release list
  g_slist_free(certificates);
  
  auth_printf(globals, "<|> SERVER\n");
}
