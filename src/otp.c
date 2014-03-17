/* OpenVAS
* $Id$
* Description: Implements OpenVAS Transfer Protocol.
*
* Authors:
* Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
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
*/

#include <string.h>

#include <openvas/misc/network.h>

#include "otp.h"

#include <glib.h>

/**
 * @brief Find the enum identifier for the client request which is given
 * @brief as string.
 *
 * @param str Enum identifier of OTP command (a client_request_t).
 * @see client_request_t
 */
client_request_t
otp_get_client_request (char *str)
{
  if (!strcmp (str, "ATTACHED_FILE"))
    return (CREQ_ATTACHED_FILE);
  if (!strcmp (str, "LONG_ATTACK"))
    return (CREQ_LONG_ATTACK);
  if (!strcmp (str, "OPENVASSD_VERSION"))
    return (CREQ_OPENVAS_VERSION);
  if (!strcmp (str, "PLUGIN_INFO"))
    return (CREQ_PLUGIN_INFO);
  if (!strcmp (str, "PREFERENCES"))
    return (CREQ_PREFERENCES);
  if (!strcmp (str, "STOP_ATTACK"))
    return (CREQ_STOP_ATTACK);
  if (!strcmp (str, "STOP_WHOLE_TEST"))
    return (CREQ_STOP_WHOLE_TEST);
  if (!strcmp (str, "PAUSE_WHOLE_TEST"))
    return (CREQ_PAUSE_WHOLE_TEST);
  if (!strcmp (str, "RESUME_WHOLE_TEST"))
    return (CREQ_RESUME_WHOLE_TEST);
  if (!strcmp (str, "NVT_INFO"))
    return (CREQ_NVT_INFO);

  return (CREQ_UNKNOWN);
}

/**
 * @brief Send server response OPENVAS_VERSION.
 */
void
otp_server_openvas_version (struct arglist *globals)
{
  auth_printf (globals, "SERVER <|> OPENVAS_VERSION <|> %s <|> SERVER\n",
               OPENVASSD_VERSION);
}
