/* OpenVAS
* $Id$
* Description: Protos for OpenVAS Transfer Protocol 1.0.
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

#ifndef _OTP_1_0_H
#define _OTP_1_0_H

typedef enum {
  CREQ_UNKNOWN,
  CREQ_ATTACHED_FILE,
  CREQ_LONG_ATTACK,
  CREQ_NEW_ATTACK,
  CREQ_OPENVAS_VERSION,
  CREQ_PLUGIN_INFO,
  CREQ_PREFERENCES,
  CREQ_RULES,
  CREQ_SESSIONS_LIST,
  CREQ_SESSION_DELETE,
  CREQ_SESSION_RESTORE,
  CREQ_STOP_ATTACK,
  CREQ_STOP_WHOLE_TEST
} client_request_t;

client_request_t otp_1_0_get_client_request(char *);

void otp_1_0_server_openvas_version(struct arglist *);

#endif
