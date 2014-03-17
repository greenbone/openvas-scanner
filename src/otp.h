/* OpenVAS
* $Id$
* Description: Protos for OpenVAS Transfer Protocol.
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

#ifndef _OTP_H
#define _OTP_H

typedef enum
{
  CREQ_UNKNOWN,
  CREQ_ATTACHED_FILE,
  CREQ_LONG_ATTACK,
  CREQ_OPENVAS_VERSION,
  CREQ_PAUSE_WHOLE_TEST,
  CREQ_PLUGIN_INFO,
  CREQ_PREFERENCES,
  CREQ_RESUME_WHOLE_TEST,
  CREQ_STOP_ATTACK,
  CREQ_STOP_WHOLE_TEST,
  CREQ_NVT_INFO,
} client_request_t;

client_request_t otp_get_client_request (char *);

void otp_server_openvas_version (struct arglist *);

void otp_server_send_certificates (struct arglist *globals);

#endif
