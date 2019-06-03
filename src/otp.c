/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

/**
 * @file otp.c
 * @brief Implements OpenVAS Transfer Protocol.
 */

#include "otp.h"

#include "../misc/network.h"

#include <glib.h>
#include <string.h>

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
  if (!strcmp (str, "PREFERENCES"))
    return (CREQ_PREFERENCES);
  if (!strcmp (str, "STOP_WHOLE_TEST"))
    return (CREQ_STOP_WHOLE_TEST);

  return (CREQ_UNKNOWN);
}
