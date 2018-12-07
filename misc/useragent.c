/* openvas-scanner/misc
 * $Id$
 * Description: Functions to set and get the vendor version.
 *
 * Authors:
 * Juan Jose Nicola <juan.nicola@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2017 Greenbone Networks GmbH
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

#include <glib.h>
#include "useragent.h"

/**
 * @brief User Agent, or NULL.
 */
gchar *user_agent = NULL;

/**
 * @brief Set user agent
 *
 * @param[in]  ua user agent.
 */
void
user_agent_set (const gchar *ua)
{
  g_free (user_agent);
  user_agent = g_strdup (ua);
}

/**
 * @brief Get user agent.
 *
 * @return Set user agent or NULL.
 */
const gchar *
user_agent_get ()
{
  return user_agent ? user_agent : NULL;
}
