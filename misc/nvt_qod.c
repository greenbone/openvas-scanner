/* Copyright (C) 2009-2021 Greenbone Networks GmbH
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
 * @file
 * @brief Converts a qod_type string into a QoD value.
 *
 */

#include "nvt_qod.h"

#include <glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

static const struct
{
  qod_val val;
  const char *type;
} qod_types[] = {
  {EXPLOIT, "exploit"},
  {REMOTE_VUL, "remote_vul"},
  {REMOTE_APP, "remote_app"},
  {PACKAGE, "package"},
  {REGISTRY, "registry"},
  {REMOTE_ACTIVE, "remote_active"},
  {REMOTE_BANNER, "remote_banner"},
  {EXECUTABLE_VERSION, "executable_version"},
  {REMOTE_ANALYSIS, "remote_analysis"},
  {REMOTE_PROBE, "remote_probe"},
  {REMOTE_BANNER_UNRELIABLE, "remote_banner_unreliable"},
  {EXECUTABLE_VERSION_UNRELIABLE, "executable_version_unreliable"},
  {GENERAL_NOTE, "general_note"},
  {DEFAULT, "default"}};

/**
 * @brief Converts a qod_type string into int value
 *
 * @param[in] qod_type String containing the qod type
 *
 * @return The value corresponding to the given qod type. Defaults to 70 if
 * the given type does not exist. -1 if a null pointer was given.
 */
int
qod_type2val (const char *qod_type)
{
  unsigned int i;

  if (!qod_type)
    return -1;

  for (i = 0; i < sizeof (qod_types) / sizeof (qod_types[i]); i++)
    {
      if (!g_strcmp0 (qod_types[i].type, qod_type))
        return qod_types[i].val;
    }
  return DEFAULT;
}
