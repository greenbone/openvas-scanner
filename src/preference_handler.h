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
 * @file preference_handler.h
 * @brief Header file for module preference_handler.
 */

#ifndef PREFERENCE_HANDLER_H
#define PREFERENCE_HANDLER_H

#include "../misc/scanneraux.h"

#include <glib.h>
#include <gvm/base/prefs.h> /* for prefs_get() */
#include <json-glib/json-glib.h>

void
prefs_store_file (struct scan_globals *, const gchar *, const gchar *);

void
write_json_credentials_to_preferences (struct scan_globals *, JsonReader *);

#endif // PREFERENCE_HANDLER_H
