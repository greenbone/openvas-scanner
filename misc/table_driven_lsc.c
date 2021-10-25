/* Portions Copyright (C) 2021 Greenbone Networks GmbH
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
 * @file table_drive_lsc.c
 * @brief Function to start a table driven lsc.
 */

#include "table_driven_lsc.h"

#include <gvm/util/mqtt.h>      // for mqtt_reset
#include <gvm/util/uuidutils.h> // for gvm_uuid_make
#include <json-glib/json-glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/**
 * @brief Split the package list string and creates a json array.
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param[in/out] builder   The Json builder to add the array to.
 * @param[in]     packages  The installed package list as string
 *
 * @return JSON builder including the package list as array.
 */
static JsonBuilder *
add_packages_str_to_list (JsonBuilder *builder, const gchar *packages)
{
  gchar **package_list = NULL;

  json_builder_set_member_name (builder, "package_list");
  json_builder_begin_array (builder);

  package_list = g_strsplit (packages, "\n", 0);
  if (package_list && package_list[0])
    {
      int i;
      for (i = 0; package_list[i]; i++)
        json_builder_add_string_value (builder, package_list[i]);
    }

  json_builder_end_array (builder);
  g_strfreev (package_list);

  return builder;
}

/**
 * @brief Build a json object with data necessary to start a table drive LSC
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param scan_id     Scan Id.
 * @param kb
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 * @param module      Module to be used. The OS base name or package manager
 * name
 * @param os_release  OS release
 * @param package_list The installed package list in the target system to be
 * evaluated
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
gchar *
make_table_driven_lsc_info_json_str (const char *scan_id, const char *ip_str,
                                     const char *hostname,
                                     const char *os_release,
                                     const char *package_list)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gchar *json_str;

  /* Build the message in json format to be published. */
  builder = json_builder_new ();

  json_builder_begin_object (builder);

  json_builder_set_member_name (builder, "message_id");
  builder = json_builder_add_string_value (builder, gvm_uuid_make ());

  json_builder_set_member_name (builder, "group_id");
  builder = json_builder_add_string_value (builder, gvm_uuid_make ());

  json_builder_set_member_name (builder, "message_type");
  builder = json_builder_add_string_value (builder, "scan.start");

  json_builder_set_member_name (builder, "created");
  builder = json_builder_add_int_value (builder, time (NULL));

  json_builder_set_member_name (builder, "scan_id");
  builder = json_builder_add_string_value (builder, scan_id);

  json_builder_set_member_name (builder, "host_ip");
  json_builder_add_string_value (builder, ip_str);

  json_builder_set_member_name (builder, "host_name");
  json_builder_add_string_value (builder, hostname);

  json_builder_set_member_name (builder, "os_release");
  json_builder_add_string_value (builder, os_release);

  add_packages_str_to_list (builder, package_list);

  json_builder_end_object (builder);

  gen = json_generator_new ();
  root = json_builder_get_root (builder);
  json_generator_set_root (gen, root);
  json_str = json_generator_to_data (gen, NULL);

  json_node_free (root);
  g_object_unref (gen);
  g_object_unref (builder);

  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}
