/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 * @param os_release  OS release
 * @param package_list The installed package list in the target system to be
 * evaluated
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
static gchar *
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

/**
 * @brief Get the status of table driven lsc from json object
 *
 * Checks for the corresponding status inside the JSON. If the status does not
 * belong the the scan or host, NULL is returned instead. NULL is also returned
 * if message JSON cannot be parsed correctly. Return value has to be freed by
 * caller.
 *
 * @param scan_id id of scan
 * @param host_ip ip of host
 * @param json json to get information from
 * @param len length of json
 * @return gchar* Status of table driven lsc or NULL
 */
static gchar *
get_status_of_table_driven_lsc_from_json (const char *scan_id,
                                          const char *host_ip, const char *json,
                                          int len)
{
  JsonParser *parser;
  JsonReader *reader = NULL;

  GError *err = NULL;
  gchar *ret = NULL;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, json, len, &err))
    {
      goto cleanup;
    }

  reader = json_reader_new (json_parser_get_root (parser));

  // Check for Scan ID
  if (!json_reader_read_member (reader, "scan_id"))
    {
      goto cleanup;
    }
  if (g_strcmp0 (json_reader_get_string_value (reader), scan_id))
    {
      goto cleanup;
    }
  json_reader_end_member (reader);

  // Check Host IP
  if (!json_reader_read_member (reader, "host_ip"))
    {
      goto cleanup;
    }
  if (g_strcmp0 (json_reader_get_string_value (reader), host_ip))
    {
      goto cleanup;
    }
  json_reader_end_member (reader);

  // Check Status
  if (!json_reader_read_member (reader, "status"))
    {
      goto cleanup;
    }
  ret = g_strdup (json_reader_get_string_value (reader));

  json_reader_end_member (reader);

cleanup:
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse json. Reason: %s", __func__,
                 err->message);
    }
  return ret;
}

/**
 * @brief Publish the necessary data to start a Table driven LSC scan.
 *
 * If the gather-package-list.nasl plugin was launched, and it generated
 * a valid package list for a supported OS, the table driven LSC scan
 * which is subscribed to the topic will perform a scan an publish the
 * the results to be handle by the sensor/client.
 *
 * @param scan_id     Scan Id.
 * @param kb
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 *
 * @return 0 on success, less than 0 on error.
 */
int
run_table_driven_lsc (const char *scan_id, const char *ip_str,
                      const char *hostname, const char *package_list,
                      const char *os_release)
{
  gchar *json_str;
  gchar *topic;
  gchar *payload;
  gchar *status = NULL;
  int topic_len;
  int payload_len;
  int err = 0;

  // Subscribe to status topic
  err = mqtt_subscribe ("scanner/status");
  if (err)
    {
      g_warning ("%s: Error starting lsc. Unable to subscribe", __func__);
      return -1;
    }

  if (!os_release || !package_list)
    return -1;

  json_str = make_table_driven_lsc_info_json_str (scan_id, ip_str, hostname,
                                                  os_release, package_list);

  // Run table driven lsc
  if (json_str == NULL)
    return -1;
  err = mqtt_publish ("scanner/package/cmd/notus", json_str);
  if (err)
    {
      g_warning ("%s: Error publishing message for Notus.", __func__);
      g_free (json_str);
      return -1;
    }

  g_free (json_str);

  // Wait for Notus scanner to start or interrupt
  while (!status)
    {
      err = mqtt_retrieve_message (&topic, &topic_len, &payload, &payload_len,
                                   60000);
      if (err == -1 || err == 1)
        {
          g_warning ("%s: Unable to retrieve status message from notus. %s",
                     __func__, err == 1 ? "Timeout after 60 s." : "");
          return -1;
        }

      // Get status if it belongs to corresponding scan and host
      // Else wait for next status message
      status = get_status_of_table_driven_lsc_from_json (scan_id, ip_str,
                                                         payload, payload_len);

      g_free (topic);
      g_free (payload);
    }
  // If started wait for it to finish or interrupt
  if (!g_strcmp0 (status, "running"))
    {
      g_debug ("%s: table driven LSC with scan id %s successfully started "
               "for host %s",
               __func__, scan_id, ip_str);
      g_free (status);
      status = NULL;
      while (!status)
        {
          err = mqtt_retrieve_message (&topic, &topic_len, &payload,
                                       &payload_len, 60000);
          if (err == -1)
            {
              g_warning ("%s: Unable to retrieve status message from notus.",
                         __func__);
              return -1;
            }
          if (err == 1)
            {
              g_warning ("%s: Unablet to retrieve message. Timeout after 60s.",
                         __func__);
              return -1;
            }

          status = get_status_of_table_driven_lsc_from_json (
            scan_id, ip_str, payload, payload_len);
          g_free (topic);
          g_free (payload);
        }
    }
  else
    {
      g_warning ("%s: Unable to start lsc. Got status: %s", __func__, status);
      g_free (status);
      return -1;
    }

  if (g_strcmp0 (status, "finished"))
    {
      g_warning (
        "%s: table driven lsc with scan id %s did not finish successfully "
        "for host %s. Last status was %s",
        __func__, scan_id, ip_str, status);
      err = -1;
    }
  else
    g_debug ("%s: table driven lsc with scan id %s successfully finished "
             "for host %s",
             __func__, scan_id, ip_str);
  g_free (status);
  return err;
}
