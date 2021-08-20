/* Copyright (C) 2021 Greenbone Networks GmbH
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
 * @file messageutils.c
 * @brief Reporting function.
 */
#include "reporting.h"

#include "plugutils.h"

#include <eulabeia/json.h>
#include <eulabeia/types.h>
#include <glib.h>
#include <gvm/base/hosts.h>      // for g_vhost_t
#include <gvm/base/networking.h> // for port_protocol_t
#include <gvm/base/prefs.h>      // for prefs_get
#include <gvm/util/uuidutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *
msg_type_to_str (msg_t type)
{
  gchar *type_str;

  switch (type)
    {
    case ERRMSG:
      type_str = "ERRMSG";
      break;
    case HOST_START:
      type_str = "HOST_START";
      break;
    case HOST_END:
      type_str = "HOST_END";
      break;
    case LOG:
      type_str = "LOG";
      break;
    case HOST_DETAIL:
      type_str = "HOST_DETAIL";
      break;
    case ALARM:
      type_str = "ALARM";
      break;
    case DEADHOST:
      type_str = "DEADHOST";
      break;
    default:
      return NULL;
      break;
    }

  return type_str;
}

/**
 * @brief Build a json representation of a result.
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param scan_id     Scan Id. Mandatory
 * @param type        Type of result, like LOG. Mandatory
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 * @param port_s      Port string.
 * @param proto       Protocol related to the issue (tcp or udp).
 * @param action_str  The actual result text. Mandatory
 * @param uri         Location like file path or webservice URL.
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
gchar *
make_result_json_str (const gchar *scan_id, msg_t type, const gchar *ip_str,
                      const gchar *hostname, const gchar *port_s,
                      const gchar *proto, const gchar *oid,
                      const gchar *action_str, const gchar *uri)
{
  struct EulabeiaMessage *msg;
  struct EulabeiaScanResult *result;
  const gchar *global_scan_id = NULL;
  gchar *json_str = NULL;
  gchar *port = NULL;

  global_scan_id = scan_id ? scan_id : prefs_get ("global_scan_id");

  if (!global_scan_id || !(type >= ERRMSG && type <= HOSTS_COUNT)
      || !action_str)
    return NULL;

  if ((msg = eulabeia_initialize_message (EULABEIA_INFO_SCAN_RESULT,
                                          EULABEIA_SCAN, NULL))
      == NULL)
    {
      g_warning ("%s: unable to initialize start.scan message", __func__);
      return NULL;
    }
  port = NULL;
  if (port_s && proto)
    port = g_strdup_printf ("%s/%s", port_s, proto);

  result->message = msg;
  result->result_type = g_strdup (msg_type_to_str (type));
  result->id = g_strdup (global_scan_id);
  result->host_ip = ip_str ? g_strdup (ip_str) : NULL;
  result->host_name = hostname ? g_strdup (hostname) : NULL;
  result->port = port;
  result->value = action_str ? g_strdup (action_str) : NULL;
  result->oid = oid ? g_strdup (oid) : NULL;
  result->uri = uri ? g_strdup (uri) : NULL;

  json_str = eulabeia_scan_result_message_to_json (msg, result);
  eulabeia_message_destroy (&msg);
  eulabeia_scan_result_destroy (&result);

  return json_str;
}

//############################################
// Messages generated from scan process.
//############################################

//############################################
// Messages generated from host processes.
//############################################
static void
host_message_send (const gchar *message)
{
  char topic[128];
  const char *context;

  context = prefs_get ("mqtt_context");
  snprintf (topic, sizeof (topic), "%s/scan/info", context);

  mqtt_publish (topic, message);
}

/**
 * @brief Host process sends a message regarding a pluging
 *
 * @description: The plugin timeouts and the host process, which controls
 * each single plugin process detects that the plugins reached run time limit.
 * Send the message to the client, informing about the NVT.
 *
 * @param host_ip Host IP which the plugin timed out against to.
 * @param oid   The oid of the NVT which timed out
 * @param timeout The timeout value.
 *
 **/
void
host_message_nvt_timeout (const gchar *host_ip, const gchar *oid, const gchar *msg)
{
  gchar *json_str = NULL;

  json_str = make_result_json_str (NULL, ERRMSG, host_ip, NULL, NULL, NULL, oid,
                                   msg, NULL);
  if (json_str)
    host_message_send (json_str);

  g_free (json_str);
}

/**
 * @brief Function to send a message to the client from a host process.
 *
 * @description: In general, host process only send a message informing the host_ip
 * the and the message with a message type.
 *
 * @param type  Message type ERRMSG, HOST_START, HOST_END, LOG, DEAD_HOST.
 * @param host_ip Host IP which the plugin timed out against to.
 * @param msg   The message to be sent
 *
 **/
void
host_message (msg_t type, const gchar *host_ip, const gchar *msg)
{
  gchar *json_str = NULL;

  json_str = make_result_json_str (NULL, type, host_ip, NULL, NULL, NULL, NULL,
                                   msg, NULL);
  if (json_str)
    host_message_send (json_str);

  g_free (json_str);
}


//############################################
// Messages generated from plugin processes.
//############################################
/**
 * @brief Post a security message (e.g. LOG, NOTE, WARNING ...).
 *
 * @param oid   The oid of the NVT
 * @param desc  The script infos where to get settings.
 * @param port  Port number related to the issue.
 * @param proto Protocol related to the issue (tcp or udp).
 * @param action The actual result text
 * @param msg_type   The message type.
 * @param uri   Location like file path or webservice URL.
 */
static void
proto_post_wrapped (const char *oid, struct script_infos *desc, int port,
                    const char *proto, const char *action, msg_t msg_type,
                    const char *uri)
{
  const char *hostname = "";
  char *buffer, *data, port_s[16] = "general";
  char topic[128];
  const char *context;
  gchar *json;
  char ip_str[INET6_ADDRSTRLEN];
  GString *action_str;
  gsize length;

  /* Should not happen, just to avoid trouble stop here if no NVTI found */
  if (!oid)
    return;

  if (action == NULL)
    action_str = g_string_new ("");
  else
    {
      action_str = g_string_new (action);
      g_string_append (action_str, "\n");
    }

  if (port > 0)
    snprintf (port_s, sizeof (port_s), "%d", port);
  if ((hostname = plug_current_vhost ()) == NULL && (desc->vhosts))
    hostname = ((gvm_vhost_t *) desc->vhosts->data)->value;
  addr6_to_str (plug_get_host_ip (desc), ip_str);
  buffer = g_strdup_printf ("%s|||%s|||%s|||%s/%s|||%s|||%s|||%s",
                            msg_type_to_str (msg_type), ip_str, hostname ?: " ",
                            port_s, proto, oid, action_str->str, uri ?: "");
  /* Convert to UTF-8 before sending to Manager. */
  data = g_convert (buffer, -1, "UTF-8", "ISO_8859-1", NULL, &length, NULL);

  /* Send result via MQTT. */
  context = prefs_get ("mqtt_context");
  snprintf (topic, 128, "%s/scan/info", context);
  json = make_result_json_str (desc->globals->scan_id, msg_type, ip_str,
                               hostname ?: " ", port_s, proto, oid,
                               action_str->str, uri ?: "");
  if (json == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);
  else
    mqtt_publish (topic, json);
  g_free (json);

  g_free (data);
  g_free (buffer);
  g_string_free (action_str, TRUE);
}

void
proto_post_alarm (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, ALARM, uri);
}

void
post_alarm (const char *oid, struct script_infos *desc, int port,
            const char *action, const char *uri)
{
  proto_post_alarm (oid, desc, port, "tcp", action, uri);
}

/**
 * @brief Post a log message
 */
void
proto_post_log (const char *oid, struct script_infos *desc, int port,
                const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, LOG, uri);
}

/**
 * @brief Post a log message about a tcp port.
 */
void
post_log (const char *oid, struct script_infos *desc, int port,
          const char *action)
{
  proto_post_log (oid, desc, port, "tcp", action, NULL);
}

/**
 * @brief Post a log message about a tcp port with a uri
 */
void
post_log_with_uri (const char *oid, struct script_infos *desc, int port,
                   const char *action, const char *uri)
{
  proto_post_log (oid, desc, port, "tcp", action, uri);
}

void
proto_post_error (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, ERRMSG, uri);
}

void
post_error (const char *oid, struct script_infos *desc, int port,
            const char *action, const char *uri)
{
  proto_post_error (oid, desc, port, "tcp", action, uri);
}
