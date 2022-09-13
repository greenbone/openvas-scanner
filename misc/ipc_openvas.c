/* Portions Copyright (C) 2009-2022 Greenbone Networks GmbH
 * Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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
#include "ipc_openvas.h"

#include <json-glib/json-glib.h>
#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

// Data types definitions

// ipc_hostname is used to send / retrieve new hostnames.
struct ipc_hostname
{
  char *source;        // source value
  char *hostname;      // hostname value
  size_t source_len;   // length of source
  size_t hostname_len; // length of hostname
};

typedef struct ipc_hostname ipc_hostname_t;

// ipc_user_agent is used to send / retrieve the User-Agent.
struct ipc_user_agent
{
  char *user_agent;      // user_agent value
  size_t user_agent_len; // length of user_agent
};

typedef struct ipc_user_agent ipc_user_agent_t;

struct ipc_data
{
  enum ipc_data_type type;
  union
  {
    ipc_user_agent_t *ipc_user_agent;
    ipc_hostname_t *ipc_hostname;
  };
};

// Functions to access the structures

/**
 * @brief Get the data type in data
 *
 * @param data Structure containing the data and data type
 *
 * @Return The corresponding ipc_data_type, IPC_DT_ERROR on error.
 */
enum ipc_data_type
ipc_get_data_type_from_data (ipc_data_t *data)
{
  if (data != NULL)
    return data->type;
  return IPC_DT_ERROR;
}

gchar *
ipc_get_hostname_from_data (ipc_data_t *data)
{
  if (data == NULL || (ipc_get_data_type_from_data (data) != IPC_DT_HOSTNAME))
    return NULL;

  return data->ipc_hostname->hostname;
}

gchar *
ipc_get_hostname_source_from_data (ipc_data_t *data)
{
  if (data == NULL || (ipc_get_data_type_from_data (data) != IPC_DT_HOSTNAME))
    return NULL;

  return data->ipc_hostname->source;
}

gchar *
ipc_get_user_agent_from_data (ipc_data_t *data)
{
  if (data == NULL || (ipc_get_data_type_from_data (data) != IPC_DT_USER_AGENT))
    return NULL;

  return data->ipc_user_agent->user_agent;
}

// Hostname

/**
 * @brief initializes ipc_data for a hostname data.
 *
 * @param source the source of the hostname
 * @param hostname the name of the host
 *
 * @return a heap initialized ipc_data or NULL on failure.
 */
struct ipc_data *
ipc_data_type_from_hostname (const char *source, size_t source_len,
                             const char *hostname, size_t hostname_len)
{
  struct ipc_data *data = NULL;
  ipc_hostname_t *hnd = NULL;
  if (source == NULL || hostname == NULL)
    return NULL;
  if ((data = calloc (1, sizeof (*data))) == NULL)
    return NULL;
  data->type = IPC_DT_HOSTNAME;
  if ((hnd = calloc (1, sizeof (*hnd))) == NULL)
    goto failure_exit;
  hnd->hostname = g_strdup (hostname);
  hnd->source = g_strdup (source);
  hnd->hostname_len = hostname_len;
  hnd->source_len = source_len;
  data->ipc_hostname = hnd;
  return data;
failure_exit:
  free (data);
  return NULL;
}

static void
ipc_hostname_destroy (ipc_hostname_t *data)
{
  if (data == NULL)
    return;
  g_free (data->hostname);
  g_free (data->source);
  g_free (data);
}

// User-Agent

/**
 * @brief initializes ipc_data for the User-Agent.
 *
 * @param user_agent The User-Agent
 * @param user_agent_len Length of the user agent string.
 *
 * @return a heap initialized ipc_data or NULL on failure.
 */
struct ipc_data *
ipc_data_type_from_user_agent (const char *user_agent, size_t user_agent_len)
{
  struct ipc_data *data = NULL;
  ipc_user_agent_t *uad = NULL;
  gchar *ua_str = NULL;

  if (user_agent == NULL)
    return NULL;

  if ((data = calloc (1, sizeof (*data))) == NULL)
    return NULL;
  data->type = IPC_DT_USER_AGENT;

  if ((uad = calloc (1, sizeof (*uad))) == NULL)
    goto failure_exit;

  ua_str = g_strdup (user_agent);
  uad->user_agent = ua_str;
  uad->user_agent_len = user_agent_len;

  data->ipc_user_agent = uad;
  return data;

failure_exit:
  free (data);
  return NULL;
}

/**
 * @brief Free a user agent data structure
 *
 * @param data The user agent data structure to be free()'ed
 */
static void
ipc_user_agent_destroy (ipc_user_agent_t *data)
{
  if (data == NULL)
    return;
  g_free (data->user_agent);
  g_free (data);
}

// General IPC data functios

/**
 * @brief destroys ipc_data.
 *
 * @param data the ipc_data to be destroyed.
 *
 */
void
ipc_data_destroy (struct ipc_data *data)
{
  if (data == NULL)
    return;
  switch (data->type)
    {
    case IPC_DT_HOSTNAME:
      ipc_hostname_destroy (data->ipc_hostname);
      break;
    case IPC_DT_USER_AGENT:
      ipc_user_agent_destroy (data->ipc_user_agent);
      break;
    case IPC_DT_ERROR:
      return;
    }
  g_free (data);
}

/**
 * @brief transforms ipc_data to a json string
 *
 * @param data the ipc_data to be transformed.
 *
 * @return a heap allocated achar array containing the json or NULL on failure.
 */
const char *
ipc_data_to_json (struct ipc_data *data)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gchar *json_str;
  ipc_hostname_t *hn = NULL;
  ipc_user_agent_t *ua = NULL;
  enum ipc_data_type type = IPC_DT_ERROR;

  if (data == NULL)
    return NULL;

  if ((type = ipc_get_data_type_from_data (data)) == IPC_DT_ERROR)
    return NULL;

  builder = json_builder_new ();

  json_builder_begin_object (builder);

  json_builder_set_member_name (builder, "type");
  builder = json_builder_add_int_value (builder, type);
  switch (type)
    {
    case IPC_DT_HOSTNAME:
      hn = data->ipc_hostname;
      json_builder_set_member_name (builder, "source");
      builder = json_builder_add_string_value (builder, hn->source);
      json_builder_set_member_name (builder, "hostname");
      builder = json_builder_add_string_value (builder, hn->hostname);
      break;

    case IPC_DT_USER_AGENT:
      ua = data->ipc_user_agent;
      json_builder_set_member_name (builder, "user-agent");
      builder = json_builder_add_string_value (builder, ua->user_agent);
      break;

    default:
      g_warning ("%s: Unknown data type %d.", __func__, type);
    }

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
 * @brief transforms json string to a ipc_data struct
 *
 * @param json the json representation to be transformed.
 * @param len the length of the json representation
 *
 * @return a heap allocated ipc_data or NULL on failure.
 */
struct ipc_data *
ipc_data_from_json (const char *json, size_t len)
{
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;

  GError *err = NULL;
  struct ipc_data *ret = NULL;
  ipc_user_agent_t *ua;
  ipc_hostname_t *hn;

  enum ipc_data_type type = IPC_DT_ERROR;

  if ((ret = calloc (1, sizeof (*ret))) == NULL)
    goto cleanup;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, json, len, &err))
    {
      goto cleanup;
    }

  reader = json_reader_new (json_parser_get_root (parser));

  if (!json_reader_read_member (reader, "type"))
    {
      goto cleanup;
    }

  type = json_reader_get_int_value (reader);
  json_reader_end_member (reader);

  ret->type = type;
  switch (type)
    {
    case IPC_DT_ERROR:
      goto cleanup;
    case IPC_DT_HOSTNAME:
      if ((hn = calloc (1, sizeof (*hn))) == NULL)
        goto cleanup;
      if (!json_reader_read_member (reader, "hostname"))
        {
          goto cleanup;
        }
      hn->hostname = g_strdup (json_reader_get_string_value (reader));
      hn->hostname_len = strlen (hn->hostname);
      json_reader_end_member (reader);
      if (!json_reader_read_member (reader, "source"))
        {
          goto cleanup;
        }
      hn->source = g_strdup (json_reader_get_string_value (reader));
      hn->source_len = strlen (hn->source);
      json_reader_end_member (reader);
      ret->ipc_hostname = hn;
      break;

    case IPC_DT_USER_AGENT:

      if ((ua = calloc (1, sizeof (*ua))) == NULL)
        goto cleanup;
      if (!json_reader_read_member (reader, "user-agent"))
        {
          goto cleanup;
        }
      ua->user_agent = g_strdup (json_reader_get_string_value (reader));
      ua->user_agent_len = strlen (ua->user_agent);
      json_reader_end_member (reader);
      ret->ipc_user_agent = ua;
      break;
    }

cleanup:
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse json (%s). Reason: %s", __func__, json,
                 err->message);
    }
  if (ret == NULL)
    ipc_data_destroy (ret);

  return ret;
}
