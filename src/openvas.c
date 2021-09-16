/* Portions Copyright (C) 2009-2021 Greenbone Networks GmbH
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

/**
 * @mainpage
 *
 * @section Introduction
 * @verbinclude README.md
 *
 * @section license License Information
 * @verbinclude COPYING
 */

/**
 * @file
 * OpenVAS main module, runs the scanner.
 */

#include "../misc/plugutils.h"     /* nvticache_free */
#include "../misc/reporting.h"     /* for send_failure */
#include "../misc/vendorversion.h" /* for vendor_version_set */
#include "attack.h"                /* for attack_network */
#include "debug_utils.h"           /* for init_sentry */
#include "pluginlaunch.h"          /* for init_loading_shm */
#include "processes.h"             /* for create_process */
#include "sighand.h"               /* for openvas_signal */
#include "utils.h"                 /* for store_file */

#include <errno.h> /* for errno() */
#include <eulabeia/client.h>
#include <fcntl.h>  /* for open() */
#include <gcrypt.h> /* for gcry_control */
#include <glib.h>
#include <gnutls/gnutls.h> /* for gnutls_global_set_log_*  */
#include <grp.h>
#include <gvm/base/logging.h> /* for setup_log_handler, load_log_configuration, free_log_configuration*/
#include <gvm/base/nvti.h>      /* for prefs_get() */
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/base/proctitle.h> /* for proctitle_set */
#include <gvm/base/version.h>   /* for gvm_libs_version */
#include <gvm/util/kb.h>        /* for KB_PATH_DEFAULT */
#include <gvm/util/mqtt.h>      /* for mqtt_init */
#include <gvm/util/nvticache.h> /* nvticache_free */
#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <json-glib/json-glib.h>
#include <netdb.h> /* for addrinfo */
#include <pwd.h>
#include <signal.h> /* for SIGTERM */
#include <stdio.h>  /* for fflush() */
#include <stdlib.h> /* for atoi() */
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h> /* for waitpid */
#include <time.h>
#include <unistd.h> /* for close() */

#ifdef GIT_REV_AVAILABLE
#include "gitrevision.h"
#endif

#if GNUTLS_VERSION_NUMBER < 0x030300
#include "../misc/network.h" /* openvas_SSL_init */
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

#define PROCTITLE_WAITING "openvas: Waiting for incoming connections"
#define PROCTITLE_LOADING "openvas: Loading Handler"
#define PROCTITLE_RELOADING "openvas: Reloading"
#define PROCTITLE_SERVING "openvas: Serving %s"

/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

int global_min_memory = 0;
int global_max_sysload = 0;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;

static volatile int termination_signal = 0;
static char *global_scan_id = NULL;

typedef struct
{
  char *option;
  char *value;
} openvas_option;

/**
 * @brief Default values for scanner options. Must be NULL terminated.
 *
 * Only include options which are dependent on CMake variables.
 * Empty options must be "\0", not NULL, to match the behavior of prefs_init.
 */
static openvas_option openvas_defaults[] = {
  {"plugins_folder", OPENVAS_NVT_DIR},
  {"include_folders", OPENVAS_NVT_DIR},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"scanner_plugins_timeout", G_STRINGIFY (SCANNER_NVT_TIMEOUT)},
  {"db_address", KB_PATH_DEFAULT},
  {"mqtt_context", "scanner"},
  {NULL, NULL}};

/**
 * @brief Set the prefs from the openvas_defaults array.
 */
static void
set_default_openvas_prefs ()
{
  for (int i = 0; openvas_defaults[i].option != NULL; i++)
    prefs_set (openvas_defaults[i].option, openvas_defaults[i].value);
}

static void
my_gnutls_log_func (int level, const char *text)
{
  g_message ("(%d) %s", level, text);
}

static void
set_globals_from_preferences (void)
{
  const char *str;

  if ((str = prefs_get ("max_hosts")) != NULL)
    {
      global_max_hosts = atoi (str);
      if (global_max_hosts <= 0)
        global_max_hosts = 15;
    }

  if ((str = prefs_get ("max_checks")) != NULL)
    {
      global_max_checks = atoi (str);
      if (global_max_checks <= 0)
        global_max_checks = 10;
    }

  if ((str = prefs_get ("max_sysload")) != NULL)
    {
      global_max_sysload = atoi (str);
      if (global_max_sysload <= 0)
        global_max_sysload = 0;
    }

  if ((str = prefs_get ("min_free_mem")) != NULL)
    {
      global_min_memory = atoi (str);
      if (global_min_memory <= 0)
        global_min_memory = 0;
    }
}

static void
handle_termination_signal (int sig)
{
  termination_signal = sig;
}

/**
 * @brief Initializes main scanner process' signal handlers.
 */
static void
init_signal_handlers (void)
{
  openvas_signal (SIGTERM, handle_termination_signal);
  openvas_signal (SIGINT, handle_termination_signal);
  openvas_signal (SIGQUIT, handle_termination_signal);
  openvas_signal (SIGCHLD, sighand_chld);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wunused-value"
/**
 * @brief Check if the preference value matches with the type
 *
 * @param type preference type
 * @param value preference value
 *
 * @return True if value is the type of "type". False otherwise.
 */
static gboolean
validate_pref_type_value (gchar *type, gchar *value)
{
  // TODO: validate types
  (void *) type;
  (void *) value;
  return TRUE;
}

/**
 * @brief Stores a file type plugin preference
 *
 * @details File types are stored in a hash list and only the file
 * name is stored as preference.
 *
 * @param globals Scan_globals struct to stored the file content.
 * @param key_name The preference key name (OID:PrefID:Type:Name)
 * @param file The file content to be stored.
 */
static void
prefs_store_file (struct scan_globals *globals, const gchar *key_name,
                  const gchar *file)
{
  char *file_uuid = gvm_uuid_make ();
  int ret;

  prefs_set (key_name, file_uuid);
  ret = store_file (globals, file, file_uuid);
  if (ret)
    g_debug ("Load preference: Failed to upload file "
             "for nvt %s preference.",
             key_name);

  g_free (file_uuid);
}

/**
 * @brief Store credentials as preferences.
 *
 * @details Credentials are received as json object but must be
 * stored either as plugin preferences or boreas preferences.
 *
 * @param alive_test_reader Json reader pointing to the object with
 * alive test preferences.
 */
static void
write_json_credentials_to_preferences (struct scan_globals *globals,
                                       JsonReader *credentials_reader)
{
  int j, num_cred;

  num_cred = json_reader_count_elements (credentials_reader);
  for (j = 0; j < num_cred; j++)
    {
      const char *service = NULL;
      const char *username = NULL;
      const char *password = NULL;

      json_reader_read_element (credentials_reader, j);
      service = json_reader_get_string_value (credentials_reader);

      json_reader_read_member (credentials_reader, "username");
      username = json_reader_get_string_value (credentials_reader);
      json_reader_end_member (credentials_reader);

      json_reader_read_member (credentials_reader, "password");
      password = json_reader_get_string_value (credentials_reader);
      json_reader_end_member (credentials_reader);

      // SSH Service
      if (!g_strcmp0 (service, "ssh"))
        {
          int port;
          char portstr[6];
          const char *priv_username;
          const char *priv_password;

          json_reader_read_member (credentials_reader, "username");
          priv_username = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          json_reader_read_member (credentials_reader, "password");
          priv_password = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          // SSH port
          if (json_reader_read_member (credentials_reader, "port"))
            {
              port = json_reader_get_int_value (credentials_reader);
              if (port > 65535 || port < 1)
                {
                  g_warning ("Port for SSH is out of range (1-65535): %d",
                             port);
                  json_reader_end_member (
                    credentials_reader); // close port node
                  json_reader_end_member (
                    credentials_reader); // close service node
                  continue;
                }
            }
          else
            {
              port = 22;
              g_warning ("Missing port number for ssh credentials. Using "
                         "default port 22.");
            }
          json_reader_end_member (credentials_reader); // close port node

          g_snprintf (portstr, sizeof (portstr), "%d", port);
          prefs_set ("auth_port_ssh", portstr);

          // Credential type
          if (json_reader_read_member (credentials_reader, "credential_type"))
            {
              const char *cred_type = NULL;
              int err = 0;
              cred_type = json_reader_get_string_value (credentials_reader);

              if (!g_strcmp0 (cred_type, "up"))
                {
                  prefs_set ("1.3.6.1.4.1.25623.1.0.103591:3:password:SSH "
                             "password (unsafe!):",
                             password ? password : "");
                }
              else if (!g_strcmp0 (cred_type, "usk"))
                {
                  const char *private;

                  json_reader_read_member (credentials_reader, "private");
                private
                  = json_reader_get_string_value (credentials_reader);
                  json_reader_end_member (credentials_reader);

                  prefs_set ("1.3.6.1.4.1.25623.1.0.103591:2:password:SSH key "
                             "passphrase:",
                             password ? password : "");
                  prefs_store_file (
                    globals,
                    "1.3.6.1.4.1.25623.1.0.103591:4:file:SSH private key:",
                    private ? private : "");
                }
              else if (cred_type)
                {
                  g_warning (
                    "Unknown Credential Type for SSH: %s Use 'up' for Username "
                    "+ Password or 'usk' for Username + SSH Key.",
                    cred_type);
                  err = 1;
                }
              else
                {
                  g_warning (
                    "Missing Credential Type for SSH. Use 'up' for Username + "
                    "Password or 'usk' for Username + SSH Key.");
                  err = 1;
                }
              // close credential type node
              json_reader_end_member (credentials_reader);
              if (err == 1)
                {
                  json_reader_end_member (
                    credentials_reader); // close service node
                  continue;
                }

              prefs_set ("1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login:",
                         username ? username : "");
              prefs_set ("1.3.6.1.4.1.25623.1.0.103591:7:entry:SSH privilege "
                         "login name:",
                         priv_username ? priv_username : "");
              prefs_set ("1.3.6.1.4.1.25623.1.0.103591:8:password:SSH "
                         "privilege password:",
                         priv_password ? priv_password : "");

              // close service node
              json_reader_end_member (credentials_reader);
            }
        } // End SSH Service

      // SMB Service
      else if (!g_strcmp0 (service, "smb"))
        {
          prefs_set ("1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:",
                     username ? username : "");
          prefs_set ("1.3.6.1.4.1.25623.1.0.90023:2:password:SMB password:",
                     password ? password : "");
        } // End SMB Service

      // ESXi Service
      else if (!g_strcmp0 (service, "esxi"))
        {
          prefs_set ("1.3.6.1.4.1.25623.1.0.105058:1:entry:ESXi login name:",
                     username ? username : "");
          prefs_set (
            "1.3.6.1.4.1.25623.1.0.105058:2:password:ESXi login password:",
            password ? password : "");
        } // End ESXi Service

      json_reader_end_element (credentials_reader);
    }
}

/**
 * @brief Store alive test as preferences.
 *
 * @details Alive tests are received as json object but must be
 * stored either as plugin preferences or boreas preferences.
 *
 * @param alive_test_reader Json reader pointing to the object with
 * alive test preferences.
 */
static void
write_json_alive_test_to_preferences (JsonReader *alive_test_reader)
{
  // TODO: handle alive tests
  (void *) alive_test_reader;
}
#pragma GCC diagnostic pop

/**
 * @brief Get the type and the name of a plugin preferences.
 *
 * @details Plugins preferences key name have the form
 * OID:PrefID:Type:Name.
 * Only the ID is received in the json object (in addtion to the value).
 * This function retrieves the missing components necessary to form the
 * preference's key name.
 *
 * @param[in] nprefs List of preferences which belong to the plugin.
 * @param[in] id Preference ID which name and type are seek.
 * @param[out] name The preference name
 * @param[out] type The preference type
 */
static void
get_pref_name_components (GSList *nprefs, gchar *id, gchar **name, gchar **type)
{
  GSList *pref_tmp;

  pref_tmp = nprefs;
  while (pref_tmp)
    {
      if (atoi (id) == nvtpref_id (pref_tmp->data))
        {
          *type = nvtpref_type (pref_tmp->data);
          *name = nvtpref_name (pref_tmp->data);
          break;
        }
      pref_tmp = pref_tmp->next;
    }
}

/**
 * @brief Get the value which the json reader is pointing to
 *
 * @details Check for the value type and store the value.
 *
 * @param value_reader Json reader pointing to the value.
 *
 * @return Value as string. Null otherwise.
 */
static gchar *
get_json_value (JsonReader *value_reader)
{
  JsonNode *node_value = json_reader_get_value (value_reader);
  GType type = json_node_get_value_type (node_value);
  gchar *value = NULL;

  if (type == G_TYPE_STRING)
    {
      value = g_strdup (json_reader_get_string_value (value_reader));
    }
  if (type == G_TYPE_BOOLEAN)
    {
      value =
        g_strdup (json_reader_get_boolean_value (value_reader) ? "yes" : "no");
    }
  if (type == G_TYPE_INT64 || type == G_TYPE_INT)
    {
      value = g_strdup_printf ("%ld", json_reader_get_int_value (value_reader));
    }
  return value;
}

/**
 * @brief Store plugin preferences in the right form.
 *
 * @details Only the id is received (besides the value). This functions
 * created the key_name of the preferences, and validate the value with the
 * type. Also handle the special "file" type preference.
 *
 * @param globals Scan_globals struct. Used only to store the file types.
 * @param single_vt_reader Json reader pointing to a single vt plugins
 * @param oid OID of the plugins which the preferences to be handle belongs to.
 */
static void
write_json_plugin_prefs_to_preferences (struct scan_globals *globals,
                                        JsonReader *single_vt_reader,
                                        const gchar *oid)
{
  // TODO: better error handling for non-existing preferences/plugins
  // Plugins can be removed from redis and no preferences will be found.

  gchar **members;
  int j, num_plug_prefs;
  GSList *nprefs;
  g_debug ("%s: entered", __func__);

  json_reader_read_member (single_vt_reader, "prefs_by_id");
  if (!json_reader_is_object (single_vt_reader))
    {
      // we ignore prefs_by_id when it is not an object (e.g. when NULL)
      return;
    }
  num_plug_prefs = json_reader_count_members (single_vt_reader);
  g_debug ("%s: amount of plug preferences: %d", __func__, num_plug_prefs);
  members = json_reader_list_members (single_vt_reader);

  // Get nvt preferences list, to get the key name by id
  // Done here, to don't query redis for each plugin's preference list
  nprefs = nvticache_get_prefs (oid);

  for (j = 0; j < num_plug_prefs; j++)
    {
      gchar *key = members[j];

      json_reader_read_member (single_vt_reader, key);
      if (json_reader_is_value (single_vt_reader))
        {
          gchar *value, *name = NULL, *type = NULL;

          /* Only got the id and value. We need now the
           * name and type.
           */
          get_pref_name_components (nprefs, key, &name, &type);
          if (name == NULL || type == NULL)
            {
              g_warning ("%s: Preference with ID %s was not found for %s. "
                         "Preference will not be loaded.",
                         __func__, key, oid);
              json_reader_end_member (single_vt_reader);
              continue;
            }
          value = get_json_value (single_vt_reader);
          if (value && validate_pref_type_value (type, value))
            {
              gchar *key_name;

              key_name = g_strdup_printf ("%s:%s:%s:%s", oid, key, type, name);
              // handle special case for file type
              if (!g_strcmp0 (type, "file"))
                prefs_store_file (globals, key_name, value);
              else
                prefs_set (key_name, value);

              g_free (key_name);
            }
          g_free (value);
        }
      json_reader_end_member (single_vt_reader);
    }
  json_reader_end_member (single_vt_reader);
  g_slist_free_full (nprefs, (void (*) (void *)) nvtpref_free);
}

/**
 * @brief Store plugins list and  preferences in the right form.
 *
 * @details An array of plugins struct (oid + preferences) arrives as json
 * object.
 * This function preapres the "TARGET" string, concatenating the plugins oids.
 * Also, preapres the handle the plugin preferences
 *
 * @param globals Scan_globals struct. Used only to store the file types.
 * @param reader Json reader pointing to a list of plugins
 */
static void
write_json_plugins_to_preferences (struct scan_globals *globals,
                                   JsonReader *reader)
{
  const char *value;
  char *key;
  int j, num_plugins;
  GString *values = NULL;
  g_debug ("%s: entered", __func__);

  json_reader_read_member (reader, "single_vts");
  num_plugins = json_reader_count_elements (reader);

  key = "plugin_set";
  g_debug ("%s: number of plugins %d", __func__, num_plugins);

  for (j = 0; j < num_plugins; j++)
    {
      json_reader_read_element (reader, j);
      json_reader_read_member (reader, "oid");

      value = json_reader_get_string_value (reader);
      g_debug ("%s: value %s", __func__, value);
      if (value)
        {
          if (j == 0) // first plugin
            values = g_string_new (value);
          else // Other plugins
            g_string_append_printf (values, ";%s", value);
          // Write this plugin preferences
          write_json_plugin_prefs_to_preferences (globals, reader, value);
        }
      json_reader_end_member (reader);
      json_reader_end_element (reader);
    }
  g_debug ("%s: add %s (%s)", __func__, key, values->str);
  prefs_set (key, values->str);
  g_string_free (values, TRUE);
  json_reader_end_member (reader);
}

/**
 * @brief Write preferences from json into globals
 *
 * Adds preferences from a json string into the global_prefs.
 * If preference already exists in global_prefs they will be overwritten by
 * prefs from json.
 *
 * @param json String in which preferences are stored.
 * @return int 0 on success, -1 if json is empty or format is invalid.
 */
static int
write_json_to_preferences (struct scan_globals *globals, char *json, int len)
{
  JsonParser *parser;
  JsonReader *reader;

  gint num_member;
  gchar **members;
  GError *err = NULL;

  int i;

  // Build json tree struct
  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, json, len, &err))
    {
      g_warning ("%s: Unable to parse json. Reason: %s", __func__,
                 err->message);
      return -1;
    }

  reader = json_reader_new (json_parser_get_root (parser));

  num_member = json_reader_count_members (reader);
  if (num_member < 1)
    {
      g_warning ("%s: Empty json.", __func__);
      return -1;
    }

  members = json_reader_list_members (reader);

  for (i = 0; i < num_member; i++)
    {
      gchar *key = members[i];
      g_debug ("%s: processing %s", __func__, key);
      if (!strcmp (key, "created") || !strcmp (key, "message_type")
          || !strcmp (key, "group_id") || !strcmp (key, "message_id"))
        {
          g_debug ("%s: skipped", __func__);
          continue;
        }
      else if (is_scanner_only_pref (key))
        {
          g_warning ("%s is a scanner only preference. It can not be written "
                     "by the client and will be ignored.",
                     key);
          continue;
        }

      json_reader_read_member (reader, key);
      // key-value preferences
      if (json_reader_is_value (reader))
        {
          char *value;

          value = get_json_value (reader);
          g_debug ("%s: %s -> %s", __func__, key, value);
          prefs_set (key, value);
          g_free (value);
        }
      // list (ports, hosts)
      // parse list comma separated into single string
      if (json_reader_is_array (reader))
        {
          if (!strcmp (key, "hosts"))
            {
              key = "TARGET";
            }
          if (!strcmp (key, "ports"))
            {
              key = "port_range";
            }
          const char *value;
          GString *values = NULL;
          int j, elements;

          elements = json_reader_count_elements (reader);

          // Read first element
          for (j = 0; j < elements; j++)
            {
              if (json_reader_read_element (reader, j))
                {
                  value = json_reader_get_string_value (reader);
                  if (value)
                    {
                      if (j == 0) // first element
                        values = g_string_new (value);
                      else // Other elements
                        g_string_append_printf (values, ";%s", value);
                    }
                  json_reader_end_element (reader);
                }
            }

          g_debug ("%s: adding elements for %s (%s)", __func__, key,
                   values->str);
          prefs_set (key, values->str);
          g_string_free (values, TRUE);
        }
      // dictionary (plugins)
      // parse list semicolon separated into single string
      if (json_reader_is_object (reader))
        {
          if (!strcmp (key, "plugins"))
            write_json_plugins_to_preferences (globals, reader);
          else if (!strcmp (key, "credentials"))
            write_json_credentials_to_preferences (globals, reader);
          else if (!strcmp (key, "alive"))
            write_json_alive_test_to_preferences (reader);
          else
            g_warning ("%s: unknown object %s", __func__, key);
        }
      json_reader_end_member (reader);
    }

  g_object_unref (reader);
  g_object_unref (parser);
  g_free (members);
  g_debug ("%s: leaving.", __func__);
  return 0;
}

/**
 * @brief Ask for start scan data.
 *
 * Sends a message to the director via mqtt asking for the necessary
 * information to start a scan.
 *
 * @param[in] scan_id Scan ID used to get the preferences.
 *
 * @return 0 on success, -1 if the kb is not found or no prefs are found in
 *         the kb.
 */
static int
ask_for_scan_prefs_from_client (const char *scan_id)
{
  char *msg_id, *group_id, topic_send[128], msg_send[1024];
  const char *context;
  int ret;

  // TODO: Get alive test via mqtt
  prefs_set ("ALIVE_TEST", "2");
  context = prefs_get ("mqtt_context");

  // Sned Get Scan
  msg_id = gvm_uuid_make ();
  group_id = gvm_uuid_make ();

  g_snprintf (topic_send, sizeof (topic_send), "%s/scan/cmd/director", context);
  g_snprintf (msg_send, sizeof (msg_send),
              "{\"message_id\":\"%s\","
              "\"group_id\":\"%s\","
              "\"message_type\":\"get.scan\","
              "\"created\":%ld,"
              "\"id\":\"%s\"}",
              msg_id, group_id, get_timestamp (), scan_id);

  if ((ret = mqtt_publish (topic_send, msg_send)) < 0)
    g_warning ("%s Publish to %s failed", __func__, topic_send);

  free (msg_id);
  free (group_id);
  return ret;
}

/**
 * @brief Init logging.
 *
 * @return 0 on success, -1 on error.
 */
static int
init_logging ()
{
  static gchar *log_config_file_name = NULL;
  int err;

  log_config_file_name =
    g_build_filename (OPENVAS_SYSCONF_DIR, "openvas_log.conf", NULL);
  if (g_file_test (log_config_file_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (log_config_file_name);
  err = setup_log_handlers (log_config);
  if (err)
    {
      g_warning ("%s: Can not open or create log file or directory. "
                 "Please check permissions of log files listed in %s.",
                 __func__, log_config_file_name);
      g_free (log_config_file_name);
      return -1;
    }
  g_free (log_config_file_name);

  return 0;
}

static void
gcrypt_init (void)
{
  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P))
    return;
  gcry_check_version (NULL);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED);
}

/**
 * @brief Check TLS.
 */
static void
check_tls ()
{
#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
#endif

  if (prefs_get ("debug_tls") != NULL && atoi (prefs_get ("debug_tls")) > 0)
    {
      g_warning ("TLS debug is enabled and should only be used with care, "
                 "since it may reveal sensitive information in the scanner "
                 "logs and might make openvas fill your disk rather quickly.");
      gnutls_global_set_log_function (my_gnutls_log_func);
      gnutls_global_set_log_level (atoi (prefs_get ("debug_tls")));
    }
}

/**
 * @brief Print start message.
 */
static void
openvas_print_start_msg ()
{
#ifdef OPENVAS_GIT_REVISION
  g_message ("openvas %s (GIT revision %s) started", OPENVAS_VERSION,
             OPENVAS_GIT_REVISION);
#else
  g_message ("openvas %s started", OPENVAS_VERSION);
#endif
}

/**
 * @brief Search in redis the process ID of a running scan and
 * sends it the kill signal SIGUSR1, which will stop the scan.
 * To find the process ID, it uses the scan_id passed with the
 * --scan-stop option.
 */
static void
stop_single_task_scan (void)
{
  char key[1024];
  kb_t kb;
  int pid;

  if (!global_scan_id)
    {
      exit (1);
    }

  g_snprintf (key, sizeof (key), "internal/%s", global_scan_id);
  kb = kb_find (prefs_get ("db_address"), key);
  if (!kb)
    {
      exit (1);
    }

  pid = kb_item_get_int (kb, "internal/ovas_pid");

  /* Only send the signal if the pid is a positive value.
     Since kb_item_get_int() will return -1 if the key does
     not exist. killing with -1 pid will send the signal system wide.
   */
  if (pid <= 0)
    return;

  /* Send the signal to the process group. */
  killpg (pid, SIGUSR1);
}

/**
 * @brief Creates the main kb and inserts the scan id
 *
 * @param scan_id
 * @return int 0 on success, -1 on failure
 */
int
create_main_kb (const char *scan_id)
{
  kb_t main_kb;
  int i;
  char id[6]; // max ID 99999 + \0

  if (kb_new (&main_kb, prefs_get ("db_address")))
    return -1;

  i = kb_get_kb_index (main_kb);

  g_snprintf (id, sizeof (id), "%d", i);
  g_debug ("Created new main db with id %d", i);
  prefs_set ("ov_maindbid", id);

  kb_item_add_str_unique (main_kb, "internal/scanid", scan_id, strlen (scan_id),
                          0);
  return 0;
}

/**
 * @brief Deletes the main kb
 *
 * @return int 0 on success, non-null on error
 */
int
delete_main_kb ()
{
  kb_t main_kb;
  int i = atoi (prefs_get ("ov_maindbid"));

  main_kb = kb_direct_conn (prefs_get ("db_address"), i);

  return kb_delete (main_kb);
}

/**
 * @brief Set up data needed for attack_network().
 *
 * @param globals scan_globals needed for client preference handling.
 * @param config_file Used for config preference handling.
 */
void
attack_network_init (struct scan_globals *globals, const gchar *config_file)
{
  const char *mqtt_server_uri, *mqtt_context;
  char *topic_recv, *msg_recv;
  int topic_len, msg_len, ret = 0;
  struct EulabeiaCRUDProgress get_progress;

  set_default_openvas_prefs ();
  prefs_config (config_file);

  if (create_main_kb (globals->scan_id))
    {
      g_warning ("%s: Failed to create main db.", __func__);
      exit (1);
    }

  /* Init MQTT communication */
  mqtt_server_uri = prefs_get ("mqtt_server_uri");
  if (!mqtt_server_uri)
    {
      g_warning ("%s: Unable to get mqtt_uri; aborting.", __func__);
      exit (1);
    }

  mqtt_context = prefs_get ("mqtt_context");
  if (!mqtt_context)
    {
      g_warning ("%s: Unable to get mqtt_context; aborting.", __func__);
      exit (1);
    }
  if (prefs_get ("vendor_version") != NULL)
    vendor_version_set (prefs_get ("vendor_version"));
  check_tls ();
  openvas_print_start_msg ();

  if (plugins_cache_init ())
    {
      g_message ("Failed to initialize nvti cache.");
      send_failure (globals->scan_id, "Failed to initialize nvti cache.");
      nvticache_reset ();
      exit (1);
    }
  nvticache_reset ();

  init_signal_handlers ();

  /* Make process a group leader, to make it easier to cleanup forked
   * processes & their children. */
  setpgid (0, 0);
  struct EulabeiaClient *ec = eulabeia_initialize (mqtt_server_uri, NULL);
  if (ec == NULL)
    {
      g_warning ("%s: Unable to initialize eulabeia_client; aborting",
                 __func__);
      exit (1);
    }

  if (ask_for_scan_prefs_from_client (globals->scan_id))
    exit (0);

  // Wait for incomming data and store it in globals
  msg_len = 0;
  get_progress.status = EULABEIA_CRUD_REQUESTED;
  int rc;
  while (get_progress.status != EULABEIA_CRUD_SUCCESS
         && get_progress.status != EULABEIA_CRUD_FAILED)
    {
      if ((rc =
             ec->retrieve (&topic_recv, &topic_len, &msg_recv, &msg_len, NULL))
          == -1)
        {
          g_warning ("%s: Unable to retrieve mqtt_message; aborting", __func__);
          exit (1);
        }
      if (rc == 0)
        {
          if ((rc = eulabeia_crud_progress (msg_recv, globals->scan_id,
                                            EULABEIA_INFO_GOT, &get_progress))
              == 0)
            {
              g_message ("%s: got response (%s) for %s", __func__, msg_recv,
                         globals->scan_id);
              if ((ret = write_json_to_preferences (globals, msg_recv, msg_len))
                  < 0)
                g_warning ("%s: Write preferences failed", __func__);
            }
          if (msg_recv != NULL)
            free (msg_recv);
          if (topic_recv != NULL)
            free (topic_recv);

          msg_recv = NULL;
          topic_recv = NULL;
        }
    }

  eulabeia_destroy (ec);
  if (ret)
    exit (0);
}

void
attack_network_cleanup ()
{
  delete_main_kb ();
}

/**
 * @brief openvas.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
int
openvas (int argc, char *argv[])
{
  int err;

  proctitle_init (argc, argv);
  gcrypt_init ();

  static gboolean display_version = FALSE;
  static gchar *config_file = NULL;
  static gchar *scan_id = NULL;
  static gchar *stop_scan_id = NULL;
  static gboolean print_specs = FALSE;
  static gboolean print_sysconfdir = FALSE;
  static gboolean update_vt_info = FALSE;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"cfg-specs", 's', 0, G_OPTION_ARG_NONE, &print_specs,
     "Print configuration settings", NULL},
    {"sysconfdir", 'y', 0, G_OPTION_ARG_NONE, &print_sysconfdir,
     "Print system configuration directory (set at compile time)", NULL},
    {"update-vt-info", 'u', 0, G_OPTION_ARG_NONE, &update_vt_info,
     "Updates VT info into redis store from VT files", NULL},
    {"scan-start", '\0', 0, G_OPTION_ARG_STRING, &scan_id,
     "ID of scan to start. ID and related data must be stored into redis "
     "before.",
     "<string>"},
    {"scan-stop", '\0', 0, G_OPTION_ARG_STRING, &stop_scan_id,
     "ID of scan to stop", "<string>"},

    {NULL, 0, 0, 0, NULL, NULL, NULL}};

  option_context =
    g_option_context_new ("- Open Vulnerability Assessment Scanner");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      exit (0);
    }
  g_option_context_free (option_context);

  /* --sysconfdir */
  if (print_sysconfdir)
    {
      g_print ("%s\n", SYSCONFDIR);
      exit (0);
    }

  /* --version */
  if (display_version)
    {
      printf ("OpenVAS %s\n", OPENVAS_VERSION);
#ifdef OPENVAS_GIT_REVISION
      printf ("GIT revision %s\n", OPENVAS_GIT_REVISION);
#endif
      printf ("gvm-libs %s\n", gvm_libs_version ());
      printf ("Most new code since 2005: (C) 2021 Greenbone Networks GmbH\n");
      printf (
        "Nessus origin: (C) 2004 Renaud Deraison <deraison@nessus.org>\n");
      printf ("License GPLv2: GNU GPL version 2\n");
      printf (
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n\n");
      exit (0);
    }

  /* Switch to UTC so that OTP times are always in UTC. */
  if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_print ("%s\n\n", strerror (errno));
      exit (0);
    }
  tzset ();

  if ((err = init_logging ()) != 0)
    return -1;

  err = init_sentry ();
  err ? /* Sentry is optional */
      : g_message ("Sentry is enabled. This can log sensitive information.");

  /* Config file location */
  if (!config_file)
    config_file = OPENVAS_CONF;

  if (update_vt_info)
    {
      set_default_openvas_prefs ();
      prefs_config (config_file);
      set_globals_from_preferences ();
      err = plugins_init ();
      nvticache_reset ();
      gvm_close_sentry ();
      return err ? -1 : 0;
    }

  /* openvas --scan-stop */
  if (stop_scan_id)
    {
      global_scan_id = g_strdup (stop_scan_id);
      stop_single_task_scan ();
      gvm_close_sentry ();
      exit (0);
    }

  /* openvas --scan-start */
  if (scan_id)
    {
      struct scan_globals *globals;
      global_scan_id = g_strdup (scan_id);
      globals = g_malloc0 (sizeof (struct scan_globals));
      globals->scan_id = g_strdup (global_scan_id);

      // TODO: improve the storage of the global_scan_id. Avoid global prefs.
      prefs_set ("global_scan_id", global_scan_id);

      attack_network_init (globals, config_file);
      g_message ("attack_network_init successfully executed");
      attack_network (globals);
      attack_network_cleanup ();

      gvm_close_sentry ();
      exit (0);
    }

  if (print_specs)
    {
      set_default_openvas_prefs ();
      prefs_config (config_file);
      prefs_dump ();
      gvm_close_sentry ();
      exit (0);
    }

  exit (0);
}
