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
 * @file preference_handler.c
 * @brief Function to handle preferences before starting a scan.
 */

#include "preference_handler.h"

#include "../misc/plugutils.h"
#include "utils.h" /* for store_file */

#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <json-glib/json-glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

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
void
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
void
write_json_credentials_to_preferences (struct scan_globals *globals,
                                       JsonReader *credentials_reader)
{
  int j, num_cred;

  num_cred = json_reader_count_members (credentials_reader);
  for (j = 0; j < num_cred; j++)
    {
      const char *service = NULL;
      const char *username = NULL;
      const char *password = NULL;

      // Read service element
      json_reader_read_element (credentials_reader, j);
      service = json_reader_get_member_name (credentials_reader);

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

          json_reader_read_member (credentials_reader, "priv_username");
          priv_username = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          json_reader_read_member (credentials_reader, "priv_password");
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

      // SNMP Service
      else if (!g_strcmp0 (service, "snmp"))
        {
          const char *community;
          const char *auth_algorithm;
          const char *privacy_password;
          const char *privacy_algorithm;

          json_reader_read_member (credentials_reader, "privacy_algorithm");
          privacy_algorithm = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          json_reader_read_member (credentials_reader, "privacy_password");
          privacy_password = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          json_reader_read_member (credentials_reader, "auth_algorithm");
          auth_algorithm = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          json_reader_read_member (credentials_reader, "community");
          community = json_reader_get_string_value (credentials_reader);
          json_reader_end_member (credentials_reader);

          if (privacy_algorithm == NULL && privacy_password != NULL)
            {
              g_warning ("When no privacy algorithm is used, the privacy "
                         "password also has to be empty.");
              json_reader_end_member (credentials_reader); // close service node
              continue;
            }
          else if (g_strcmp0 (privacy_algorithm, "aes")
                   && g_strcmp0 (privacy_algorithm, "aes"))
            {
              g_warning ("Unknown privacy algorithm used: %s. Use 'aes', 'des' "
                         "or '' (none).",
                         privacy_algorithm);
              json_reader_end_member (credentials_reader); // close service node
              continue;
            }

          if (auth_algorithm == NULL)
            {
              g_warning ("Missing authentication algorithm for SNMP. Use 'md5' "
                         "or 'sha1'.");
              json_reader_end_member (credentials_reader); // close service node
              continue;
            }
          else if (g_strcmp0 (auth_algorithm, "md5")
                   && g_strcmp0 (auth_algorithm, "sha1"))
            {
              g_warning (
                "Unknown authentication algorithm: %s. Use 'md5' or 'sha1'.",
                auth_algorithm);
              json_reader_end_member (credentials_reader); // close service node
              continue;
            }

          prefs_set ("1.3.6.1.4.1.25623.1.0.105076:1:password:SNMP Community:",
                     community ? community : "");
          prefs_set ("1.3.6.1.4.1.25623.1.0.105076:2:entry:SNMPv3 Username:",
                     username ? username : "");
          prefs_set ("1.3.6.1.4.1.25623.1.0.105076:3:password:SNMPv3 Password:",
                     password ? password : "");
          prefs_set ("1.3.6.1.4.1.25623.1.0.105076:4:radio:SNMPv3 "
                     "Authentication Algorithm:",
                     auth_algorithm ? auth_algorithm : "");
          prefs_set (
            "1.3.6.1.4.1.25623.1.0.105076:5:password:SNMPv3 Privacy Password:",
            privacy_password ? privacy_password : "");
          prefs_set (
            "1.3.6.1.4.1.25623.1.0.105076:6:password:SNMPv3 Privacy Algorithm:",
            privacy_algorithm ? privacy_algorithm : "");
        } // End SNMP Service
      else if (service != NULL)
        g_warning ("Unknown service type for credential: %s.", service);
      else
        g_warning ("Missing service type for credential.");

      // close service node
      json_reader_end_member (credentials_reader);
    }
}

/**
 * @brief Store VT preferences for host_alive_detection.nasl.
 *
 * @details Store VT preferences which are used by host_alive_detection.nasl to
 * determine the method which was responsible for the alive detection.
 *
 * @param alive_test_bitflag Methods of alive detection.
 */
static void
write_alive_test_vt_preferences (int alive_test_bitflag)
{
  // TODO: Set the vt preferences
  (void) alive_test_bitflag;
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
void
write_json_alive_test_to_preferences (JsonReader *alive_test_reader)
{
  gboolean test_alive_hosts_only = TRUE;
  int alive_test_bitflag = 2; // default ICMP
  char at_bitflag_str[12];
  GString *ports_string = NULL;
  int j, num_ports, port;

  // 1. Set test_alive_hosts_only
  json_reader_read_member (alive_test_reader, "test_alive_hosts_only");
  test_alive_hosts_only = json_reader_get_boolean_value (alive_test_reader);
  prefs_set ("test_alive_hosts_only", test_alive_hosts_only ? "yes" : "no");
  json_reader_end_member (alive_test_reader);

  // 2. Set alive detection method
  json_reader_read_member (alive_test_reader, "methods_bitflag");
  alive_test_bitflag = json_reader_get_int_value (alive_test_reader);
  g_snprintf (at_bitflag_str, sizeof (at_bitflag_str), "%d",
              alive_test_bitflag);
  prefs_set ("ALIVE_TEST", at_bitflag_str);
  json_reader_end_member (alive_test_reader);

  // 3. Set port list
  if (json_reader_read_member (alive_test_reader, "ports"))
    {
      num_ports = json_reader_count_elements (alive_test_reader);
      for (j = 0; j < num_ports; j++)
        {
          json_reader_read_element (alive_test_reader, j);
          port = json_reader_get_int_value (alive_test_reader);
          if (port)
            {
              if (j == 0)
                {
                  ports_string = g_string_new (NULL);
                  g_string_append_printf (ports_string, "%d", port);
                }
              else
                {
                  g_string_append_printf (ports_string, ",%d", port);
                }
            }
          json_reader_end_element (alive_test_reader);
        }
      prefs_set ("ALIVE_TEST_PORTS", ports_string->str);
      g_string_free (ports_string, TRUE);
    }
  json_reader_end_member (alive_test_reader);

  // 4. Write vt preferences for host_alive_detection.nasl
  write_alive_test_vt_preferences (alive_test_bitflag);
}
