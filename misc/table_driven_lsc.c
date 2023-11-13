/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file table_drive_lsc.c
 * @brief Function to start a table driven lsc.
 */

#include "table_driven_lsc.h"

#include "base/networking.h"
#include "kb_cache.h"
#include "network.h"
#include "plugutils.h"

#include <ctype.h> // for tolower()
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h>
#include <gvm/util/mqtt.h>      // for mqtt_reset
#include <gvm/util/uuidutils.h> // for gvm_uuid_make
#include <json-glib/json-glib.h>
#include <stddef.h>

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
gchar *
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

#define RSNOTUS
#ifdef RSNOTUS
/** @brief Struct to hold necessary information to call and run notus
 *
 */
struct notus_info
{
  char *schema; // schema is http or https
  char *host;   // server hostname
  char *alpn; // Application layer protocol negotiation: http/1.0, http/1.1, h2
  char *http_version; // same version as in application layer
  int port;           // server port
  int tls;            // 0: TLS encapsulation diable. Otherwise enable
};

typedef struct notus_info *notus_info_t;

/** @brief Free notus info structure
 *
 */
static void
free_notus_info (notus_info_t notusdata)
{
  if (notusdata)
    {
      g_free (notusdata->schema);
      g_free (notusdata->host);
      g_free (notusdata->alpn);
      g_free (notusdata->http_version);
    }
}

/** @brief helper function to lower case
 *
 */
static char *
schema_tolower (char *s)
{
  for (char *p = s; *p; p++)
    *p = tolower (*p);
  return s;
}

/**
 * @brief Build a json array from the package list to start a table drive LSC
 *
 * @param packages The installed package list in the target system to be
 * evaluated
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
static gchar *
make_package_list_as_json_str (const char *packages)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gchar *json_str = NULL;
  gchar **package_list = NULL;
  builder = json_builder_new ();

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

/** @brief Call notus on plain HTTP
 *
 *  @param sockfd An opened socket to the server
 *  @param message HTTP message to be sent to the server
 *
 *  @return GString with the server response or NULL
 */
static GString *
call_notus_via_http (int sockfd, GString *message)
{
  int bytes, sent, total;
  GString *response;
  char buffer[4096];

  /* send the request */
  total = message->len;
  sent = 0;

  /* send the request */
  total = message->len;
  sent = 0;
  do
    {
      bytes = write (sockfd, message->str + sent, total - sent);
      if (bytes < 0)
        g_message ("ERROR writing message to socket");
      if (bytes == 0)
        break;
      sent += bytes;
    }
  while (sent < total);

  /* receive the response */
  response = g_string_new (NULL);

  int flags = 0;
  do
    {
      bytes = recv (sockfd, buffer, sizeof (buffer), flags);

      g_message ("leidos: %d", bytes);
      if (bytes < 0)
        g_message ("ERROR reading response from socket");
      if (bytes == 0)
        {
          g_message ("leidos: %d", bytes);
          break;
        }
      flags = MSG_DONTWAIT;
      g_string_append (response, buffer);
    }
  while (bytes == EAGAIN || bytes == EINTR);

  return response;
}

/** @brief Call notus over HTTPS
 *
 *  @param sockfd An opened socket to the server
 *  @param message HTTP message to be sent to the server
 *  @param alpn Application layer to be set for protocol negotiation
 *
 *  @return GString with the server response or NULL
 */
static GString *
call_notus_via_https (int sockfd, GString *message, const char *alpn)
{
  int ret, ii;
  char buffer[4096];
  GString *response;
  gnutls_session_t session;
  gnutls_anon_client_credentials_t anoncred;
  gnutls_datum_t protocol;

  gnutls_global_init ();

  gnutls_anon_allocate_client_credentials (&anoncred);

  /* Initialize TLS session
   */
  gnutls_init (&session, GNUTLS_CLIENT);

  /* Use default priorities */
  gnutls_priority_set_direct (
    session, "PERFORMANCE:+ANON-ECDH:+ANON-DH",
    //"NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:+ARCFOUR-128",
    //"NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:+ARCFOUR-128:%COMPAT",
    NULL);

  // Set alpn
  protocol.data = (void *) alpn;
  protocol.size = strlen (alpn);
  gnutls_alpn_set_protocols (session, &protocol, 1, 0);

  // Use the anonymous credentials to the current session, since it is
  // not required for notus. No sensitive data is sent/received.
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  gnutls_transport_set_int (session, sockfd);
  gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  response = g_string_new (NULL);
  /* Perform the TLS handshake
   */
  do
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

  if (ret < 0)
    {
      g_warning ("%s: Handshake failed\n", __func__);
      gnutls_perror (ret);
      goto end;
    }
  else
    {
      char *desc;
      desc = gnutls_session_get_desc (session);
      g_debug ("- Session info: %s\n", desc);
      gnutls_free (desc);
    }

  // Send request
  do
    {
      ret = gnutls_record_send (session, message->str, message->len);
    }
  while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

  // Receive response
  do
    {
      ret = gnutls_record_recv (session, buffer, 4096);
      g_string_append (response, buffer);
    }
  while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

  if (ret == 0)
    {
      goto end;
    }
  else if (ret < 0 && gnutls_error_is_fatal (ret) == 0)
    {
      g_warning ("%s: %s\n", __func__, gnutls_strerror (ret));
    }
  else if (ret < 0)
    {
      g_warning ("%s: %s\n", __func__, gnutls_strerror (ret));
      goto end;
    }

  if (ret > 0)
    {
      g_debug ("%s: Received %d bytes: ", __func__, ret);
      for (ii = 0; ii < ret; ii++)
        {
          fputc (buffer[ii], stdout);
        }
      fputs ("\n", stdout);
    }

  do
    {
      ret = gnutls_bye (session, GNUTLS_SHUT_RDWR);
    }
  while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

end:
  gnutls_deinit (session);
  gnutls_anon_free_client_credentials (anoncred);
  gnutls_global_deinit ();
  return response;
}

/** @brief Parse the server URL
 *
 *  @param[in] server String containing the server URL
 *                Valid is http://example.com:1234
 *                or https://example.com.1234.
 *  @notusdata[out] Structure to store information from the URL
 *
 *  @return 0 on success, -1 on error.
 */
static int
parse_server (const char *server, notus_info_t *notusdata)
{
  char **splitted_server;

  if (!server)
    return -1;

  splitted_server = g_strsplit (server, ":", 0);
  if (splitted_server == NULL)
    {
      g_warning ("%s: Invalid openvasd server", server);
      return -1;
    }

  if (splitted_server[0] == NULL || splitted_server[1] == NULL
      || splitted_server[2] == NULL)
    {
      g_warning ("%s: Invalid openvasd server %s. "
                 "Valid is http://example.com:1234 "
                 "or https://example.com.1234",
                 __func__, server);
      g_strfreev (splitted_server);
      return -1;
    }

  (*notusdata)->schema = g_strdup (schema_tolower (splitted_server[0]));
  if (g_strrstr ((*notusdata)->schema, "https"))
    {
      (*notusdata)->tls = 1;
      (*notusdata)->http_version = g_strdup ("2");
      (*notusdata)->alpn = g_strdup ("h2");
    }
  else if (g_strrstr ((*notusdata)->schema, "http"))
    {
      (*notusdata)->tls = 0;
      (*notusdata)->http_version = g_strdup ("1.1");
      (*notusdata)->alpn = g_strdup ("http/1.1");
    }
  else
    {
      g_warning ("%s: Invalid openvasd server schema", server);
      g_strfreev (splitted_server);
      return -1;
    }

  if (strlen (splitted_server[1]) > 2)
    {
      (*notusdata)->host = &splitted_server[1][2];
    }
  else
    {
      g_warning ("%s: Invalid openvasd server", server);
      g_strfreev (splitted_server);
      return -1;
    }

  (*notusdata)->port = atoi (splitted_server[2]);
  return 0;
}

enum fixed_type
{
  UNKNOWN,
  RANGE,
  SINGLE,
};

struct fixed_version
{
  char *version;
  char *specifier;
};
typedef struct fixed_version fixed_version_t;

struct version_range
{
  char *start;
  char *stop;
};
typedef struct version_range version_range_t;

struct vulnerable_pkg
{
  char *pkg_name;        // package name
  char *install_version; // installed version of the vulnerable package
  enum fixed_type type;  // fixed version type: range or single
  union
  {
    version_range_t *range;   // range of vulnerable versions
    fixed_version_t *version; // version and specifier for the fixed versions
  };
};

typedef struct vulnerable_pkg vuln_pkg_t;

struct advisory
{
  char *oid;             // Advisory OID
  vuln_pkg_t *pkgs[100]; // list of vulnerable packages, installed version and
                         // fixed versions
  size_t count;          // Count of vulnerable packages this adivsory has
};

typedef struct advisory advisory_t;

struct advisories
{
  advisory_t **advisories;
  size_t count;
  size_t max_size;
};
typedef struct advisories advisories_t;

/** @brief Initialize a new adivisories struct with 100 slots
 *
 *  @return initialized advisories_t struct. It must be free by the caller
 *          with advisories_free()
 */
static advisories_t *
advisories_new ()
{
  advisories_t *advisories_list = g_malloc0 (sizeof (advisories_t));
  advisories_list->max_size = 100;
  advisories_list->advisories =
    g_malloc0_n (advisories_list->max_size, sizeof (advisory_t));

  return advisories_list;
}

/** @brief Initialize a new adivisories struct with 100 slots
 *
 *  @param advisories_list[in/out] An advisories holder to add new advisories
into.
 *  @param advisory[in] the new advisory to add in the list
 *
 */
static void
advisories_add (advisories_t *advisories_list, advisory_t *advisory)
{
  // Reallocate more memory if the list is full
  if (advisories_list->count == advisories_list->max_size)
    {
      advisories_list->max_size *= 2;
      advisories_list->advisories =
        g_realloc_n (advisories_list->advisories, advisories_list->max_size,
                     sizeof (*advisories_list->advisories));
      memset (advisories_list->advisories + advisories_list->count, '\0',
              (advisories_list->max_size - advisories_list->count)
                * sizeof (advisory_t *));
    }
  advisories_list->advisories[advisories_list->count] = advisory;
  advisories_list->count++;
}

/** @brief Initialize a new adivisory
 *
 *  @param oid The advisory's OID
 *
 *  @return initialized advisory_t struct
 */

static advisory_t *
advisory_new (char *oid)
{
  advisory_t *adv = NULL;
  adv = g_malloc0 (sizeof (advisory_t));
  adv->oid = g_strdup (oid);
  adv->count = 0;
  return adv;
}

/** @brief Add a new vulnerability to the advisory.
 *
 *  @description Each advisory can have multiple vulnerable packages
 *               This structure can hold up to 100 packages.
 *
 *  @param adv[in/out] The advisory to add the vulnerable package into
 *  @param vuln[in] The vulnerable package to add.
 */
static void
advisory_add_vuln_pkg (advisory_t *adv, vuln_pkg_t *vuln)
{
  if (adv->count == 100)
    {
      g_warning ("%s: Failed adding new vulnerable package to the advisory %s. "
                 "No more free slots",
                 __func__, adv->oid);
      return;
    }

  adv->pkgs[adv->count] = vuln;
  adv->count++;
}

/** @brief Free()'s an advisory
 *
 *  @param advisory The adviosory to be free()'ed.
 *  It free()'s all vulnerable packages that belong to this advisory.
 */
static void
advisory_free (advisory_t *advisory)
{
  if (advisory == NULL)
    return;

  g_free (advisory->oid);
  for (size_t i = 0; i < advisory->count; i++)
    {
      if (advisory->pkgs[i] != NULL)
        {
          g_free (advisory->pkgs[i]->pkg_name);
          g_free (advisory->pkgs[i]->install_version);
          if (advisory->pkgs[i]->type == RANGE)
            {
              g_free (advisory->pkgs[i]->range->start);
              g_free (advisory->pkgs[i]->range->stop);
            }
          else if (advisory->pkgs[i]->type == SINGLE)
            {
              g_free (advisory->pkgs[i]->version->version);
              g_free (advisory->pkgs[i]->version->specifier);
            }
        }
    }
  advisory = NULL;
}

/** @brief Free()'s an advisories
 *
 *  @param advisory The adviosories holder to be free()'ed.
 *  It free()'s all advisories members.
 */
static void
advisories_free (advisories_t *advisories)
{
  if (advisories == NULL)
    return;

  for (size_t i = 0; i < advisories->count; i++)
    advisory_free (advisories->advisories[i]);
  advisories = NULL;
}

/** @brief Creates a new Vulnerable packages which belongs to an advisory
 *
 *  @param pkg_name
 *  @param install_version
 *  @param type Data type specifying how the fixed version is stored.
 *              Can be RANGE or SINGLE
 *  @param item1 Depending on the type is the "version" for SINGLE type,
 *               or the "less than" for RANGE type
 *  @param item2 Depending on the type is the "specifer" for SINGLE type,
 *               or the "greather than" for RANGE type
 *
 *  @return a vulnerable packages struct.
 */
static vuln_pkg_t *
vulnerable_pkg_new (const char *pkg_name, const char *install_version,
                    enum fixed_type type, char *item1, char *item2)
{
  vuln_pkg_t *vuln = NULL;
  version_range_t *range = NULL;
  fixed_version_t *fixed_ver = NULL;

  vuln = g_malloc0 (sizeof (vuln_pkg_t));
  vuln->pkg_name = g_strdup (pkg_name);
  vuln->install_version = g_strdup (install_version);
  vuln->type = type;
  if (type == RANGE)
    {
      range = g_malloc0 (sizeof (range_t));
      range->start = g_strdup (item1);
      range->stop = g_strdup (item2);
      vuln->range = range;
    }
  else
    {
      fixed_ver = g_malloc0 (sizeof (fixed_version_t));
      fixed_ver->version = g_strdup (item1);
      fixed_ver->specifier = g_strdup (item2);
      vuln->version = fixed_ver;
    }

  return vuln;
}

/** @brief Process a json object which contains advisories and vulnerable
 *         packages
 *
 *  @description This is the body string in response get from an openvasd server
 *
 *  @param resp String containing the json object to be processed.
 *  @param len String lenght.
 *
 *  @return a advisories_t struct containing all advisories and vulnerable
 *                         packages.
 *                         After usage must be free()'ed with advisories_free().
 */
static advisories_t *
process_notus_response (const gchar *resp, const size_t len)
{
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;
  GError *err = NULL;

  advisories_t *advisories = advisories_new ();

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, resp, len, &err))
    {
      g_message ("Errror parsing");
    }

  reader = json_reader_new (json_parser_get_root (parser));

  if (!json_reader_is_object (reader))
    {
      g_message ("No es un object");
    }

  char **members = json_reader_list_members (reader);

  for (int i = 0; members[i]; i++)
    {
      advisory_t *advisory;

      if (!json_reader_read_member (reader, members[i]))
        {
          g_debug ("No member oid");
          goto cleanup_advisories;
        }
      if (!json_reader_is_array (reader))
        {
          g_debug ("Is not an array");
          goto cleanup_advisories;
        }

      advisory = advisory_new (g_strdup (members[i]));

      int count_pkgs = json_reader_count_elements (reader);
      g_debug ("There are %d packages for advisory %s", count_pkgs, members[i]);
      for (int j = 0; j < count_pkgs; j++)
        {
          vuln_pkg_t *pkg = NULL;
          char *name = NULL;
          char *installed_version = NULL;
          char *start = NULL;
          char *stop = NULL;
          char *version = NULL;
          char *specifier = NULL;
          enum fixed_type type = UNKNOWN;

          json_reader_read_element (reader, j);
          if (!json_reader_is_object (reader))
            {
              g_warning ("%s: Package %d of advisory %s is not an object",
                         __func__, j, members[i]);
              advisories_free (advisories);
              goto cleanup_advisories;
            }

          json_reader_read_member (reader, "name");
          name = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("name: %s", name);

          json_reader_read_member (reader, "installed_version");
          installed_version = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("installed_version: %s", installed_version);

          json_reader_read_member (reader, "fixed_version");
          g_debug ("Fixed_version has %d members",
                   json_reader_count_members (reader));

          // Version Range
          json_reader_read_member (reader, "start");
          start = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          json_reader_read_member (reader, "end");
          stop = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("start %s, end: %s", start, stop);

          // version and specifier
          json_reader_read_member (reader, "version");
          version = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          json_reader_read_member (reader, "specifier");
          specifier = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("version %s, specifier: %s", version, specifier);

          // end read fixes version member
          json_reader_end_member (reader);

          // end package element
          json_reader_end_element (reader);

          char *item1 = NULL, *item2 = NULL;
          if (start && stop)
            {
              type = RANGE;
              item1 = start;
              item2 = stop;
            }
          else if (version && specifier)
            {
              type = SINGLE;
              item1 = version;
              item2 = specifier;
            }
          else
            {
              g_warning ("%s: Error parsing json element", __func__);
              g_free (name);
              g_free (installed_version);
              g_free (item1);
              g_free (item2);
              advisories_free (advisories);
              goto cleanup_advisories;
            }

          pkg =
            vulnerable_pkg_new (name, installed_version, type, item1, item2);
          g_free (name);
          g_free (installed_version);
          g_free (item1);
          g_free (item2);

          advisory_add_vuln_pkg (advisory, pkg);
        }
      // end advisory
      json_reader_end_member (reader);
      advisories_add (advisories, advisory);
    }

cleanup_advisories:
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);

  return advisories;
}

/** @brief Sent the installed package list and OS to notus
 *
 *  @param pkg_list Installed package list
 *  @param os The target's OS
 *
 *  @return GString containing the server response or NULL
 *          Must be free()'ed by the caller.
 */
static GString *
notus_get_response (const char *pkg_list, const char *os)
{
  const char *server = NULL;
  int timeout = -2; // Default to 20
  int sockfd;
  char *json_pkglist;
  GString *message;
  GString *response;
  notus_info_t notusdata;

  // Parse the server and get the port, host, schema
  // and necessary information to build the message
  notusdata = g_malloc0 (sizeof (struct notus_info));
  server = prefs_get ("openvasd_server");

  if (parse_server (server, &notusdata) < 0)
    {
      free_notus_info (notusdata);
      return NULL;
    }

  // Convert the packge list string into a string containing json
  // array of packages
  if ((json_pkglist = make_package_list_as_json_str (pkg_list)) == NULL)
    {
      free_notus_info (notusdata);
      return NULL;
    }

  // Build the message to be sent to rs-notus
  message = g_string_new (NULL);
  g_string_printf (message,
                   "POST /notus/%s HTTP/%s\r\n"
                   "Host: %s:%d\r\n"
                   "user-agent: openvas\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Length %lu\r\n"
                   "X-API-KEY: %s\r\n\r\n%s",
                   os, notusdata->http_version, notusdata->host,
                   notusdata->port, strlen (json_pkglist),
                   prefs_get ("openvasd-apikey"), json_pkglist);
  g_debug ("Request:\n%s\n", message->str);

  // Create the socket
  sockfd = open_sock_opt_hn (notusdata->host, notusdata->port, SOCK_STREAM,
                             IPPROTO_IP, timeout);
  if (sockfd < 0)
    {
      g_message ("%s: Error creating socket", __func__);
      g_string_free (message, TRUE);
      g_free (json_pkglist);
      return NULL;
    }

  // Send the message to the server
  if (notusdata->tls)
    response = call_notus_via_https (sockfd, message, notusdata->alpn);
  else
    response = call_notus_via_http (sockfd, message);

  // cleanup
  shutdown (sockfd, SHUT_RDWR);
  close (sockfd);
  g_string_free (message, TRUE);
  g_free (json_pkglist);

  return response;
}

/** @brief Call notus and stores the results
 *
 *  @param ip_str Target's IP address.
 *  @param hostname Targer's hostname.
 *  @param pkg_list List of packages installed in the target. The packages are
 * "\n" separated.
 *  @param os Name of the target's operative sistem.
 *
 *  @result Count of stored results. -1 on error.
 */
int
call_rs_notus (const char *ip_str, const char *hostname, const char *pkg_list,
               const char *os)
{
  GString *response = NULL;
  gchar *body = NULL;
  advisories_t *advisories = NULL;
  int res_count = 0;
  if ((response = notus_get_response (pkg_list, os)) == NULL)
    return -1;

  gchar **head_body = g_strsplit (response->str, "\r\n\r\n", 1);
  body = g_strdup (head_body[1]);
  g_strfreev (head_body);
  g_string_free (response, TRUE);

  advisories = process_notus_response (body, strlen (body));

  for (size_t i = 0; i < advisories->count; i++)
    {
      advisory_t *advisory = advisories->advisories[i];
      gchar *buffer;
      GString *result = g_string_new (NULL);
      for (size_t j = 0; j < advisory->count; j++)
        {
          vuln_pkg_t *pkg = advisory->pkgs[j];
          GString *res = g_string_new (NULL);

          if (pkg->type == RANGE)
            {
              g_string_printf (res,
                               "\nVulnerable package: %s\n"
                               "Installed version: %s\n"
                               "Fixed version: <%s, >%s\n",
                               pkg->pkg_name, pkg->install_version,
                               pkg->range->start, pkg->range->stop);
            }
          else if (pkg->type == SINGLE)
            {
              g_string_printf (res,
                               "\nVulnerable package: %s\n"
                               "Installed version: %s\n"
                               "Fixed version: %s%s\n",
                               pkg->pkg_name, pkg->install_version,
                               pkg->version->specifier, pkg->version->version);
            }
          else
            {
              g_warning ("%s: Unknown fixed version type.", __func__);
              advisories_free (advisories);
              return -1;
            }
          g_string_append (result, g_strdup (res->str));
          g_string_free (res, TRUE);
        }

      // type|||IP|||HOSTNAME|||package|||OID|||the result message|||URI
      buffer = g_strdup_printf ("%s|||%s|||%s|||%s|||%s|||%s|||%s", "ALARM",
                                ip_str, hostname ? hostname : " ", "package",
                                advisory->oid, result->str, "");
      g_string_free (result, TRUE);
      kb_item_push_str_with_main_kb_check (get_main_kb (), "internal/results",
                                           buffer);
      res_count++;
      g_free (buffer);
    }

  advisories_free (advisories);
  return res_count;
}

#endif // End RSNOTUS
