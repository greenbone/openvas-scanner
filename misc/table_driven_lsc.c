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
#include "plugutils.h"

#include <ctype.h> // for tolower()
#include <curl/curl.h>
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

/** @brief LSC ran or didn't
 * 0 didn't run. 1 ran.
 */
static int lsc_flag = 0;

/** @brief Set lsc_flag to 1
 */
void
set_lsc_flag (void)
{
  lsc_flag = 1;
}

/** @brief Get lsc_flag value.
 */
int
lsc_has_run (void)
{
  return lsc_flag;
}

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

#define RSNOTUS
#ifdef RSNOTUS
/** @brief Struct to hold necessary information to call and run notus
 *
 */
struct notus_info
{
  char *server; // original openvasd server URL
  char *schema; // schema is http or https
  char *host;   // server hostname
  char *alpn; // Application layer protocol negotiation: http/1.0, http/1.1, h2
  char *http_version; // same version as in application layer
  int port;           // server port
  int tls;            // 0: TLS encapsulation diable. Otherwise enable
};

typedef struct notus_info *notus_info_t;

/** @brief Initialize a notus info struct and stores the server URL
 *
 *  @param server Original server to store and to get the info from
 *
 *  @return the initialized struct. NULL on error.
 */
static notus_info_t
init_notus_info (const char *server)
{
  notus_info_t notusdata;
  notusdata = g_malloc0 (sizeof (struct notus_info));
  if (!notusdata)
    return NULL;
  notusdata->server = g_strdup (server);
  return notusdata;
}

/** @brief Free notus info structure
 *
 * @param notusdata The data to free()
 */
static void
free_notus_info (notus_info_t notusdata)
{
  if (notusdata)
    {
      g_free (notusdata->server);
      g_free (notusdata->schema);
      g_free (notusdata->host);
      g_free (notusdata->alpn);
      g_free (notusdata->http_version);
    }
}

/** @brief helper function to lower case
 *
 *  @param s the string to lower case
 *
 *  @return pointer to the modified string.
 */
static char *
help_tolower (char *s)
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
 * @return String in json format on success. Must be freed by caller. NULL on
 * error.
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
parse_server (notus_info_t *notusdata)
{
  CURLU *h = curl_url ();
  char *schema = NULL;
  char *host = NULL;
  char *port = NULL;

  if (!notusdata)
    return -1;

  if (curl_url_set (h, CURLUPART_URL, (*notusdata)->server, 0) > 0)
    {
      g_warning ("%s: Error parsing URL %s", __func__, (*notusdata)->server);
      return -1;
    }

  curl_url_get (h, CURLUPART_SCHEME, &schema, 0);
  curl_url_get (h, CURLUPART_HOST, &host, 0);
  curl_url_get (h, CURLUPART_PORT, &port, 0);

  if (!schema || !host)
    {
      g_warning ("%s: Invalid URL %s. It must be in format: "
                 "schema://host:port. E.g. http://localhost:8080",
                 __func__, (*notusdata)->server);
      curl_url_cleanup (h);
      curl_free (schema);
      curl_free (host);
      curl_free (port);
      return -1;
    }

  (*notusdata)->host = g_strdup (host);
  if (port)
    (*notusdata)->port = atoi (port);
  else if (g_strcmp0 (schema, "https"))
    (*notusdata)->port = 443;
  else
    (*notusdata)->port = 80;

  (*notusdata)->schema = g_strdup (help_tolower (schema));
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
      g_warning ("%s: Invalid openvasd server schema", (*notusdata)->server);
      curl_url_cleanup (h);
      curl_free (schema);
      curl_free (host);
      curl_free (port);
      return -1;
    }

  curl_url_cleanup (h);
  curl_free (schema);
  curl_free (host);
  curl_free (port);

  return 0;
}

/** @brief Fixed version format
 */
enum fixed_type
{
  UNKNOWN, // Unknown
  RANGE,   // Range of version which fixed the package
  SINGLE,  // A single version with a specifier (gt or lt)
};

/** @brief Fixed version
 */
struct fixed_version
{
  char *version;   // a version
  char *specifier; // a lt or gt specifier
};
typedef struct fixed_version fixed_version_t;

/** @brief Specify a version range
 */
struct version_range
{
  char *start; // <= the version
  char *stop;  // >= the version
};
typedef struct version_range version_range_t;

/** @brief Define a vulnerable package
 */
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

/** brief define an advisory with a list of vulnerable packages
 */
struct advisory
{
  char *oid;             // Advisory OID
  vuln_pkg_t *pkgs[100]; // list of vulnerable packages, installed version and
                         // fixed versions
  size_t count;          // Count of vulnerable packages this adivsory has
};

typedef struct advisory advisory_t;

/** brief define a advisories list
 */
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
                     sizeof (advisory_t));
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
 *  @return a vulnerable packages struct. Members are a copy of the passed
 *          parametes. They must be free separately.
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

/** @brief Define a string struct for storing the response.
 */
struct string
{
  char *ptr;
  size_t len;
};

/** @brief Initialize the string struct to hold the response
 *
 *  @param s[in/out] The string struct to be initialized
 */
static void
init_string (struct string *s)
{
  s->len = 0;
  s->ptr = g_malloc0 (s->len + 1);
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return;
    }
  s->ptr[0] = '\0';
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  struct string *s = struct_string;
  size_t new_len = s->len + size * nmemb;
  char *ptr_aux = g_realloc (s->ptr, new_len + 1);
  s->ptr = ptr_aux;
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0; // no memory left
    }
  memcpy (s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

/** @brief Send a request to the server
 *
 *  @param[in] notusdata Structure containing information necessary for the
request
 *  @param[in] os Target's operative system. Necessary for the URL path part.
 *  @param[in] pkg_list The package list installed in the target, to be checked
 *  @param[out] response The string containing the results in json format.
 *
 *  @return the http code or -1 on error
 */
static long
send_request (notus_info_t notusdata, const char *os, const char *pkg_list,
              char **response)
{
  CURL *curl;
  GString *url = NULL;
  long http_code = -1;
  struct string resp;
  struct curl_slist *customheader = NULL;
  char *os_aux;
  GString *xapikey = NULL;

  if ((curl = curl_easy_init ()) == NULL)
    {
      g_warning ("Not possible to initialize curl library");
      return http_code;
    }

  url = g_string_new (notusdata->server);
  g_string_append (url, "/notus/");

  //
  os_aux = help_tolower (g_strdup (os));
  for (size_t i = 0; i < strlen (os_aux); i++)
    {
      if (os_aux[i] == ' ')
        os_aux[i] = '_';
    }

  g_string_append (url, os_aux);
  g_free (os_aux);

  g_debug ("%s: URL: %s", __func__, url->str);
  // Set URL
  if (curl_easy_setopt (curl, CURLOPT_URL, g_strdup (url->str)) != CURLE_OK)
    {
      g_warning ("Not possible to set the URL");
      curl_easy_cleanup (curl);
      return http_code;
    }
  g_string_free (url, TRUE);

  // Accept an insecure connection. Don't verify the server certificate
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);

  // Set API KEY
  if (prefs_get ("x-apikey"))
    {
      xapikey = g_string_new ("X-APIKEY: ");
      g_string_append (xapikey, prefs_get ("x-apikey"));
      customheader = curl_slist_append (customheader, g_strdup (xapikey->str));
      g_string_free (xapikey, TRUE);
    }
  // SET Content type
  customheader =
    curl_slist_append (customheader, "Content-Type: application/json");
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, customheader);
  // Set body
  curl_easy_setopt (curl, CURLOPT_POSTFIELDS, pkg_list);
  curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (pkg_list));

  // Init the struct where the response is stored and set the callback function
  init_string (&resp);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, response_callback_fn);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &resp);

  int ret = CURLE_OK;
  if ((ret = curl_easy_perform (curl)) != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %d", __func__, ret);
      curl_easy_cleanup (curl);
      g_free (resp.ptr);
      return http_code;
    }

  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup (curl);
  g_debug ("Server response %s", resp.ptr);
  *response = g_strdup (resp.ptr);
  g_free (resp.ptr);
  // already free()'ed with curl_easy_cleanup().

  return http_code;
}

/** @brief Sent the installed package list and OS to notus
 *
 *  @param pkg_list Installed package list
 *  @param os The target's OS
 *
 *  @return String containing the server response or NULL
 *          Must be free()'ed by the caller.
 */
static char *
notus_get_response (const char *pkg_list, const char *os)
{
  const char *server = NULL;
  char *json_pkglist;
  char *response = NULL;
  notus_info_t notusdata;

  // Parse the server and get the port, host, schema
  // and necessary information to build the message
  server = prefs_get ("openvasd_server");
  notusdata = init_notus_info (server);

  if (parse_server (&notusdata) < 0)
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

  if (send_request (notusdata, os, json_pkglist, &response) == -1)
    g_warning ("Error sending request to openvasd");

  free_notus_info (notusdata);
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
static int
call_rs_notus (const char *ip_str, const char *hostname, const char *pkg_list,
               const char *os)
{
  char *body = NULL;
  advisories_t *advisories = NULL;
  int res_count = 0;
  if ((body = notus_get_response (pkg_list, os)) == NULL)
    return -1;

  advisories = process_notus_response (body, strlen (body));

  // Process the advisories, generate results and store them in the kb
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
                               "Installed version:    %s\n"
                               "Fixed version:      <=%s\n"
                               "Fixed version:      >=%s\n",
                               pkg->pkg_name, pkg->install_version,
                               pkg->range->start, pkg->range->stop);
            }
          else if (pkg->type == SINGLE)
            {
              int spec_len = 8 - (int) strlen (pkg->version->specifier);
              g_string_printf (res,
                               "\nVulnerable package:%*s%s\n"
                               "Installed version:%*s%s\n"
                               "Fixed version:%*s%s%s\n",
                               3, "", pkg->pkg_name, 4, "",
                               pkg->install_version, spec_len, "",
                               pkg->version->specifier, pkg->version->version);
            }
          else
            {
              g_warning ("%s: Unknown fixed version type for advisory %s",
                         __func__, advisory->oid);
              g_string_free (result, TRUE);
              advisories_free (advisories);
              return -1;
            }
          g_string_append (result, res->str);
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
  int err = 0;
  if (!os_release || !package_list)
    return 0;

  if (prefs_get ("openvasd_server"))
    {
      g_message ("Running Notus for %s via openvasd", ip_str);
      err = call_rs_notus (ip_str, hostname, package_list, os_release);

      return err;
    }
  else
    {
      gchar *json_str;
      gchar *topic;
      gchar *payload;
      gchar *status = NULL;
      int topic_len;
      int payload_len;

      // Subscribe to status topic
      err = mqtt_subscribe ("scanner/status");
      if (err)
        {
          g_warning ("%s: Error starting lsc. Unable to subscribe", __func__);
          return -1;
        }
      /* Get the OS release. TODO: have a list with supported OS. */

      json_str = make_table_driven_lsc_info_json_str (scan_id, ip_str, hostname,
                                                      os_release, package_list);

      // Run table driven lsc
      if (json_str == NULL)
        return -1;

      g_message ("Running Notus for %s", ip_str);
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
          err = mqtt_retrieve_message (&topic, &topic_len, &payload,
                                       &payload_len, 60000);
          if (err == -1 || err == 1)
            {
              g_warning ("%s: Unable to retrieve status message from notus. %s",
                         __func__, err == 1 ? "Timeout after 60 s." : "");
              return -1;
            }

          // Get status if it belongs to corresponding scan and host
          // Else wait for next status message
          status = get_status_of_table_driven_lsc_from_json (
            scan_id, ip_str, payload, payload_len);

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
                  g_warning (
                    "%s: Unable to retrieve status message from notus.",
                    __func__);
                  return -1;
                }
              if (err == 1)
                {
                  g_warning (
                    "%s: Unablet to retrieve message. Timeout after 60s.",
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
          g_warning ("%s: Unable to start lsc. Got status: %s", __func__,
                     status);
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
    }
  return err;
}
