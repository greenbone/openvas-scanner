/* OpenVAS
* $Id: oval_plugins.c 140 2006-05-31 15:24:25Z tarik $
* Description: Launches OVAL definitions.
*
* Authors: - Michael Wiegand <michael.wiegand@intevation.de>
*
* Copyright:
* Copyright (C) 2008 Intevation GmbH
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 or later,
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*/

/*
 * DISCLAIMER: This is just a proof-of-concept for OVAL support in OpenVAS.
 * It currently supports only a part of the objects specified in the OVAL
 * specification and requires a patched version of ovaldi, the OVAL definition
 * interpreter.
 */

#include <includes.h>
#include <nasl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include "corevers.h"
#include "log.h"
#include "pluginload.h"
#include "preferences.h"
#include "processes.h"


static void oval_thread (struct arglist *);
void ovaldi_launch (struct arglist * g_args);

// TODO: A better way to store the results of the XML parser would be to use the
// user_data pointer provided by the glib XML parser.

/**
 * @brief Structure for plugin information.
 */
typedef struct
{
  gchar * id;
  gchar * oid;
  gchar * version;
  gchar * description;
  gchar * title;
} oval_plugin_t;

/**
 * @brief The current plugin/definition when parsing definitions.
 */
oval_plugin_t * current_plugin;

/**
 * @brief The list of plugins/definitions.
 */
GSList * plugin_list = NULL;

/**
 * @brief Structure for result information.
 */
typedef struct
{
  gchar * definition_id;
  gchar * result;
} oval_result_t;

/**
 * @brief The current result when parsing results.
 */
oval_result_t * current_result;

/**
 * @brief The list of results.
 */
GSList * result_list = NULL;

/**
 * @brief Possible states during XML parsing.
 */
typedef enum
{
  DESCRIPTION,
  DEFINITION,
  TITLE,
  RESULTS,
  RESULTS_DEFINITION,
  TOP
} state_t;

/**
 * @brief The current parser state during XML parsing.
 */
state_t parser_state = TOP;

/**
 * @brief Sets the internal state during XML parsing.
 *
 * @param state The state to be set.
 */
void
set_parser_state (state_t state)
{
  parser_state = state;
}

/**
 * @brief Prepares the launch of an external executable by dropping privileges.
 *
 * This function is called by the forked child just before it is executed. We
 * try to drop our root privileges and setuid to nobody to minimize the risk of
 * running an untrusted executable, in this case ovaldi.  NB: The current
 * implementation is somewhat linux-specific and may not work on other
 * platforms.
 * 
 * @param user_data Pointer to additional data passed by glib; currently unused.
 */
void
drop_privileges (gpointer user_data)
{
  struct passwd * nobody_pw = NULL;

  if (getuid () == 0)
    {
      log_write ("oval_plugins.c: Running as root, trying to drop privileges.\n");
      if ((nobody_pw = getpwnam ("nobody")))
        {
          if (setgid (nobody_pw->pw_gid) == 0)
            {
              log_write ("oval_plugins.c: Successfully dropped group privileges.\n");
            }
          else
            {
              log_write ("oval_plugins.c: WARNING: Could not drop group privileges!\n");
            }
          if (setuid (nobody_pw->pw_uid) == 0)
            {
              log_write ("oval_plugins.c: Successfully dropped user privileges.\n");
            }
          else
            {
              log_write ("oval_plugins.c: WARNING: Could not drop group privileges!\n");
            }
        }
      else
        {
          log_write ("oval_plugins.c: WARNING: Could not drop privileges; unable to get uid and gid for user nobody!\n");
        }
    }
  else
    {
      log_write ("oval_plugins.c: WARNING: Did not attempt to drop privileges since we do not seem to be running as root.\n");
    }
}

/**
 * @brief This function handles the opening tag of an XML element. 
 */
void
start_element (GMarkupParseContext *context, const gchar *element_name,
               const gchar **attribute_names, const gchar **attribute_values,
               gpointer user_data, GError **error)
{
  const gchar **name_cursor = attribute_names;
  const gchar **value_cursor = attribute_values;

  switch (parser_state)
    {
      case TOP:
        if (strcmp (element_name, "definition") == 0)
          {
            set_parser_state (DEFINITION);
            current_plugin = g_malloc (sizeof (oval_plugin_t));
            while (*name_cursor)
              {
                if (strcmp (*name_cursor, "id") == 0)
                  {
                    current_plugin->id = g_strrstr (g_strdup (*value_cursor), ":") + 1;
                    // TODO: This currently assigns only IDs in the range intended for
                    // RedHat security advisories.
                    current_plugin->oid = g_strconcat ("1.3.6.1.4.1.25623.1.2.2312.",
                                                       current_plugin->id, NULL);
                  }
                if (strcmp (*name_cursor, "version") == 0)
                  current_plugin->version = g_strdup (*value_cursor);
                name_cursor++;
                value_cursor++;
              }
          }
        if (strcmp (element_name, "results") == 0)
          set_parser_state (RESULTS);
        break;
      case DEFINITION:
        if (strcmp (element_name, "description") == 0)
          set_parser_state (DESCRIPTION);
        if (strcmp (element_name, "title") == 0)
          set_parser_state (TITLE);
        break;
      case RESULTS:
        if (strcmp (element_name, "definition") == 0)
          {
            set_parser_state (RESULTS_DEFINITION);
            current_result = g_malloc (sizeof (oval_result_t));
            while (*name_cursor)
              {
                if (strcmp (*name_cursor, "definition_id") == 0)
                  {
                    current_result->definition_id = g_strdup (*value_cursor);
                  }
                if (strcmp (*name_cursor, "result") == 0)
                  {
                    current_result->result = g_strdup (*value_cursor);
                  }
                name_cursor++;
                value_cursor++;
              }
          }
        break;
      default:
        break;
    }
}

/**
 * @brief This function handles the text content of an XML element.
 *
 */
void
text (GMarkupParseContext *context, const gchar *text, gsize text_len,
      gpointer user_data, GError **error)
{
  switch (parser_state)
    {
      case DESCRIPTION:
        // NOTE: This currently cuts off descriptions longer than the maximum
        // length specified in libopenvas/store_internal.h
        current_plugin->description = g_strndup (text, 3190);
        break;
      case TITLE:
          {
            int i;
            gchar **title_split = g_strsplit (text, "\n", 0);
            if (g_strv_length (title_split) > 1)
              {
                for (i = 0; i < g_strv_length (title_split); i++)
                  {
                    g_strstrip (title_split[i]);
                  }
                current_plugin->title = g_strjoinv (" ", title_split);
              }
            else
              {
                current_plugin->title = g_strdup (title_split[0]);
              }
            g_strfreev (title_split);
          }
        break;
      default:
        break;
    }
}

/**
 * @brief This function handles the closing tag of an XML element.
 */
void
end_element (GMarkupParseContext *context, const gchar *element_name,
             gpointer user_data, GError **error)
{
  switch (parser_state)
    {
      case DESCRIPTION:
        if (strcmp (element_name, "description") == 0)
          set_parser_state (DEFINITION);
        break;
      case DEFINITION:
        if (strcmp (element_name, "definition") == 0)
          {
            plugin_list = g_slist_append (plugin_list, current_plugin);
            set_parser_state (TOP);
          }
        break;
      case TITLE:
        if (strcmp (element_name, "title") == 0)
          set_parser_state (DEFINITION);
        break;
      case RESULTS:
        if (strcmp (element_name, "results") == 0)
          set_parser_state (TOP);
        break;
      case RESULTS_DEFINITION:
        if (strcmp (element_name, "definition") == 0)
          {
            result_list = g_slist_append (result_list, current_result);
            set_parser_state (RESULTS);
          }
        break;
      default:
        break;
    }
}

/**
 * @brief Initialize the plugin class.
 */
pl_class_t*
oval_plugin_init (struct arglist* prefs, struct arglist* args)
{
  return &oval_plugin_class;
}

/**
 * @brief Add a single OVAL definition file to the list of available NVTs.
 */
struct arglist *
oval_plugin_add (char * folder, char * name,
                 struct arglist * plugins,
                 struct arglist * preferences)
{
  char fullname[PATH_MAX+1];
  struct arglist * args = NULL;
  struct arglist * prev_plugin = NULL;
  GMarkupParser parser; 
  GMarkupParseContext *context = NULL;
  gchar *filebuffer = NULL;
  gsize length = 0;
  gchar * title = NULL;
  gchar * descriptions = NULL;
  gchar * description = NULL;
  int i;

  if (plugin_list != NULL)
    {
      g_slist_free (plugin_list);
      plugin_list = NULL;
    }

  snprintf (fullname, sizeof (fullname), "%s/%s", folder, name);

  if (preferences_nasl_no_signature_check (preferences) == 0 
      && nasl_verify_signature (fullname) != 0)
    {
      log_write("%s: signature of nvt could not been verified/ is missing.",
                fullname);
      return NULL;
    }

  args = store_load_plugin (folder, name, preferences);

  if (args == NULL)
    {
      char* sign_fprs = nasl_extract_signature_fprs (fullname );
      // If server accepts signed plugins only, discard if signature file missing.
      if (preferences_nasl_no_signature_check (preferences) == 0 
          && sign_fprs == NULL)
        {
          printf ("%s: nvt is not signed and thus ignored\n", fullname);
          return NULL;
        }
      else if (sign_fprs == NULL)
        {
          sign_fprs = "";
        }

      parser.start_element = start_element;
      parser.end_element = end_element;
      parser.text = text;
      parser.passthrough = NULL;
      parser.error = NULL;

      if (!g_file_get_contents (fullname, &filebuffer, &length, NULL))
        {
          log_write ("oval_plugin_add: File %s not found", fullname);
          return NULL;
        }

      context = g_markup_parse_context_new (&parser, 0, NULL, NULL);
      g_markup_parse_context_parse (context, filebuffer, length, NULL);
      g_free (filebuffer);
      g_markup_parse_context_free (context);

      if (g_slist_length (plugin_list) == 0)
        {
          log_write ("oval_plugin_add: Empty plugin_list, no definitions found in %s!",
                     fullname);
          return NULL;
        }

      oval_plugin_t * first_plugin = g_slist_nth_data  (plugin_list, 0);
      if (g_slist_length (plugin_list) > 1)
        {
          gchar ** title_array;
          title_array = g_malloc0 ((g_slist_length (plugin_list) + 1) * sizeof (gchar *));

          for (i = 0; i < g_slist_length (plugin_list); i++)
            {
              oval_plugin_t * plug = g_slist_nth_data (plugin_list, i);
              title_array[i] = g_strdup_printf ("%s\n", plug->title);
            }
          title_array[i] = NULL;
          descriptions = g_strjoinv (NULL, title_array);
          if (strlen (descriptions) > 3100)
            {
              description = g_strconcat ("This OVAL file contains the following definitions:\n",
                                         g_strndup (descriptions, 3100),
                                         "\n(list cut due to memory limitations)", NULL);
            }
          else
            {
              description = g_strconcat ("This OVAL file contains the following definitions:\n",
                                         g_strdup (descriptions), NULL);
            }
          g_free (descriptions);
          g_strfreev (title_array);
          title = g_strdup_printf ("%s (%d OVAL definitions)", name,
                                   g_slist_length (plugin_list));
        }
      else
        {
          description = first_plugin->description;
          title = first_plugin->title;
        }

      args = emalloc (sizeof (struct arglist));

      plug_set_oid (args, g_strdup (first_plugin->oid));
      plug_set_version (args, first_plugin->version);
      plug_set_name (args, title, NULL);
      plug_set_description (args, description, NULL);
      plug_set_category (args, ACT_END);
      plug_set_family (args, "OVAL definitions", NULL);

      plug_set_path (args, g_build_filename (folder, name, NULL));

      plug_set_sign_key_ids (args, sign_fprs);

      store_plugin (args, name);
      args = store_load_plugin (folder, name, preferences);
    }

  if (args != NULL)
    {
      prev_plugin = arg_get_value (plugins, name);
      if (prev_plugin == NULL)
        arg_add_value (plugins, name, ARG_ARGLIST, -1, args);
      else
        {
          plugin_free (prev_plugin);
          arg_set_value (plugins, name, -1, args);
        }
    }
  return args;
}

/**
 * @brief Launches an OVAL plugin.
 */
int
oval_plugin_launch (struct arglist * globals, struct arglist * plugin,
                    struct arglist * hostinfos, struct arglist * preferences,
                    struct kb_item ** kb, char * name)
{
  nthread_t module;
  arg_add_value (plugin, "globals", ARG_ARGLIST, -1, globals);
  arg_add_value (plugin, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
  arg_add_value (plugin, "name", ARG_STRING, strlen (name), name);
  arg_set_value (plugin, "preferences", -1, preferences);
  arg_add_value (plugin, "key", ARG_PTR, -1, kb);

  // TODO felix get Preferences from global context and check the signature
  //if (nasl_verify_signature (arg_get_value (g_args, "name")))
  //  post_log (g_args, 0, "Attempt to start signed oval plugin.");

  module = create_process ((process_func_t)oval_thread, plugin);
  return module;
}

/**
 * @brief Creates a thread for an OVAL plugin.
 */
static void
oval_thread (struct arglist * g_args)
{
  struct arglist * args = arg_get_value (g_args, "args");
  int soc = GPOINTER_TO_SIZE (arg_get_value (g_args, "SOCKET"));
  struct arglist * globals = arg_get_value (args, "globals");

  soc = dup2 (soc, 4);
  if (soc < 0)
    {
      log_write ("oval_thread: dup2() failed ! - can not launch the plugin\n");
      return;
    }
  arg_set_value (args, "SOCKET", sizeof (gpointer), GSIZE_TO_POINTER (soc));
  arg_set_value (globals, "global_socket", sizeof (gpointer), GSIZE_TO_POINTER (soc));

  setproctitle ("testing %s (%s)",
                (char*) arg_get_value (arg_get_value (args, "HOSTNAME"), "NAME"),
                (char*) arg_get_value (g_args, "name"));
  signal (SIGTERM, _exit);

  ovaldi_launch (g_args);
  internal_send (soc, NULL, INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
}

/**
 * @brief Launches ovaldi.
 *
 * This function will generate an OVAL system characteristics document from the
 * data available in the knowledge base (KB), run ovaldi and return the results
 * to the client.
 */
void
ovaldi_launch (struct arglist * g_args)
{
  gchar * sc_filename;
  gchar * results_filename;
  FILE * sc_file;
  time_t t;
  struct tm *tmp;
  char timestr[20];
  // struct arglist * args = arg_get_value (g_args, "args");
  struct kb_item ** kb = arg_get_value (g_args, "key");
  gchar * basename = g_strrstr (g_strdup ((char*) arg_get_value (g_args, "name")), "/") + 1;
  gchar * result_string = NULL;
  gchar * folder = g_strndup ((char*) arg_get_value (g_args, "name"),
                              strlen ((char*) arg_get_value (g_args, "name")) - strlen (basename));

  sc_filename = g_strconcat (folder, "sc-out.xml", NULL);
  log_write ("SC Filename: %s\n", sc_filename);
  results_filename = "/tmp/results.xml";

  if (g_file_test (results_filename, G_FILE_TEST_EXISTS))
    {
      log_write ("Found existing results file in %s, deleting it to avoid conflicts.", results_filename);
      g_unlink (results_filename);
    }

  sc_file = fopen (sc_filename, "w");
  if (sc_file == NULL)
    {
      result_string = g_strdup_printf ("Could not launch ovaldi for OVAL definition %s: Could not create SC file.\n\n",
                                       basename);
      post_note (g_args, 0, result_string);
      efree (&sc_filename);
    }
  else
    {
      fprintf (sc_file, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n");
    fprintf(sc_file, "<oval_system_characteristics xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5\" xmlns:linux-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\" xmlns:oval=\"http://oval.mitre.org/XMLSchema/oval-common-5\" xmlns:oval-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5\" xmlns:unix-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5 oval-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix unix-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux linux-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows windows-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent independent-system-characteristics-schema.xsd\">\n\n");

      t = time (NULL);
      tmp = localtime (&t);
      strftime (timestr, sizeof (timestr), "%FT%T", tmp);
      fprintf (sc_file, "\t<generator>\n\t\t<oval:product_name>%s</oval:product_name>\n\t\t<oval:product_version>%s</oval:product_version>\n\t\t<oval:schema_version>5.4</oval:schema_version>\n\t\t<oval:timestamp>%s</oval:timestamp>\n\t\t<vendor>The OpenVAS Project</vendor>\n\t</generator>\n\n", PROGNAME, OPENVAS_FULL_VERSION, timestr);

      // TODO: Replace dummy values with real values; inserted dummy value
      // since ovaldi does not like empty elements here.
      fprintf (sc_file, "\t<system_info>\n\t\t<os_name>dummy</os_name>\n\t\t<os_version>dummy</os_version>\n\t\t<architecture>dummy</architecture>\n\t\t<primary_host_name>dummy</primary_host_name>\n\t\t<interfaces>\n\t\t\t<interface>\n\t\t\t\t<interface_name>dummy</interface_name>\n\t\t\t\t<ip_address>dummy</ip_address>\n\t\t\t\t<mac_address>dummy</mac_address>\n\t\t\t</interface>\n\t\t</interfaces>\n\t</system_info>\n\n");

      GString *system_data = g_string_new ("\t<system_data>\n");
      GString *collected_objects= g_string_new ("\t<collected_objects>\n");

      int i = 1;

      // Get the open TCP ports from the KB and build <inetlisteningserver_item>
      struct kb_item * res = kb_item_get_pattern (kb, "Ports/tcp/*");

      while (res)
        {
          g_string_append_printf (system_data, "\t\t<inetlisteningserver_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
          g_string_append_printf (system_data, "\t\t\t<protocol>tcp</protocol>\n");
          g_string_append_printf (system_data, "\t\t\t<local_address/>\n");
          g_string_append_printf (system_data, "\t\t\t<local_port>%s</local_port>\n", g_strrstr (res->name, "/") + 1);
          g_string_append_printf (system_data, "\t\t\t<local_full_address/>\n\t\t\t<program_name/>\n\t\t\t<foreign_address/>\n\t\t\t<foreign_port/>\n\t\t\t<foreign_full_address/>\n\t\t\t<pid/>\n\t\t\t<user_id/>\n");
          g_string_append_printf (system_data, "\t\t</inetlisteningserver_item>\n");
          i++;
          res = res->next;
        }

      // Collect user_items
      gchar *users = kb_item_get_str(kb, "USER_SID/USERS");
      if (users == NULL)
        {
          log_write ("Did not find USER_SID/USERS!");
        }
      else
        {
          log_write ("Found USER_SID/USERS: %s", users);
          gchar **user_array = g_strsplit (users, ",", 0);
          if (g_strv_length (user_array) > 0)
            {
              int k;
              for (k = 0; k < g_strv_length (user_array); k++)
                {
                  gchar *username = user_array[k];
                  gchar *result = kb_item_get_str(kb, g_strconcat ("USER_SID/", username,
                                                                   NULL)); 
                  if (result == NULL)
                    {
                      log_write ("Could not get a kb_item for USER_SID/%s.", username);
                    }
                  else
                    {
                      log_write ("Got a kb_item for USER_SID/%s: %s", username,
                                 result);
                      gboolean enabled = FALSE;
                      gchar **groups = NULL;
                      gchar **items = g_strsplit (result, ",", 0);
                      if (g_ascii_strcasecmp (items[1], " Enabled") == 0)
                        {
                          log_write ("%s is enabled.", username);
                          enabled = TRUE;
                        }
                      else
                        {
                          if (g_ascii_strcasecmp (items[1], " Disabled") == 0)
                            {
                              log_write ("%s is disabled.", username);
                              enabled = FALSE;
                            }
                          else
                            {
                              log_write ("%s is neither enabled nor disabled???", username);
                            }
                        }
                      if (g_strv_length (items) > 2)
                        {
                          int j;
                          groups = g_malloc0 ((g_strv_length (items) - 1) * sizeof (gchar *));
                          for (j = 2; j < g_strv_length (items); j++)
                            {
                              log_write ("%s is in group %s.", username, items[j]);
                              groups[j - 2] = g_strdup (items[j]);
                              g_strstrip (groups[j - 2]);
                            }
                          groups[j - 2] = NULL;
                        }

                      g_string_append_printf (system_data, "\t\t<user_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows\">\n", i);
                      g_string_append_printf (system_data, "\t\t\t<user>%s</user>\n", username);
                      // Workaround for PoC to create a collected_objects that
                      // will make ovaldi happy
                      if (g_ascii_strcasecmp (username, "Administrator") == 0)
                        {
                          g_string_append_printf (collected_objects, "\t\t<object flag=\"complete\" id=\"oval:gov.nist.fdcc.xp:obj:60221\" version=\"1\">\n");
                          g_string_append_printf (collected_objects, "\t\t\t<reference item_ref=\"%d\"/>\n", i);
                          g_string_append_printf (collected_objects, "\t\t</object>\n");
                        }
                      if (enabled == TRUE)
                        {
                          g_string_append_printf (system_data, "\t\t\t<enabled datatype=\"boolean\">true</enabled>\n");
                        }
                      else
                        {
                          g_string_append_printf (system_data, "\t\t\t<enabled datatype=\"boolean\">false</enabled>\n");
                        }
                      if (groups != NULL)
                        {
                          int j;
                          for (j = 0; j < g_strv_length (groups); j++)
                            {
                              g_string_append_printf (system_data, "\t\t\t<group>%s</group>\n",
                                       groups[j]);
                            }
                        }
                      g_string_append_printf (system_data, "\t\t</user_item>\n");
                      i++;
                    }
                }
            }
        }

      // Collect sid_items
      gchar *sid_item_users = kb_item_get_str(kb, "SID_ITEM/USERS");
      if (sid_item_users == NULL)
        {
          log_write ("Did not find SID_ITEM/USERS!");
        }
      else
        {
          log_write ("Found SID_ITEM/USERS: %s", sid_item_users);
          gchar **user_array = g_strsplit (sid_item_users, ",", 0);
          if (g_strv_length (user_array) > 0)
            {
              int k;
              for (k = 0; k < g_strv_length (user_array); k++)
                {
                  gchar *username = user_array[k];
                  gchar *result = kb_item_get_str(kb, g_strconcat ("SID_ITEM/", username,
                                                                   NULL)); 
                  if (result == NULL)
                    {
                      log_write ("Could not get a kb_item for SID_ITEM/%s.", username);
                    }
                  else
                    {
                      log_write ("Got a kb_item for SID_ITEM/%s: %s", username,
                                 result);
                      gchar **items = g_strsplit (result, ",", 0);
                      if (g_strv_length (items) == 3)
                        {
                          g_string_append_printf (system_data, "\t\t<sid_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows\">\n", i);
                          g_string_append_printf (system_data, "\t\t\t<trustee_name>%s</trustee_name>\n", g_strstrip (items[0]));
                          g_string_append_printf (system_data, "\t\t\t<trustee_sid>%s</trustee_sid>\n", g_strstrip (items[1]));
                          g_string_append_printf (system_data, "\t\t\t<trustee_domain>%s</trustee_domain>\n", g_strstrip (items[2]));
                          g_string_append_printf (system_data, "\t\t</sid_item>\n");
                          // Workaround for PoC to create a collected_objects that
                          // will make ovaldi happy
                          if (g_ascii_strcasecmp (items[0], "Administrator") == 0)
                            {
                              g_string_append_printf (collected_objects, "\t\t<object flag=\"complete\" id=\"oval:gov.nist.fdcc.xp:obj:12\" version=\"1\">\n");
                              g_string_append_printf (collected_objects, "\t\t\t<reference item_ref=\"%d\"/>\n", i);
                              g_string_append_printf (collected_objects, "\t\t</object>\n");
                            }
                          if (g_ascii_strcasecmp (items[0], "Gast") == 0)
                            {
                              g_string_append_printf (collected_objects, "\t\t<object flag=\"complete\" id=\"oval:gov.nist.fdcc.xp:obj:6\" version=\"1\">\n");
                              g_string_append_printf (collected_objects, "\t\t\t<reference item_ref=\"%d\"/>\n", i);
                              g_string_append_printf (collected_objects, "\t\t</object>\n");
                            }
                          i++;
                        }
                      else
                        {
                          log_write ("Expected 3 items in SID_ITEM, but found %d!", g_strv_length (items));
                        }

                    }
                }
            }
        }
      // Test if ssh/login/release is present in the KB; this means that an
      // information gathering plugin has collected release and possibly package
      // information from the remote system.
      if (kb_item_get_str (kb, "ssh/login/release") == NULL)
        {
          log_write ("Could not identify release, not collecting package information.\n");
          result_string = g_strdup_printf ("Could not collect remote package information for OVAL definition %s: Result may be incomplete.\n\n", basename);
          post_note (g_args, 0, result_string);

        }
      else
        {
          // TODO: Right now, every plugin needs to parse the package data in the KB
          // by itself and dependent on the detected release since they are not
          // stored in a structured way by the collecting plugin.
          if (strstr (kb_item_get_str (kb, "ssh/login/release"), "DEB") != NULL)
            {
              log_write ("Detected Debian package information\n");
              char * packages_str = kb_item_get_str (kb, "ssh/login/packages");

              if (packages_str)
                {
                  gchar ** package = g_strsplit (packages_str, "\n", 0);
                  int j = 5;
                  while (package[j] != NULL)
                    {
                      strtok (package[j], " ");
                      g_string_append_printf (system_data, "\t\t<dpkginfo_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
                      g_string_append_printf (system_data, "\t\t\t<name>%s</name>\n", strtok (NULL, " "));
                      g_string_append_printf (system_data, "\t\t\t<arch/>\n");
                      g_string_append_printf (system_data, "\t\t\t<epoch/>\n");
                      g_string_append_printf (system_data, "\t\t\t<release/>\n");
                      g_string_append_printf (system_data, "\t\t\t<version>%s</version>\n", strtok (NULL, " "));
                      g_string_append_printf (system_data, "\t\t\t<evr/>\n");
                      g_string_append_printf (system_data, "\t\t</dpkginfo_item>\n");
                      i++;
                      j++;
                    }
                  g_strfreev (package);
                }
            }

          // NOTE: This parser should work for other RPM-based distributions as well.
          if (strstr (kb_item_get_str (kb, "ssh/login/release"), "RH") != NULL)
            {
              log_write ("Detected RedHat package information\n");
              char * packages_str = kb_item_get_str (kb, "ssh/login/rpms");

              if (packages_str)
                {
                  gchar ** package = g_strsplit (packages_str, ";", 0);
                  int j = 1;
                  char keyid[17];
                  keyid[16] = '\0';
                  gchar * package_name;
                  gchar * package_version;
                  gchar * package_release;
                  while (package[j] != NULL)
                    {
                      gchar * pgpsig = strncpy (keyid, package[j] + strlen (package[j]) - 16, 16);
                      g_strchug (package[j]);
                      gchar ** package_data = g_strsplit (package[j], "~", 0);
                      if (package_data[0])
                        {
                          package_name = package_data[0];
                          package_version = package_data[1];
                          package_release = package_data[2];
                          g_string_append_printf (system_data, "\t\t<rpminfo_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
                          g_string_append_printf (system_data, "\t\t\t<name>%s</name>\n", package_name);
                          g_string_append_printf (system_data, "\t\t\t<arch/>\n");
                          g_string_append_printf (system_data, "\t\t\t<epoch/>\n");
                          g_string_append_printf (system_data, "\t\t\t<release>%s</release>\n", package_release);
                          g_string_append_printf (system_data, "\t\t\t<version>%s</version>\n", package_version);
                          g_string_append_printf (system_data, "\t\t\t<evr/>\n");
                          g_string_append_printf (system_data, "\t\t\t<signature_keyid>%s</signature_keyid>\n", pgpsig);
                          g_string_append_printf (system_data, "\t\t</rpminfo_item>\n");
                          i++;
                        }
                      j++;
                      g_strfreev (package_data);
                    }
                  g_strfreev (package);
                }
            }
        }

      g_string_append_printf (system_data, "\t</system_data>\n\n");
      g_string_append_printf (collected_objects, "\t</collected_objects>\n\n");

      fprintf (sc_file, collected_objects->str);
      fprintf (sc_file, system_data->str);
      fprintf (sc_file, "</oval_system_characteristics>\n");
      g_string_free (collected_objects, TRUE);
      g_string_free (system_data, TRUE);
    }
  if (sc_file != NULL)
    fclose (sc_file);

  gchar ** argv = (gchar **) g_malloc (11 * sizeof (gchar *));
  argv[0] = g_strdup ("ovaldi");
  argv[1] = g_strdup ("-m");  // Do not check OVAL MD5 signature
  argv[2] = g_strdup ("-o");  // Request the use of _this_ plugin
  argv[3] = g_strdup ((char*) arg_get_value (g_args, "name"));
  argv[4] = g_strdup ("-i");  // Request the use of the system characteristics retrieved from the KB
  argv[5] = g_strdup (sc_filename);
  argv[6] = g_strdup ("-r");  // Store the scan results where we can parse them
  argv[7] = g_strdup (results_filename);
  argv[8] = g_strdup ("-a");  // Path to the directory that contains the OVAL schema
  argv[9] = g_strdup (folder);
  argv[10] = NULL;
  //   log_write ("Launching ovaldi with: %s\n", g_strjoinv (" ", argv));

  if (g_spawn_sync (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, drop_privileges, NULL,
                    NULL, NULL, NULL, NULL))
    {
      GMarkupParser parser; 
      GMarkupParseContext *context = NULL;
      gchar *filebuffer = NULL;
      gsize length = 0;
      int i;

      parser.start_element = start_element;
      parser.end_element = end_element;
      parser.text = text;
      parser.passthrough = NULL;
      parser.error = NULL;

      if (!g_file_get_contents (results_filename, &filebuffer, &length, NULL))
        {
          result_string = g_strdup_printf ("Could not return results for OVAL definition %s: Results file not found.\n\n",
                                           basename);
          post_note (g_args, 0, result_string);
          log_write ("Results file %s not found!\n", results_filename);
        }
      else
        {
          context = g_markup_parse_context_new (&parser, 0, NULL, NULL);
          g_markup_parse_context_parse (context, filebuffer, length, NULL);
          g_free (filebuffer);
          g_markup_parse_context_free (context);

          if (g_slist_length (result_list) == 0)
            {
              log_write ("oval_result_add: Empty result_list, no results found in %s!", basename);
            }

          oval_result_t * first_result = g_slist_nth_data (result_list, 0);
          if (g_slist_length (result_list) > 1)
            {
              gchar ** result_array;
              result_array = g_malloc0 ((g_slist_length (result_list) + 1) * sizeof (gchar *));

              for (i = 0; i < g_slist_length (result_list); i++)
                {
                  oval_result_t * res = g_slist_nth_data (result_list, i);
                  result_array[i] = g_strdup_printf ("The OVAL definition %s returned the following result: %s\n",
                                                     res->definition_id, res->result);
                }
              result_array[i] = NULL;
              result_string = g_strjoinv (NULL, result_array);
              g_strfreev (result_array);
            }
          else
            {
              result_string = g_strdup_printf ("The OVAL definition %s returned the following result: %s\n\n",
                                               first_result->definition_id, first_result->result);
            }

          post_note (g_args, 0, result_string);
        }
    }
  else
    {
      result_string = g_strdup_printf ("Could not launch ovaldi for OVAL definition %s: Launch failed. (Is ovaldi in your PATH?)\n\n",
                                       basename);
      post_note (g_args, 0, result_string);
      log_write ("Could not launch ovaldi!\n");
    }
  g_strfreev (argv);
  g_free (result_string);
}

pl_class_t oval_plugin_class = {
  NULL,
  ".oval",
  oval_plugin_init,
  oval_plugin_add,
  oval_plugin_launch,
};
