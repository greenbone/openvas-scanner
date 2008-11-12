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
#include "pluginload.h"
#include "log.h"
#include <glib.h>
#include "processes.h"
#include "corevers.h"

static void oval_thread(struct arglist *);
void ovaldi_launch(struct arglist * g_args);

// TODO: A better way to store the results of the XML parser would be to use the
// user_data pointer provided by the glib XML parser.
gchar * id;
gchar * oid;
gchar * version;
gchar * description;
gchar * title;
gboolean in_description = FALSE;
gboolean in_definition = FALSE;
gboolean in_title = FALSE;
gboolean in_results = FALSE;
gboolean in_results_definition = FALSE;
gchar * result;

void child_setup (gpointer user_data) {
  // This function is called by the forked child just before it is executed. We
  // try to drop our root privileges and setuid to nobody to minimize the
  // risk of running an untrusted ovaldi.
  // NB: The current implementation is somewhat linux-specific and may not work
  // on other platforms.

  struct passwd * nobody_pw = NULL;

  if(getuid() == 0)
  {
    log_write("oval_plugins.c: Running as root, trying to drop privileges.\n");
    if((nobody_pw = getpwnam("nobody")))
    {
      if(setgid(nobody_pw->pw_gid) == 0)
      {
        log_write("oval_plugins.c: Successfully dropped group privileges.\n");
      }
      else
      {
        log_write("oval_plugins.c: WARNING: Could not drop group privileges!\n");
      }
      if(setuid(nobody_pw->pw_uid) == 0)
      {
        log_write("oval_plugins.c: Successfully dropped user privileges.\n");
      }
      else
      {
        log_write("oval_plugins.c: WARNING: Could not drop group privileges!\n");
      }
    }
    else
    {
      log_write("oval_plugins.c: WARNING: Could not drop privileges; unable to get uid and gid for user nobody!\n");
    }
  }
  else
  {
    log_write("oval_plugins.c: WARNING: Did not attempt to drop privileges since we do not seem to be running as root.\n");
  }
}

void start_element (GMarkupParseContext *context, const gchar *element_name,
                    const gchar **attribute_names,
                    const gchar **attribute_values, gpointer user_data,
                    GError **error)
{
  const gchar **name_cursor = attribute_names;
  const gchar **value_cursor = attribute_values;

  if(!in_results && strcmp(element_name, "definition") == 0)
  {
    in_definition = TRUE;
    while(*name_cursor)
    {
      if (strcmp (*name_cursor, "id") == 0)
      {
        id = g_strrstr(g_strdup(*value_cursor), ":") + 1;
        // TODO: This currently assigns only IDs in the range intended for
        // RedHat security advisories.
        oid = g_strconcat("1.3.6.1.4.1.25623.1.2.2312.", id, NULL);
      }
      if (strcmp (*name_cursor, "version") == 0)
        version = g_strdup(*value_cursor);
      name_cursor++;
      value_cursor++;
    }
  }

  if(strcmp(element_name, "description") == 0)
    in_description = TRUE;

  if(strcmp(element_name, "title") == 0)
    in_title = TRUE;

  if(strcmp(element_name, "results") == 0)
    in_results = TRUE;

  if(in_results && strcmp(element_name, "definition") == 0)
  {
    in_results_definition = TRUE;
    while(*name_cursor)
    {
      if (strcmp (*name_cursor, "result") == 0)
        result = g_strdup(*value_cursor);

      name_cursor++;
      value_cursor++;
    }
  }
}

void text(GMarkupParseContext *context, const gchar *text, gsize text_len,
          gpointer user_data, GError **error)
{
  if (in_description)
  {
    // NOTE: This currently cuts off descriptions longer than the maximum length
    // specified in libopenvas/store_internal.h
    description = g_strndup(text, 3190);
  }
  if (in_title)
  {
    title = g_strndup(text, text_len);
    g_strdelimit(title, "\n", ' ');
  }
}

void end_element (GMarkupParseContext *context, const gchar *element_name,
                  gpointer user_data, GError **error)
{
  in_description = FALSE;
  in_definition = FALSE;
  in_title = FALSE;
  if(strcmp(element_name, "results") == 0)
    in_results = FALSE;
  if(in_results && strcmp(element_name, "definition") == 0)
    in_results_definition = FALSE;
}

/*
 *  Initialize the plugin class
 */
pl_class_t* oval_plugin_init(struct arglist* prefs, struct arglist* args)
{
    return &oval_plugin_class;
}

/*
 * add *one* OVAL definition to the server list
 */
struct arglist * oval_plugin_add(char * folder, char * name,
                                 struct arglist * plugins,
                                 struct arglist * preferences)
{
  char fullname[PATH_MAX+1];
  struct arglist * args = NULL;
  struct arglist * prev_plugin = NULL;
  GMarkupParser parser; 
  GMarkupParseContext *context = NULL;
  gchar *filebuffer = NULL;
  guint length = 0;

  snprintf(fullname, sizeof(fullname), "%s/%s", folder, name);

  if ( preferences_nasl_no_signature_check(preferences) == 0 
       && nasl_verify_signature( fullname) != 0)
  {
    log_write("%s: signature of nvt could not been verified/ is missing.");
    return NULL;
  }

  args = store_load_plugin(folder, name, preferences);

  if(args == NULL)
  {
    char* sign_fprs = nasl_extract_signature_fprs( fullname );
    // If server accepts signed plugins only, discard if signature file missing.
    if(preferences_nasl_no_signature_check(preferences) == 0 && sign_fprs == NULL)
    {
      printf("%s: nvt is not signed and thus ignored\n", fullname);
      return NULL;
    }
    else if(sign_fprs == NULL)
    {
      sign_fprs = "";
    }

    // Parse plugin properties into arglist
    parser.start_element = start_element;
    parser.end_element = end_element;
    parser.text = text;
    parser.passthrough = NULL;
    parser.error = NULL;

    if(!g_file_get_contents(fullname, &filebuffer, &length, NULL))
    {
      log_write("oval_plugin_add: File %s not found", fullname);
      return NULL;
    }

    context = g_markup_parse_context_new(&parser, 0, NULL, NULL);
    g_markup_parse_context_parse(context, filebuffer, length, NULL);
    g_free(filebuffer);
    g_markup_parse_context_free(context);

    args = emalloc(sizeof(struct arglist));

    plug_set_oid(args, oid);

    plug_set_version(args, version);
    plug_set_name(args, title, NULL);
    plug_set_description(args, description, NULL);
    plug_set_category(args, ACT_END);
    plug_set_family(args, "OVAL definitions", NULL);

    plug_set_sign_key_ids(args, sign_fprs);

    store_plugin(args, name);
    args = store_load_plugin(folder, name, preferences);
  }

  if(args != NULL)
  {
    prev_plugin = arg_get_value(plugins, name);
    if(prev_plugin == NULL)
      arg_add_value(plugins, name, ARG_ARGLIST, -1, args);
    else
    {
      plugin_free(prev_plugin);
      arg_set_value(plugins, name, -1, args);
    }
  }
  return args;
}

/*
 * Launch an OVAL plugin
 */
int oval_plugin_launch(struct arglist * globals, struct arglist * plugin,
                       struct arglist * hostinfos, struct arglist * preferences,
                       struct kb_item ** kb, char * name)
{
  nthread_t module;
  arg_add_value(plugin, "globals", ARG_ARGLIST, -1, globals);
  arg_add_value(plugin, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
  arg_add_value(plugin, "name", ARG_STRING, strlen(name), name);
  arg_set_value(plugin, "preferences", -1, preferences);
  arg_add_value(plugin, "key", ARG_PTR, -1, kb);

  // TODO felix get preferences from global context and check the signature.
  // Otherwise a client can start unsigned oval plugins even if the server
  // preference is set to "no"!
  // if( nasl_verify_signature( arg_get_value(g_args, "name")) )
  //  post_log( g_args, 0, "Attempt to start signed oval plugin.");

  module = create_process((process_func_t)oval_thread, plugin);
  return module;
}

/*
 * Create a thread for the OVAL plugin
 */
static void oval_thread(struct arglist * g_args)
{
  struct arglist * args = arg_get_value(g_args, "args");
  int soc = (int)arg_get_value(g_args, "SOCKET");
  struct arglist * globals = arg_get_value(args, "globals");

  soc = dup2(soc, 4);
  if(soc < 0)
  {
    log_write("oval_thread: dup2() failed ! - can not launch the plugin\n");
    return;
  }
  arg_set_value(args, "SOCKET", sizeof(int), (void*)soc);
  arg_set_value(globals, "global_socket", sizeof(int), (void*)soc);

  setproctitle("testing %s (%s)",
               (char*)arg_get_value(arg_get_value(args, "HOSTNAME"), "NAME"),
               (char*)arg_get_value(g_args, "name"));
  signal(SIGTERM, _exit);

  ovaldi_launch(g_args);
  internal_send(soc, NULL, INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
}

/*
 * This function will generate an OVAL system characteristics document from the
 * data available in the knowledge base (KB), run ovaldi and return the results
 * to the client.
 */
void ovaldi_launch(struct arglist * g_args)
{
  gchar * sc_filename;
  gchar * results_filename;
  FILE * sc_file;
  time_t t;
  struct tm *tmp;
  char timestr[20];
  struct arglist * args = arg_get_value(g_args, "args");
  struct kbitem ** kb = arg_get_value(g_args, "key");
  gchar * basename = g_strrstr(g_strdup((char*)arg_get_value(g_args, "name")), "/") + 1;
  gchar * result_string = emalloc(256);
  gchar * folder = g_strndup((char*)arg_get_value(g_args, "name"), strlen((char*)arg_get_value(g_args, "name")) - strlen(basename));

  sc_filename = g_strconcat(folder, "sc-out.xml", NULL);
  log_write("SC Filename: %s\n", sc_filename);
  results_filename = "/tmp/results.xml";

  sc_file = fopen(sc_filename, "w");
  if(sc_file == NULL)
  {
    snprintf(result_string, 256, "Could not launch ovaldi for OVAL definition %s: Could not create SC file.\n\n", basename);
    post_note(g_args, 0, result_string);
    efree(&sc_filename);
  }
  else
  {
    fprintf(sc_file, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n");
    fprintf(sc_file, "<oval_system_characteristics xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5\" xmlns:linux-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\" xmlns:oval=\"http://oval.mitre.org/XMLSchema/oval-common-5\" xmlns:oval-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5\" xmlns:unix-sc=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5 oval-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix unix-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux linux-system-characteristics-schema.xsd\">\n\n");
    
    t = time(NULL);
    tmp = localtime(&t);
    strftime(timestr, sizeof(timestr), "%FT%T", tmp);
    fprintf(sc_file, "\t<generator>\n\t\t<oval:product_name>%s</oval:product_name>\n\t\t<oval:product_version>%s</oval:product_version>\n\t\t<oval:schema_version>5.4</oval:schema_version>\n\t\t<oval:timestamp>%s</oval:timestamp>\n\t\t<vendor>The OpenVAS Project</vendor>\n\t</generator>\n\n", PROGNAME, OPENVAS_FULL_VERSION, timestr);
    
    fprintf(sc_file, "\t<system_info>\n\t\t<os_name></os_name>\n\t\t<os_version></os_version>\n\t\t<architecture></architecture>\n\t\t<primary_host_name>%s</primary_host_name>\n\t\t<interfaces>\n\t\t\t<interface>\n\t\t\t\t<interface_name></interface_name>\n\t\t\t\t<ip_address></ip_address>\n\t\t\t\t<mac_address></mac_address>\n\t\t\t</interface>\n\t\t</interfaces>\n\t</system_info>\n\n", (char*)arg_get_value(arg_get_value(args, "HOSTNAME"), "NAME"));
    fprintf(sc_file, "\t<system_data>\n");

    int i = 1;

    // Get the open TCP ports from the KB and build <inetlisteningserver_item>
    struct kb_item * res = kb_item_get_pattern(kb, "Ports/tcp/*");

    while(res)
    {
      fprintf(sc_file, "\t\t<inetlisteningserver_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
      fprintf(sc_file, "\t\t\t<protocol>tcp</protocol>\n");
      fprintf(sc_file, "\t\t\t<local_address/>\n");
      fprintf(sc_file, "\t\t\t<local_port>%s</local_port>\n", g_strrstr(res->name, "/") + 1);
      fprintf(sc_file, "\t\t\t<local_full_address/>\n\t\t\t<program_name/>\n\t\t\t<foreign_address/>\n\t\t\t<foreign_port/>\n\t\t\t<foreign_full_address/>\n\t\t\t<pid/>\n\t\t\t<user_id/>\n");
      fprintf(sc_file, "\t\t</inetlisteningserver_item>\n");
      i++;
      res = res->next;
    }

    // Test if ssh/login/release is present in the KB; this means that an
    // information gathering plugin has collected release and possibly package
    // information from the remote system.
    if(kb_item_get_str(kb, "ssh/login/release") == NULL)
    {
      log_write("Could not identify release, not collecting package information.\n");
      snprintf(result_string, 256, "Could not collect remote package information for OVAL definition %s: Result may be incomplete.\n\n", basename);
      post_note(g_args, 0, result_string);

    }
    else
    {
      // TODO: Right now, every plugin needs to parse the package data in the KB
      // by itself and dependent on the detected release since they are not
      // stored in a structured way by the collecting plugin.
      if(strstr(kb_item_get_str(kb, "ssh/login/release"), "DEB") != NULL)
      {
        log_write("Detected Debian package information\n");
        char * packages_str = kb_item_get_str(kb, "ssh/login/packages");

        if(packages_str)
        {
          gchar ** package = g_strsplit(packages_str, "\n", 0);
          int j = 5;
          while(package[j] != NULL)
          {
            strtok(package[j], " ");
            fprintf(sc_file, "\t\t<dpkginfo_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
            fprintf(sc_file, "\t\t\t<name>%s</name>\n", strtok(NULL, " "));
            fprintf(sc_file, "\t\t\t<arch/>\n");
            fprintf(sc_file, "\t\t\t<epoch/>\n");
            fprintf(sc_file, "\t\t\t<release/>\n");
            fprintf(sc_file, "\t\t\t<version>%s</version>\n", strtok(NULL, " "));
            fprintf(sc_file, "\t\t\t<evr/>\n");
            fprintf(sc_file, "\t\t</dpkginfo_item>\n");
            i++;
            j++;
          }
          g_strfreev(package);
        }
      }

      // NOTE: This parser should work for other RPM-based distributions as well.
      if(strstr(kb_item_get_str(kb, "ssh/login/release"), "RH") != NULL)
      {
        log_write("Detected RedHat package information\n");
        char * packages_str = kb_item_get_str(kb, "ssh/login/rpms");

        if(packages_str)
        {
          gchar ** package = g_strsplit(packages_str, ";", 0);
          int j = 1;
          char keyid[17];
          keyid[16] = '\0';
          gchar * package_name;
          gchar * package_version;
          gchar * package_release;
          while(package[j] != NULL)
          {
            gchar * pgpsig = strncpy(keyid, package[j] + strlen(package[j]) - 16, 16);
            g_strchug(package[j]);
            gchar ** package_data = g_strsplit(package[j], "~", 0);
            if(package_data[0])
            {
              package_name = package_data[0];
              package_version = package_data[1];
              package_release = package_data[2];
              fprintf(sc_file, "\t\t<rpminfo_item id=\"%d\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n", i);
              fprintf(sc_file, "\t\t\t<name>%s</name>\n", package_name);
              fprintf(sc_file, "\t\t\t<arch/>\n");
              fprintf(sc_file, "\t\t\t<epoch/>\n");
              fprintf(sc_file, "\t\t\t<release>%s</release>\n", package_release);
              fprintf(sc_file, "\t\t\t<version>%s</version>\n", package_version);
              fprintf(sc_file, "\t\t\t<evr/>\n");
              fprintf(sc_file, "\t\t\t<signature_keyid>%s</signature_keyid>\n", pgpsig);
              fprintf(sc_file, "\t\t</rpminfo_item>\n");
              i++;
            }
            j++;
            g_strfreev(package_data);
          }
          g_strfreev(package);
        }
      }
    }

    fprintf(sc_file, "\t</system_data>\n\n");
    fprintf(sc_file, "</oval_system_characteristics>\n");
  }
  if(sc_file != NULL)
    fclose(sc_file);

  gchar ** argv = (gchar **)g_malloc (9 * sizeof (gchar *));
  argv[0] = g_strdup("ovaldi");
  argv[1] = g_strdup("-m");  // Do not check OVAL MD5 signature
  argv[2] = g_strdup("-o");  // Request the use of _this_ plugin
  argv[3] = g_strdup((char*)arg_get_value(g_args, "name"));
  argv[4] = g_strdup("-i");  // Request the use of the system characteristics retrieved from the KB
  argv[5] = g_strdup(sc_filename);
  argv[6] = g_strdup("-r");  // Store the scan results where we can parse them
  argv[7] = g_strdup(results_filename);
  argv[8] = NULL;
//   log_write("Launching ovaldi with: %s\n", g_strjoinv(" ", argv));

  if(g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, child_setup, NULL, NULL, NULL, NULL, NULL))
  {
    GMarkupParser parser; 
    GMarkupParseContext *context = NULL;
    gchar *filebuffer = NULL;
    guint length = 0;

    parser.start_element = start_element;
    parser.end_element = end_element;
    parser.text = text;
    parser.passthrough = NULL;
    parser.error = NULL;

    if(!g_file_get_contents(results_filename, &filebuffer, &length, NULL))
    {
      snprintf(result_string, 256,
              "Could not return results for OVAL definition %s: Results file not found.\n\n",
              basename);
      post_note(g_args, 0, result_string);
      log_write("Results file %s not found!\n", results_filename);
    }
    else
    {
      context = g_markup_parse_context_new(&parser, 0, NULL, NULL);
      g_markup_parse_context_parse(context, filebuffer, length, NULL);
      g_free(filebuffer);
      g_markup_parse_context_free(context);
      snprintf(result_string, 256, "The OVAL definition %s returned the following result: %s\n\n", basename, result);
      post_note(g_args, 0, result_string);
    }
  }
  else
  {
    snprintf(result_string, 256, "Could not launch ovaldi for OVAL definition %s: Launch failed. (Is ovaldi in your PATH?)\n\n", basename);
    post_note(g_args, 0, result_string);
    log_write("Could not launch ovaldi!\n");
  }
}

pl_class_t oval_plugin_class = {
    NULL,
    ".oval",
    oval_plugin_init,
    oval_plugin_add,
    oval_plugin_launch,
};
