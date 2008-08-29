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

#include <includes.h>
#include "pluginload.h"
// #include "log.h"
#include <glib.h>

gchar * id;
gchar * oid;
gchar * version;
gchar * description;
gchar * title;
gboolean in_description = FALSE;
gboolean in_definition = FALSE;
gboolean in_title = FALSE;

void start_element (GMarkupParseContext *context,
                    const gchar         *element_name,
                    const gchar        **attribute_names,
                    const gchar        **attribute_values,
                    gpointer             user_data,
                    GError             **error)
{
  const gchar **name_cursor = attribute_names;
  const gchar **value_cursor = attribute_values;

  if(strcmp(element_name, "definition") == 0)
  {
    in_definition = TRUE;
    while(*name_cursor)
    {
      if (strcmp (*name_cursor, "id") == 0)
      {
        id = g_strrstr(g_strdup(*value_cursor), ":") + 1;
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
}

void text(GMarkupParseContext *context,
          const gchar         *text,
          gsize                text_len,
          gpointer             user_data,
          GError             **error)
{
  if (in_description)
  {
    description = g_strndup(text, 3070);
  }
  if (in_title)
  {
    title = g_strndup(text, text_len);
    g_strdelimit(title, "\n", ' ');
  }
}

void end_element (GMarkupParseContext *context,
                  const gchar         *element_name,
                  gpointer             user_data,
                  GError             **error)
{
    in_description = FALSE;
    in_definition = FALSE;
    in_title = FALSE;
}

/*
 *  Initialize this class
 */
pl_class_t* oval_plugin_init(struct arglist* prefs, struct arglist* args) {
    return &oval_plugin_class;
}

/*
 * add *one* OVAL definition to the server list
 */
struct arglist * 
oval_plugin_add(folder, name, plugins, preferences)
     char * folder;
     char * name;
     struct arglist * plugins;
     struct arglist * preferences;
{
  char fullname[PATH_MAX+1];
  struct arglist * args = NULL;
  struct arglist * prev_plugin = NULL;
  GMarkupParser parser; 
  GMarkupParseContext *context = NULL;
  gchar *filebuffer = NULL;
  guint length = 0;

  snprintf(fullname, sizeof(fullname), "%s/%s", folder, name);
  args = store_load_plugin(folder, name, preferences);

  if(args == NULL)
  {
    // Parse plugin properties in to arglist
    parser.start_element = start_element;
    parser.end_element = end_element;
    parser.text = text;
    parser.passthrough = NULL;
    parser.error = NULL;

    if (!g_file_get_contents(fullname, &filebuffer, &length, NULL)) {
      g_warning("File %s not found", fullname);
      return NULL;
    }

    context = g_markup_parse_context_new(&parser, 0, NULL, NULL);
    g_markup_parse_context_parse(context, filebuffer, length, NULL);
    g_free(filebuffer);
    g_markup_parse_context_free(context);

    args = emalloc(sizeof(struct arglist));

    plug_set_oid(args, oid);
    plug_set_id(args, (int)id);

    plug_set_version(args, version);
    plug_set_name(args, title, NULL);
    plug_set_description(args, description, NULL);
    plug_set_category(args, ACT_ATTACK);
    plug_set_family(args, "OVAL definitions", NULL);

    store_plugin(args, name);
    args = store_load_plugin(folder, name, preferences);
  }

  if( args != NULL )
  {
    prev_plugin = arg_get_value(plugins, name);
//     plug_set_launch(args, LAUNCH_DISABLED);
    if( prev_plugin == NULL )
      arg_add_value(plugins, name, ARG_ARGLIST, -1, args);
    else
    {
      plugin_free(prev_plugin);
      arg_set_value(plugins, name, -1, args);
    }
  }
  return args;

  return NULL;
}


int
oval_plugin_launch(globals, plugin, hostinfos, preferences, kb, name)
	struct arglist * globals;
	struct arglist * plugin;
	struct arglist * hostinfos;
	struct arglist * preferences;
	struct kb_item ** kb; /* knowledge base */
	char * name;
{
	printf("Would launch %s ... \n", name);
	return 0;
}

pl_class_t oval_plugin_class = {
    NULL,
    ".oval",
    oval_plugin_init,
    oval_plugin_add,
    oval_plugin_launch,
};
