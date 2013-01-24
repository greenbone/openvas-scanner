/* OpenVAS
* $Id$
* Description: Loads plugins from disk into memory.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
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
*/

#include <stdio.h> /* for printf() */

#include <openvas/nasl/nasl.h>
#include <openvas/misc/system.h>     /* for emalloc */

#include <glib.h>

#include "utils.h"
#include "pluginload.h"
#include "log.h"
#include "preferences.h"

static pl_class_t *plugin_classes = NULL;

/*
 * main function for loading all the
 * plugins that are in folder <folder>
 */
struct arglist *
plugins_init (preferences, be_quiet)
     struct arglist *preferences;
     int be_quiet;
{
  return plugins_reload (preferences, emalloc (sizeof (struct arglist)),
                         be_quiet);
}

static void
init_plugin_classes (struct arglist *preferences)
{
  if (plugin_classes == NULL)
    {
      pl_class_t **cl_pptr = &plugin_classes;
      pl_class_t *cl_ptr;
      int i;
      pl_class_t *classes[] =
        { &nasl_plugin_class, &oval_plugin_class, NULL };

      for (i = 0; (cl_ptr = classes[i]); ++i)
        {
          if ((*cl_ptr->pl_init) (preferences, NULL))
            {
              *cl_pptr = cl_ptr;
              cl_ptr->pl_next = NULL;
              cl_pptr = &cl_ptr->pl_next;
            }
        }
    }
}

/**
 * @brief Collects all NVT files in a directory and recurses into subdirs.
 *
 * @param folder The main directory from where to descend and collect.
 *
 * @param subdir A subdirectory to consider for the collection: "folder/subdir"
 *               is thus the effective directory to descend from. "subdir"
 *               can be "" to make "folder" the effective start.
 *
 * @param files  A list that is extended with all found files. If it
 *               is NULL, a new list is created automatically.
 *
 * @return Parameter "files", extended with all the NVT files found in
 *         "folder" and its subdirectories. Not added are directory names.
 *         NVT files are identified by the defined filename suffixes.
 */
GSList *
collect_nvts (const char *folder, const char *subdir, GSList * files)
{
  GDir *dir;
  const gchar *fname;

  if (folder == NULL)
    return files;

  dir = g_dir_open (folder, 0, NULL);
  if (dir == NULL)
    return files;

  fname = g_dir_read_name (dir);
  while (fname)
    {
      char *path;

      path = g_build_filename (folder, fname, NULL);
      if (g_file_test (path, G_FILE_TEST_IS_DIR))
        {
          char *new_folder, *new_subdir;

          new_folder = g_build_filename (folder, fname, NULL);
          new_subdir = g_build_filename (subdir, fname, NULL);

          files = collect_nvts (new_folder, new_subdir, files);

          if (new_folder)
            g_free (new_folder);
          if (new_subdir)
            g_free (new_subdir);
        }
      else
        {
          pl_class_t *cl_ptr = plugin_classes;
          while (cl_ptr)
            {
              if (g_str_has_suffix (fname, cl_ptr->extension))
                {
                  files =
                    g_slist_prepend (files,
                                     g_build_filename (subdir, fname, NULL));
                  break;
                }
              cl_ptr = cl_ptr->pl_next;
            }
        }
      g_free (path);
      fname = g_dir_read_name (dir);
    }

  g_dir_close (dir);
  return files;
}


static struct arglist *
plugins_reload_from_dir (preferences, plugins, folder, be_quiet)
     struct arglist *preferences;
     struct arglist *plugins;
     char *folder;
     int be_quiet;
{
  GSList *files = NULL, *f;
  char *name;
  gchar *pref_include_folders;
  gchar **include_folders;
  int n = 0, total = 0, num_files = 0;
  int i = 0;
  int result = 0;

  add_nasl_inc_dir ("");        // for absolute and relative paths

  pref_include_folders = arg_get_value (preferences, "include_folders");
  if (pref_include_folders != NULL)
    {
      include_folders = g_strsplit (pref_include_folders, ":", 0);

      for (i = 0; i < g_strv_length (include_folders); i++)
        {
          result = add_nasl_inc_dir (include_folders[i]);
          if (result < 0)
            printf
              ("Could not add %s to the list of include folders.\nMake sure %s exists and is a directory.\n",
               include_folders[i], include_folders[i]);
        }

      g_strfreev (include_folders);
    }

  init_plugin_classes (preferences);

  if (folder == NULL)
    {
#ifdef DEBUG
      log_write ("%s:%d : folder == NULL\n", __FILE__, __LINE__);
#endif
      printf ("Could not determine the value of <plugins_folder>. Check %s\n",
              (char *) arg_get_value (preferences, "config_file"));
      return plugins;
    }

  files = collect_nvts (folder, "", files);
  num_files = g_slist_length (files);

  /*
   * Add the plugins
   */

  if (be_quiet == 0)
    {
      printf ("Loading the OpenVAS plugins...");
      fflush (stdout);
    }
  f = files;
  while (f != NULL)
    {
      name = f->data;
      pl_class_t *cl_ptr = plugin_classes;

      n++;
      total++;
      if (n > 50 && be_quiet == 0)
        {
          n = 0;
          printf ("\rLoading the plugins... %d (out of %d)", total, num_files);
          fflush (stdout);
        }


      if (preferences_log_plugins_at_load (preferences))
        log_write ("Loading %s\n", name);
      while (cl_ptr)
        {
          if (g_str_has_suffix (name, cl_ptr->extension))
            {
              struct arglist *pl = (*cl_ptr->pl_add) (folder, name, plugins,
                                                      preferences);
              if (pl)
                {
                  arg_add_value (pl, "PLUGIN_CLASS", ARG_PTR, sizeof (cl_ptr),
                                 cl_ptr);
                }
              break;
            }
          cl_ptr = cl_ptr->pl_next;
        }
      g_free (f->data);
      f = g_slist_next (f);
    }

  g_slist_free (files);

  if (be_quiet == 0)
    {
      printf ("\rAll plugins loaded                                   \n");
      fflush (stdout);
    }

  return plugins;
}


struct arglist *
plugins_reload (preferences, plugins, be_quiet)
     struct arglist *preferences;
     struct arglist *plugins;
     int be_quiet;
{
  return plugins_reload_from_dir (preferences, plugins,
                                  arg_get_value (preferences, "plugins_folder"),
                                  be_quiet);
}

void
plugin_set_socket (struct arglist *plugin, int soc)
{
  if (arg_get_value (plugin, "SOCKET") != NULL)
    arg_set_value (plugin, "SOCKET", sizeof (gpointer), GSIZE_TO_POINTER (soc));
  else
    arg_add_value (plugin, "SOCKET", ARG_INT, sizeof (gpointer),
                   GSIZE_TO_POINTER (soc));
}

int
plugin_get_socket (struct arglist *plugin)
{
  return GPOINTER_TO_SIZE (arg_get_value (plugin, "SOCKET"));
}


void
plugin_unlink (plugin)
     struct arglist *plugin;
{
  if (plugin == NULL)
    {
      fprintf (stderr, "Error in plugin_unlink - args == NULL\n");
      return;
    }
  arg_set_value (plugin, "preferences", -1, NULL);
}


void
plugin_free (plugin)
     struct arglist *plugin;
{
  plugin_unlink (plugin);
  arg_free_all (plugin);
}

void
plugins_free (plugins)
     struct arglist *plugins;
{
  struct arglist *p = plugins;
  if (p == NULL)
    return;

  while (p->next)
    {
      plugin_unlink (p->value);
      p = p->next;
    }
  arg_free_all (plugins);
}

/*
 * Put our socket somewhere in the plugins
 * arguments
 */
void
plugins_set_socket (struct arglist *plugins, int soc)
{
  struct arglist *t;

  t = plugins;
  while (t && t->next)
    {
      plugin_set_socket (t->value, soc);
      t = t->next;
    }
}
