/* Nessus Attack Scripting Language Linter
 *
 * Copyright (C) 2013 Greenbone Networks GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/**
 * @file
 * Source of the NASL linter of OpenVAS.
 */

#include <stdio.h> /* for printf */
#include <stdlib.h> /* for exit */

#include "nasl.h" /* exec_nasl_script, arglist */

#include <glib.h> /* gchar, g_malloc, g_error, g_print, ... */

#include <gio/gio.h> /* g_file_... */

/**
 * @brief Returns a GDataInputStream* for a given filepath
 * @param filename the path to the file to open
 * @returns a GDataInputStream corresponding to the filepath
 */
static GDataInputStream*
get_DIS_from_filename (const gchar* filename)
{
  GFile* file = NULL;
  GFileInputStream* fis = NULL;
  GDataInputStream* dis = NULL;
  GError* error = NULL;

  file = g_file_new_for_path (filename);
  fis = g_file_read (file, NULL, &error);
  if (error != NULL) {
    if (fis != NULL)
      g_object_unref (fis);

    g_error ("%s\n\n", error->message);
  }
  dis = g_data_input_stream_new (G_INPUT_STREAM(fis));
  g_object_unref (fis);
  return dis;
}

/**
 * @brief Process a file through the linter
 * @param filepath the path of the file to be processed
 * @param mode,script_args The parameters to be given to the linter
 * @return TRUE if the file contains error(s)
 */
static gboolean
process_file (const gchar* filepath, int mode, struct arglist* script_args)
{
  g_debug("Processing %s", filepath);
  if (exec_nasl_script (script_args, filepath, NULL, mode) < 0)
    {
      g_print ("Error while processing %s.\n", filepath);
      return TRUE;
    }
  return FALSE;
}

/**
 * @brief Process each files in the list_file through the linter
 * @param list_file the path to a text file containing path to the files to
 *        process, one per line
 * @param mode,script_args Parameters for the linter
 * @return The amount of scripts that contain errors
 */
static int
process_file_list (const gchar* list_file, int mode,
                   struct arglist* script_args)
{
  int err = 0;
  GError* error = NULL;
  GDataInputStream* nvt_list = get_DIS_from_filename(list_file);

  while(TRUE)
    {
      gchar* line = g_data_input_stream_read_line (nvt_list, NULL, NULL,
                                                   &error);
      if (error != NULL)
        {
          if (line != NULL)
            g_free (line);

          g_error ("%s\n\n", error->message);
          break;
        }
      if (line == NULL)
        break;

      if (process_file(line, mode, script_args))
        err++;

      g_free (line);
    }
  g_object_unref (nvt_list);

  return err;
}

/**
 * @brief Process each given files through the linter
 * @param files The path to the files to be processed
 * @param mode,script_args Parameters to be given to the linter
 * @return The amount of script that contains errors
 */
static int
process_files(const gchar** files, int mode, struct arglist* script_args)
{
  int n = 0;
  int err = 0;
  while (files[n])
    {
      if (process_file(files[n], mode, script_args))
        err++;
      n++;
    }
  return err;
}

/**
 * @brief custom log handler
 *
 * This handler absorb each log_level not present in the log_mask, and forward
 * the other ones to the default handler.
 */
static void
custom_log_handler(const gchar *log_domain,
                   GLogLevelFlags log_level,
                   const gchar *message,
                   gpointer user_data )
{
  gint log_mask = GPOINTER_TO_INT (user_data);
  if ((log_level & log_mask) != 0)
    g_log_default_handler(log_domain, log_level, message, user_data);
}

/**
 * @brief Main of the nasl QA linter
 * @return 0 on success
 */
int
main (int argc, char **argv)
{
  int mode = 0;
  int err = 0;
  static gboolean debug = FALSE;
  static gchar *include_dir = NULL;
  static gchar *nvt_file_list = NULL;
  static const gchar **nvt_files = NULL;
  struct arglist *script_infos = g_malloc0 (sizeof (struct arglist));
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug,
     "Output debug log messages.", NULL},
    {"nvt-list", 'l', 0, G_OPTION_ARG_STRING, &nvt_file_list,
     "Process files from <file>", "<file>"},
    {"include-dir", 'i', 0, G_OPTION_ARG_STRING, &include_dir,
     "Search for includes in <dir>", "<dir>"},
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &nvt_files,
     "Absolute path to one or more nasl scripts", "NASL_FILE..."},
    {NULL}
  };

  option_context =
    g_option_context_new ("- standalone NASL linter for OpenVAS");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_error ("%s\n\n", error->message);
    }
  g_option_context_free (option_context);

#if !GLIB_CHECK_VERSION(2, 35, 0)
  g_type_init();
#endif

  mode |= NASL_COMMAND_LINE;
  /* authenticated mode */
  mode |= NASL_ALWAYS_SIGNED;
  /* linter on */
  mode |= NASL_LINT;

  /* For relative include */
  add_nasl_inc_dir ("");
  /* For absolute include (if given on command line) */
  if (include_dir != NULL)
    add_nasl_inc_dir (include_dir);

  if (debug)
    g_log_set_handler (NULL,
                       G_LOG_LEVEL_MASK,
                       custom_log_handler,
                       GINT_TO_POINTER (G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO|
                                        G_LOG_LEVEL_MESSAGE|
                                        G_LOG_LEVEL_WARNING|
                                        G_LOG_LEVEL_CRITICAL|
                                        G_LOG_LEVEL_ERROR));
  else
    g_log_set_handler (NULL,
                       G_LOG_LEVEL_MASK,
                       custom_log_handler,
                       GINT_TO_POINTER (G_LOG_LEVEL_WARNING|
                                        G_LOG_LEVEL_CRITICAL|
                                        G_LOG_LEVEL_ERROR));

  /* Process the files from the list */
  if (nvt_file_list != NULL)
    err += process_file_list(nvt_file_list, mode, script_infos);

  /* process the files from the command line */
  if (nvt_files != NULL)
    err += process_files(nvt_files, mode, script_infos);

  g_print ("%d errors found\n", err);
  return err;
}
