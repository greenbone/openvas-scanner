/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file pluginload.c
 * @brief Loads plugins from disk into memory.
 */

#include "pluginload.h"

#include "../nasl/nasl.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"

#include <bsd/unistd.h>
#include <errno.h>
#include <glib.h>
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/util/nvticache.h> /* for nvticache_new */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h> /* for shmget */
#include <sys/time.h>
#include <sys/wait.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

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
static GSList *
collect_nvts (const char *folder, const char *subdir, GSList *files)
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
      else if (g_str_has_suffix (fname, ".nasl"))
        files = g_slist_prepend (files, g_build_filename (subdir, fname, NULL));
      g_free (path);
      fname = g_dir_read_name (dir);
    }

  g_dir_close (dir);
  return files;
}

static int
calculate_eta (struct timeval start_time, int loaded, int total)
{
  struct timeval current_time;
  int elapsed, remaining;

  if (start_time.tv_sec == 0)
    return 0;

  gettimeofday (&current_time, NULL);
  elapsed = current_time.tv_sec - start_time.tv_sec;
  remaining = total - loaded;
  return (remaining * elapsed) / loaded;
}

static int *loading_shm = NULL;
static int loading_shmid = 0;

/*
 * @brief Initializes the shared memory data used to report plugins loading
 *        progress to other processes.
 */
void
init_loading_shm (void)
{
  int shm_key;

  if (loading_shm)
    return;

  shm_key = rand () + 1;
  /*
   * Create shared memory segment if it doesn't exist.
   * This will be used to communicate current plugins loading progress to other
   * processes.
   * loading_shm[0]: Number of loaded plugins.
   * loading_shm[1]: Total number of plugins.
   */
  loading_shmid = shmget (shm_key, sizeof (int) * 2, IPC_CREAT | 0600);
  if (loading_shmid < 0)
    perror ("shmget");
  loading_shm = shmat (loading_shmid, NULL, 0);
  if (loading_shm == (void *) -1)
    {
      perror ("shmat");
      loading_shm = NULL;
    }
  else
    bzero (loading_shm, sizeof (int) * 2);
}

/*
 * @brief Destroys the shared memory data used to report plugins loading
 *        progress to other processes.
 */
void
destroy_loading_shm (void)
{
  if (loading_shm)
    {
      shmdt (loading_shm);
      if (shmctl (loading_shmid, IPC_RMID, NULL))
        perror ("shmctl");
      loading_shm = NULL;
      loading_shmid = 0;
    }
}

/*
 * @brief Gives current number of loaded plugins.
 *
 * @return Number of loaded plugins,  0 if initialization wasn't successful.
 */
int
current_loading_plugins (void)
{
  return loading_shm ? loading_shm[0] : 0;
}

/*
 * @brief Gives the total number of plugins to be loaded.
 *
 * @return Total of loaded plugins,  0 if initialization wasn't successful.
 */
int
total_loading_plugins (void)
{
  return loading_shm ? loading_shm[1] : 0;
}

/*
 * @brief Sets number of loaded plugins.
 *
 * @param[in]   current Number of loaded plugins.
 */
static void
set_current_loading_plugins (int current)
{
  if (loading_shm)
    loading_shm[0] = current;
}

/*
 * @brief Sets total number of plugins to be loaded.
 *
 * @param[in]   total Total number of plugins
 */
static void
set_total_loading_plugins (int total)
{
  if (loading_shm)
    loading_shm[1] = total;
}

/*
 * @brief Clean leftover NVTs.
 *
 * @param[in]   num_files   Number of NVT files found in the folder.
 */
static void
cleanup_leftovers (int num_files)
{
  size_t count;
  GSList *oids, *element;

  setproctitle ("openvas: Cleaning leftover NVTs.");

  count = nvticache_count ();
  if ((int) count <= num_files)
    return;

  oids = element = nvticache_get_oids ();
  while (element)
    {
      char *path = nvticache_get_src (element->data);

      if (!g_file_test (path, G_FILE_TEST_EXISTS))
        nvticache_delete (element->data);
      g_free (path);
      element = element->next;
    }
  g_slist_free_full (oids, g_free);
}

static int
plugins_reload_from_dir (const char *folder)
{
  GSList *files = NULL, *f;
  int loaded_files = 0, num_files = 0;
  struct timeval start_time;

  openvas_signal (SIGTERM, SIG_DFL);
  if (folder == NULL)
    {
      g_debug ("%s:%d : folder == NULL", __FILE__, __LINE__);
      g_debug ("Could not determine the value of <plugins_folder>. "
               " Check %s\n",
               (char *) prefs_get ("config_file"));
      return 1;
    }

  files = collect_nvts (folder, "", files);
  num_files = g_slist_length (files);

  /*
   * Add the plugins
   */

  if (gettimeofday (&start_time, NULL))
    {
      bzero (&start_time, sizeof (start_time));
      g_debug ("gettimeofday: %s", strerror (errno));
    }
  f = files;
  set_total_loading_plugins (num_files);
  while (f != NULL)
    {
      static int err_count = 0;
      char *name = f->data;

      loaded_files++;
      if (loaded_files % 50 == 0)
        {
          int percentile, eta;

          set_current_loading_plugins (loaded_files);
          percentile = (loaded_files * 100) / num_files;
          eta = calculate_eta (start_time, loaded_files, num_files);
          setproctitle ("openvas: Reloaded %d of %d NVTs"
                        " (%d%% / ETA: %02d:%02d)",
                        loaded_files, num_files, percentile, eta / 60,
                        eta % 60);
        }
      if (prefs_get_bool ("log_plugins_name_at_load"))
        g_message ("Loading %s", name);
      if (g_str_has_suffix (name, ".nasl"))
        {
          if (nasl_plugin_add (folder, name))
            err_count++;
        }

      if (err_count == 20)
        {
          g_debug ("Stopped loading plugins: High number of errors.");
          setproctitle ("openvas: Error loading NVTs.");
          g_slist_free_full (files, g_free);
          return 1;
        }
      f = g_slist_next (f);
    }

  cleanup_leftovers (num_files);
  g_slist_free_full (files, g_free);
  nasl_clean_inc ();

  setproctitle ("openvas: Reloaded all the NVTs.");

  return 0;
}

static void
include_dirs (void)
{
  const gchar *pref_include_folders;

  add_nasl_inc_dir (""); // for absolute and relative paths
  pref_include_folders = prefs_get ("include_folders");
  if (pref_include_folders != NULL)
    {
      gchar **include_folders = g_strsplit (pref_include_folders, ":", 0);
      unsigned int i = 0;

      for (i = 0; i < g_strv_length (include_folders); i++)
        {
          int result = add_nasl_inc_dir (include_folders[i]);
          if (result < 0)
            g_debug ("Could not add %s to the list of include folders.\n"
                     "Make sure %s exists and is a directory.\n",
                     include_folders[i], include_folders[i]);
        }

      g_strfreev (include_folders);
    }
}
/**
 * @brief Main function for nvticache initialization without
 *        loading the plugins
 *
 * @return 0 on success, -1 on failure.
 **/
int
plugins_cache_init (void)
{
  int ret;
  const char *plugins_folder = prefs_get ("plugins_folder");

  if (nvticache_init (plugins_folder, prefs_get ("db_address")))
    {
      g_debug ("Failed to initialize nvti cache.");
      return -1;
    }
  include_dirs ();
  ret = nasl_file_check (plugins_folder, "plugin_feed_info.inc");
  if (ret)
    return -1;

  return 0;
}

/**
 * @brief main function for loading all the plugins
 *
 * @return 0 on success, !=0 on failure.
 */
int
plugins_init (void)
{
  int ret = 0;
  const char *plugins_folder = prefs_get ("plugins_folder");

  ret = plugins_cache_init ();
  if (ret)
    return ret;

  ret = plugins_reload_from_dir (plugins_folder);
  nvticache_save ();
  return ret;
}
