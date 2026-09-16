/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file file_utils.c
 * @brief Manage a directory for the temporary files of a scan.
 */

#include "file_utils.h"

#include <errno.h>
#include <fnmatch.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  file"

/**
 * @brief Default permissions for directories.
 */
#define DEFAULT_DIR_MODE 0700

/**
 * @brief Base directory of the per user runtime directories.
 */
#define RUNTIME_BASE_DIR "/run/user"

/**
 * @brief Base directory used when the runtime directory is not available.
 */
#define FALLBACK_BASE_DIR "/tmp"

/**
 * @brief Number of hexadecimal characters used for a name hash.
 */
#define NAME_HASH_LENGTH 16

/**
 * @brief Path of the managed directory, NULL until it was created.
 */
static gchar *managed_dir = NULL;

/**
 * @brief Hash a value so that it can be used as part of a file name.
 *
 * The result has a fixed length of 16 characters. SHA256 is used as the
 * hashing algorithm.
 *
 * @param value Value to hash.
 *
 * @return A newly allocated hash, or NULL if no value was given. The caller
 *         has to free the returned string.
 */
gchar *
file_utils_hash (const char *value)
{
  gchar *checksum;
  gchar *hash;

  if (value == NULL)
    return NULL;

  checksum = g_compute_checksum_for_string (G_CHECKSUM_SHA256, value, -1);
  hash = g_strndup (checksum, NAME_HASH_LENGTH);
  g_free (checksum);

  return hash;
}

/**
 * @brief Create a directory below a base directory.
 *
 * The directory has to be new, an already existing one is not reused, so that
 * the directory is always owned by this process.
 *
 * @param base Base directory.
 * @param name Name of the directory to create.
 *
 * @return A newly allocated path, or NULL on error.
 */
static gchar *
create_dir (const char *base, const char *name)
{
  gchar *path = g_build_filename (base, name, NULL);

  if (g_mkdir (path, DEFAULT_DIR_MODE) != 0)
    {
      g_debug ("%s: unable to create directory %s: %s", __func__, path,
               g_strerror (errno));
      g_free (path);
      return NULL;
    }

  return path;
}

/**
 * @brief Create the directory for the temporary files of a scan.
 *
 * The directory is created in the runtime directory of the current user, which
 * is kept in memory and removed by the system at the end of the session. If
 * that directory is not available, e.g. because the user has no session,
 * /tmp is used instead.
 *
 * @param id Identifier of the scan, used to derive the directory name.
 *
 * @return 0 on success, 1 on error.
 */
int
file_utils_init (const char *id)
{
  gchar *hash;
  gchar *name;
  gchar *runtime_dir;
  GStatBuf state;

  if (managed_dir != NULL)
    {
      g_warning ("%s: the managed directory %s exists already", __func__,
                 managed_dir);
      return 1;
    }

  hash = file_utils_hash (id);
  if (hash == NULL)
    {
      g_warning ("%s: no scan identifier given", __func__);
      return 1;
    }
  name = g_strdup_printf ("openvas_%s", hash);
  g_free (hash);

  runtime_dir = g_strdup_printf (RUNTIME_BASE_DIR "/%u", (unsigned) geteuid ());
  if (g_stat (runtime_dir, &state) == 0 && S_ISDIR (state.st_mode))
    managed_dir = create_dir (runtime_dir, name);

  if (managed_dir == NULL)
    {
      g_info ("%s: unable to use %s, falling back to %s", __func__, runtime_dir,
              FALLBACK_BASE_DIR);
      managed_dir = create_dir (FALLBACK_BASE_DIR, name);
    }

  g_free (runtime_dir);
  g_free (name);

  if (managed_dir == NULL)
    {
      g_warning ("%s: unable to create a directory for the scan files",
                 __func__);
      return 1;
    }

  g_debug ("%s: using managed directory '%s'", __func__, managed_dir);

  return 0;
}

/**
 * @brief Get the directory for the temporary files of a scan.
 *
 * @return The path of the managed directory, or NULL if it was not created.
 *         It is owned by this module and must not be freed.
 */
const char *
file_utils_get_dir (void)
{
  return managed_dir;
}

/**
 * @brief Delete all files of the managed directory matching a pattern.
 *
 * Files are deleted regardless of which process created them, so that files of
 * child processes are cleaned up as well. The pattern supports unix shell-style
 * wildcards.
 *
 * @param pattern Glob pattern matched against the file names.
 */
void
file_utils_delete_matching (const char *pattern)
{
  const gchar *entry;
  GDir *dir;

  if (managed_dir == NULL || pattern == NULL)
    return;

  dir = g_dir_open (managed_dir, 0, NULL);
  if (dir == NULL)
    {
      g_warning ("%s: unable to open directory %s: %s", __func__, managed_dir,
                 g_strerror (errno));
      return;
    }

  while ((entry = g_dir_read_name (dir)) != NULL)
    {
      gchar *path;

      if (fnmatch (pattern, entry, FNM_PATHNAME) != 0)
        continue;

      path = g_build_filename (managed_dir, entry, NULL);
      if (g_unlink (path) != 0 && errno != ENOENT)
        g_warning ("%s: unable to delete file %s: %s", __func__, path,
                   g_strerror (errno));
      else
        g_debug ("%s: deleted file '%s'", __func__, path);
      g_free (path);
    }

  g_dir_close (dir);
}

/**
 * @brief Delete the managed directory with all files in it.
 */
void
file_utils_cleanup (void)
{
  if (managed_dir == NULL)
    return;

  g_debug ("%s: cleaning up managed directory '%s'", __func__, managed_dir);

  file_utils_delete_matching ("*");

  if (g_rmdir (managed_dir) != 0 && errno != ENOENT)
    g_warning ("%s: unable to delete directory %s: %s", __func__, managed_dir,
               g_strerror (errno));

  g_free (managed_dir);
  managed_dir = NULL;
}
