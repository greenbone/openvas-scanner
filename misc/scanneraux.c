/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file scanneraux.c
 * @brief Auxiliary functions and structures for scanner.
 */

#include "scanneraux.h"

#include "credentials.h"

void
destroy_scan_globals (struct scan_globals *globals)
{
  if (globals == NULL)
    return;

  g_free (globals->scan_id);

  if (globals->files_translation)
    g_hash_table_destroy (globals->files_translation);

  if (globals->files_size_translation)
    g_hash_table_destroy (globals->files_size_translation);

  destroy_credentials (&globals->credentials);

  g_free (globals);
  globals = NULL;
}

/**
 * @brief Adds a 'translation' entry for a file sent by the client.
 *
 * Files sent by the client are stored in memory on the server side.
 * In order to access these files, their original name ('local' to the client)
 * can be 'translated' into the file contents of the in-memory copy of the
 * file on the server side.
 *
 * @param globals    Global struct.
 * @param file_hash  hash to reference the file.
 * @param contents   Contents of the file.
 */
static void
files_add_translation (struct scan_globals *globals, const char *file_hash,
                       char *contents)
{
  GHashTable *trans = globals->files_translation;
  // Register the mapping table if none there yet
  if (trans == NULL)
    {
      trans = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
      globals->files_translation = trans;
    }

  g_hash_table_insert (trans, g_strdup (file_hash), contents);
}

/**
 * @brief Adds a 'content size' entry for a file sent by the client.
 *
 * Files sent by the client are stored in memory on the server side.
 * Because they may be binary we need to store the size of the uploaded file as
 * well. This function sets up a mapping from the original name sent by the
 * client to the file size.
 *
 * @param globals    Global struct.
 * @param file_hash  hash to reference the file.
 * @param filesize   Size of the file in bytes.
 */
static void
files_add_size_translation (struct scan_globals *globals, const char *file_hash,
                            const long filesize)
{
  GHashTable *trans = globals->files_size_translation;
  gchar *filesize_str = g_strdup_printf ("%ld", filesize);

  // Register the mapping table if none there yet
  if (trans == NULL)
    {
      trans = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
      globals->files_size_translation = trans;
    }

  g_hash_table_insert (trans, g_strdup (file_hash), g_strdup (filesize_str));
}

/**
 * @brief Stores a file type preference in a hash table.
 *
 * @param globals    Global struct.
 * @param file       File content.
 * @param file_hash  hash to reference the file.
 *
 * @return 0 if successful, -1 in case of errors.
 */
int
store_file (struct scan_globals *globals, const char *file,
            const char *file_hash)
{
  char *origname;
  gchar *contents = NULL;

  size_t bytes = 0;

  if (!file_hash || *file_hash == '\0')
    return -1;

  origname = g_strdup (file_hash);

  contents = (gchar *) g_base64_decode (file, &bytes);

  if (contents == NULL)
    {
      g_debug ("store_file: Failed to allocate memory for uploaded file.");
      g_free (origname);
      return -1;
    }

  files_add_translation (globals, origname, contents);
  files_add_size_translation (globals, origname, bytes);

  g_free (origname);
  return 0;
}
