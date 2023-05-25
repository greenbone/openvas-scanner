/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file utils.c
 * @brief A bunch of miscellaneous functions, mostly file conversions.
 */

#include "utils.h"

#include "../misc/plugutils.h"  /* for kb_item_set_int_with_main_kb_check */
#include "../misc/scanneraux.h" /* for struct scan_globals */

#include <errno.h>          /* for errno() */
#include <gvm/base/prefs.h> /* for prefs_get() */
#include <gvm/boreas/cli.h> /* for is_host_alive() */
#include <stdlib.h>         /* for atoi() */
#include <string.h>         /* for strcmp() */
#include <sys/ioctl.h>      /* for ioctl() */
#include <sys/wait.h>       /* for waitpid() */

extern int global_max_hosts;
extern int global_max_checks;

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

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

/**
 * Get the max number of hosts to test at the same time.
 */
int
get_max_hosts_number (void)
{
  int max_hosts;
  if (prefs_get ("max_hosts"))
    {
      max_hosts = atoi (prefs_get ("max_hosts"));
      if (max_hosts <= 0)
        {
          g_debug ("Error ! max_hosts = %d -- check %s", max_hosts,
                   (char *) prefs_get ("config_file"));
          max_hosts = global_max_hosts;
        }
      else if (max_hosts > global_max_hosts)
        {
          g_debug ("Client tried to raise the maximum hosts number - %d."
                   " Using %d. Change 'max_hosts' in openvas.conf if you"
                   " believe this is incorrect",
                   max_hosts, global_max_hosts);
          max_hosts = global_max_hosts;
        }
    }
  else
    max_hosts = global_max_hosts;
  return (max_hosts);
}

/**
 * Get the max number of plugins to launch against the remote
 * host at the same time
 */
int
get_max_checks_number (void)
{
  int max_checks;
  if (prefs_get ("max_checks"))
    {
      max_checks = atoi (prefs_get ("max_checks"));
      if (max_checks <= 0)
        {
          g_debug ("Error ! max_hosts = %d -- check %s", max_checks,
                   (char *) prefs_get ("config_file"));
          max_checks = global_max_checks;
        }
      else if (max_checks > global_max_checks)
        {
          g_debug ("Client tried to raise the maximum checks number - %d."
                   " Using %d. Change 'max_checks' in openvas.conf if you"
                   " believe this is incorrect",
                   max_checks, global_max_checks);
          max_checks = global_max_checks;
        }
    }
  else
    max_checks = global_max_checks;
  return (max_checks);
}

/**
 * Determines if a process is alive - as reliably as we can
 */
int
process_alive (pid_t pid)
{
  int i, ret;
  if (pid == 0)
    return 0;

  for (i = 0, ret = 1; (i < 10) && (ret > 0); i++)
    ret = waitpid (pid, NULL, WNOHANG);

  return kill (pid, 0) == 0;
}

int
data_left (int soc)
{
  int data = 0;
  ioctl (soc, FIONREAD, &data);
  return data;
}

void
wait_for_children1 (void)
{
  int e, n = 0;
  do
    {
      errno = 0;
      e = waitpid (-1, NULL, WNOHANG);
      n++;
    }
  while ((e > 0 || errno == EINTR) && n < 20);
}

/*
 * @brief Checks if a provided preference is scanner-only and can't be
 * read/written by the client.
 *
 * @return 1 if pref is scanner-only, 0 otherwise.
 */
int
is_scanner_only_pref (const char *pref)
{
  if (pref == NULL)
    return 0;
  if (!strcmp (pref, "config_file") || !strcmp (pref, "plugins_folder")
      || !strcmp (
        pref,
        "kb_location") // old name of db_address, ignore from old conf's
      || !strcmp (pref, "db_address") || !strcmp (pref, "negot_timeout")
      || !strcmp (pref, "force_pubkey_auth")
      || !strcmp (pref, "log_whole_attack")
      || !strcmp (pref, "log_plugins_name_at_load")
      || !strcmp (pref, "nasl_no_signature_check")
      || !strcmp (pref, "vendor_version") || !strcmp (pref, "drop_privileges")
      || !strcmp (pref, "nasl_drop_privileges_user")
      || !strcmp (pref, "debug_tls") || !strcmp (pref, "min_free_mem")
      || !strcmp (pref, "max_sysload")
      /* Preferences starting with sys_ are scanner-side only. */
      || !strncmp (pref, "sys_", 4))
    return 1;
  return 0;
}
