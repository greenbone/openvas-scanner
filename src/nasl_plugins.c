/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_plugins.c
 * @brief The nasl - plugin class. Loads or launches nasl- plugins.
 */

#include "../misc/kb_cache.h" /* for get_main_kb */
#include "../misc/network.h"
#include "../misc/plugutils.h" /* for plug_set_launch */
#include "../nasl/nasl.h"
#include "pluginlaunch.h"
#include "pluginload.h"
#include "pluginscheduler.h"
#include "processes.h"

#include <bsd/unistd.h>
#include <errno.h> /* for errno */
#include <glib.h>
#include <gvm/base/drop_privileges.h> /* for drop_privileges */
#include <gvm/base/networking.h>
#include <gvm/base/prefs.h>     /* for prefs_get_bool */
#include <gvm/util/nvticache.h> /* for nvticache_add */
#include <stdio.h>              /* for snprintf() */
#include <string.h>             /* for strlen() */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h> /* for close() */
#include <utime.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Check that the nvt's data is valid.
 *
 * @param filename  Filename of the NVT.
 * @param nvt       NVT to check.
 *
 * @return 0 on success, -1 on error.
 */
static int
check_nvti (const char *filename, nvti_t *nvt)
{
  assert (filename);
  assert (nvt);

  if (!nvti_oid (nvt))
    {
      g_warning ("%s: Missing OID", filename);
      return -1;
    }
  else if (!nvti_name (nvt))
    {
      g_warning ("%s: Missing name", filename);
      return -1;
    }
  else if (!nvti_family (nvt))
    {
      g_warning ("%s: Missing family", filename);
      return -1;
    }
  return 0;
}

/**
 * @brief Check a single .nasl/.inc file.
 *
 * @param folder  Path to the plugin folder.
 * @param filename    File-name of the plugin
 *
 * @return 0 on success, -1 on error.
 */
int
nasl_file_check (const char *folder, const char *filename)
{
  char fullname[PATH_MAX + 1];
  int nasl_mode;
  struct script_infos *args;

  snprintf (fullname, sizeof (fullname), "%s/%s", folder, filename);
  nasl_mode = NASL_EXEC_DESCR;
  if (prefs_get_bool ("nasl_no_signature_check"))
    nasl_mode |= NASL_ALWAYS_SIGNED;

  args = g_malloc0 (sizeof (struct script_infos));
  args->key = nvticache_get_kb ();
  args->nvti = NULL;
  args->name = fullname;
  if (exec_nasl_script (args, nasl_mode) < 0)
    {
      g_debug ("%s: Checksum check failed", fullname);
      g_free (args);
      return -1;
    }
  g_free (args);

  return 0;
}

/**
 * @brief Add *one* .nasl plugin to the plugin list.
 *
 * It is parsed (via exec_nasl_script) and added to the cache
 *
 * @param folder  Path to the plugin folder.
 * @param filename    File-name of the plugin
 *
 * @return 0 on success, -1 on error.
 */
int
nasl_plugin_add (const char *folder, char *filename)
{
  char fullname[PATH_MAX + 1];
  int nasl_mode;
  nvti_t *new_nvti;
  struct script_infos *args;
  time_t now;
  struct utimbuf updated_timestamp;

  snprintf (fullname, sizeof (fullname), "%s/%s", folder, filename);
  nasl_mode = NASL_EXEC_DESCR;
  if (prefs_get_bool ("nasl_no_signature_check"))
    nasl_mode |= NASL_ALWAYS_SIGNED;

  args = g_malloc0 (sizeof (struct script_infos));
  args->key = nvticache_get_kb ();
  new_nvti = nvti_new ();
  args->nvti = new_nvti;
  args->name = fullname;
  if (exec_nasl_script (args, nasl_mode) < 0)
    {
      g_debug ("%s: Could not be loaded", fullname);
      g_free (args);
      return -1;
    }
  g_free (args);

  now = time (NULL) - 1;
  updated_timestamp.actime = now;
  updated_timestamp.modtime = now;
  utime (fullname, &updated_timestamp);

  if (!check_nvti (filename, new_nvti))
    nvticache_add (new_nvti, filename);
  nvti_free (new_nvti);

  return 0;
}

static void
nasl_thread (struct ipc_context *, struct script_infos *);

/**
 * @brief Launch a NASL plugin.
 */
int
nasl_plugin_launch (struct scan_globals *globals, struct in6_addr *ip,
                    GSList *vhosts, kb_t kb, const char *oid)
{
  int module;
  struct script_infos infos;

  memset (&infos, '\0', sizeof (infos));
  // extend here, maybe create struct to simplify calls
  infos.ip = ip;
  infos.vhosts = vhosts;
  infos.globals = globals;
  infos.key = kb;
  infos.oid = (char *) oid;
  infos.name = nvticache_get_src (oid);
  infos.ipc_context = NULL;

  module = create_ipc_process ((ipc_process_func) nasl_thread, &infos);
  g_free (infos.name);
  return module;
}

static void
nasl_thread (struct ipc_context *ipcc, struct script_infos *args)
{
  char ip_str[INET6_ADDRSTRLEN];
  int nasl_mode = 0;
  kb_t kb;
  GError *error = NULL;
  args->ipc_context = ipcc;

  /* Make plugin process a group leader, to make it easier to cleanup forked
   * processes & their children. */
  setpgid (0, 0);
  nvticache_reset ();
  kb = args->key;
  kb_lnk_reset (kb);
  kb_lnk_reset (get_main_kb ());
  addr6_to_str (args->ip, ip_str);
  // TODO extend sript_infos here

  setproctitle ("openvas: testing %s (%s)", ip_str,
                g_path_get_basename (args->name));

  if (prefs_get_bool ("nasl_no_signature_check"))
    nasl_mode |= NASL_ALWAYS_SIGNED;

  if (prefs_get_bool ("drop_privileges"))
    {
      int drop_priv_res = drop_privileges (NULL, &error);
      if (drop_priv_res != GVM_DROP_PRIVILEGES_OK)
        {
          if (drop_priv_res != GVM_DROP_PRIVILEGES_FAIL_NOT_ROOT)
            g_debug ("Failed to drop privileges for %s", args->name);
          g_error_free (error);
        }
    }

  if (exec_nasl_script (args, nasl_mode))
    g_debug ("exec_nasl_script: %s error", args->name);
}
