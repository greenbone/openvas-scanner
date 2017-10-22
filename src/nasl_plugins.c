/* OpenVAS
* $Id$
* Description: Launches NASL plugins.
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

/**
 * @brief The nasl - plugin class. Loads or launches nasl- plugins.
 */

#include <errno.h>    /* for errno */
#include <unistd.h>   /* for close() */
#include <string.h>   /* for strlen() */
#include <stdio.h>    /* for snprintf() */
#include <sys/stat.h>

#include <glib.h>

#include <sys/types.h>
#include <utime.h>

#include <gvm/base/drop_privileges.h> /* for drop_privileges */
#include <gvm/base/proctitle.h>
#include <gvm/base/prefs.h>           /* for prefs_get_bool */
#include <gvm/util/nvticache.h>       /* for nvticache_add */

#include "../misc/network.h"    /* for internal_send */
#include "../misc/plugutils.h"     /* for plug_set_launch */

#include "../nasl/nasl.h"

#include "pluginload.h"
#include "pluginscheduler.h"
#include "pluginlaunch.h"
#include "processes.h"

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
  else if (!nvti_version (nvt))
    {
      g_warning ("%s: Missing version", filename);
      return -1;
    }
  else if (!nvti_family (nvt))
    {
      g_warning ("%s: Missing family", filename);
      return -1;
    }
  else if (!nvti_copyright (nvt))
    {
      g_warning ("%s: Missing copyright", filename);
      return -1;
    }
  return 0;
}

/**
 * @brief Add *one* .nasl plugin to the plugin list.
 *
 * The plugin is first attempted to be loaded from the cache.
 * If that fails, it is parsed (via exec_nasl_script) and
 * added to the cache.
 *
 * @param folder  Path to the plugin folder.
 * @param filename    File-name of the plugin
 *
 * @return 0 on success, -1 on error.
 */
int
nasl_plugin_add (char *folder, char *filename)
{
  char fullname[PATH_MAX + 1];
  int nasl_mode;
  nasl_mode = NASL_EXEC_DESCR;

  snprintf (fullname, sizeof (fullname), "%s/%s", folder, filename);

  if (prefs_get_bool ("nasl_no_signature_check"))
    {
      nasl_mode |= NASL_ALWAYS_SIGNED;
    }

  if (!nvticache_check (filename))
    {
      nvti_t *new_nvti;
      struct script_infos *args;

      args = g_malloc0 (sizeof (struct script_infos));
      args->key = nvticache_get_kb ();
      new_nvti = nvti_new ();
      args->nvti = new_nvti;
      if (exec_nasl_script (args, fullname, NULL, nasl_mode) < 0)
        {
          g_debug ("%s: Could not be loaded", fullname);
          g_free (args);
          return -1;
        }
      g_free (args);

      // Check mtime of plugin before caching it
      // Set to now if mtime is in the future
      struct stat plug_stat;
      time_t now = time (NULL) - 1;
      stat (fullname, &plug_stat);
      if (plug_stat.st_mtime > now)
        {
          struct utimbuf fixed_timestamp;
          fixed_timestamp.actime = now;
          fixed_timestamp.modtime = now;
          if (utime (fullname, &fixed_timestamp) == 0)
            g_debug ("The timestamp for %s was from the future. This has been fixed.", fullname);
          else
            g_debug ("The timestamp for %s is from the future and could not be fixed.", fullname);
        }

      if (!check_nvti (filename, new_nvti))
        nvticache_add (new_nvti, filename);
      nvti_free (new_nvti);
    }
  return 0;
}

struct nasl_thread_args {
  struct script_infos *args;
  char *name;
  const char *oid;
  int soc;
};

static void
nasl_thread (struct nasl_thread_args *);

/**
 * @brief Launch a NASL plugin.
 */
int
nasl_plugin_launch (struct scan_globals *globals, struct host_info *hostinfo,
                    kb_t kb, char *name, const char *oid, int soc)
{
  int module;
  struct nasl_thread_args nargs;
  struct script_infos *infos;

  infos = g_malloc0 (sizeof (struct script_infos));
  infos->hostname = hostinfo;
  infos->globals = globals;
  infos->key = kb;

  nargs.args = infos;
  nargs.name = name;
  nargs.oid = oid;
  nargs.soc = soc;

  module = create_process ((process_func_t) nasl_thread, &nargs);
  g_free (infos);
  return module;
}

static void
nasl_thread (struct nasl_thread_args *nargs)
{
  struct script_infos *args = nargs->args;
  struct scan_globals *globals = args->globals;
  struct host_info *hostinfo = args->hostname;
  char *name = nargs->name;
  int nasl_mode = 0;
  kb_t kb;
  GError *error = NULL;

  nvticache_reset ();
  if (prefs_get_bool ("be_nice"))
    {
      int nice_retval;
      errno = 0;
      nice_retval = nice (-5);
      if (nice_retval == -1 && errno != 0)
        {
          g_debug ("Unable to renice process: %d", errno);
        }
    }

  kb = args->key;
  kb_lnk_reset (kb);
  globals->global_socket = nargs->soc;
  proctitle_set ("openvassd: testing %s (%s)", hostinfo->name, name);

  if (prefs_get_bool ("nasl_no_signature_check"))
    nasl_mode |= NASL_ALWAYS_SIGNED;

  if (prefs_get_bool ("drop_privileges"))
    {
      int drop_priv_res = drop_privileges (NULL, &error);
      if (drop_priv_res != GVM_DROP_PRIVILEGES_OK)
        {
          if (drop_priv_res != GVM_DROP_PRIVILEGES_FAIL_NOT_ROOT)
            g_debug ("Failed to drop privileges for %s", name);
          g_error_free (error);
        }
    }

  exec_nasl_script (args, name, nargs->oid, nasl_mode);
}
