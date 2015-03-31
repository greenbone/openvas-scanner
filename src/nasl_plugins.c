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

#include <errno.h>
#include <unistd.h>   /* for close() */
#include <string.h>   /* for strlen() */
#include <sys/stat.h>

#include <glib.h>

#include <sys/types.h>
#include <utime.h>

#include <openvas/base/drop_privileges.h> /* for drop_privileges */
#include <openvas/base/nvticache.h>       /* for nvticache_add */
#include <openvas/nasl/nasl.h>
#include <openvas/misc/network.h>    /* for internal_send */
#include <openvas/misc/nvt_categories.h>  /* for ACT_SCANNER */
#include <openvas/misc/plugutils.h>     /* for plug_set_launch */
#include <openvas/misc/internal_com.h>  /* for INTERNAL_COMM_CTRL_FINISHED */
#include <openvas/misc/openvas_proctitle.h>
#include <openvas/misc/prefs.h>         /* for prefs_get_bool */

#include "pluginload.h"
#include "pluginscheduler.h"    /* for LAUNCH_DISABLED */
#include "pluginlaunch.h"
#include "processes.h"
#include "log.h"

/**
 * @brief Add *one* .nasl plugin to the plugin list and return the pointer to it.
 *
 * The plugin is first attempted to be loaded from the cache.
 * If that fails, it is parsed (via exec_nasl_script) and
 * added to the cache.
 * If a plugin with the same (file)name is already present in the plugins
 * arglist, it will be replaced.
 *
 * @param folder  Path to the plugin folder.
 * @param name    File-name of the plugin
 * @param plugins The arglist that the plugin shall be added to (with parameter
 *                name as the key).
 *
 * @return Pointer to the plugin (as arglist). NULL in case of errors.
 */
struct arglist *
nasl_plugin_add (char *folder, char *name, struct arglist *plugins)
{
  char fullname[PATH_MAX + 1];
  struct arglist *plugin_args;
  struct arglist *prev_plugin = NULL;
  int nasl_mode;
  nasl_mode = NASL_EXEC_DESCR;
  nvti_t *nvti;

  snprintf (fullname, sizeof (fullname), "%s/%s", folder, name);

  if (prefs_get_bool ("nasl_no_signature_check"))
    {
      nasl_mode |= NASL_ALWAYS_SIGNED;
    }

  nvti = nvticache_get (name);
  plugin_args = plug_create_from_nvti_and_prefs (nvti);
  if (plugin_args == NULL)
    {
      nvti_t *new_nvti;

      g_free (nvti);
      plugin_args = g_malloc0 (sizeof (struct arglist));
      new_nvti = nvti_new ();
      arg_add_value (plugin_args, "NVTI", ARG_PTR, new_nvti);

      if (exec_nasl_script (plugin_args, fullname, NULL, nasl_mode) < 0)
        {
          log_write ("%s: Could not be loaded", fullname);
          arg_free_all (plugin_args);
          return NULL;
        }

      // this extra pointer was only necessary during parsing the
      // description part of a NASL. Now we can remove it from the args.
      if (arg_get_value (plugin_args, "NVTI"))
        arg_del_value (plugin_args, "NVTI");

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
            log_write ("The timestamp for %s was from the future. This has been fixed.", fullname);
          else
            log_write ("The timestamp for %s is from the future and could not be fixed.", fullname);
        }

      if (nvti_oid (new_nvti) != NULL)
        {
          nvticache_add (new_nvti, name);
          arg_free_all (plugin_args);
          nvti = nvticache_get (name);
          plugin_args = plug_create_from_nvti_and_prefs (nvti);
        }
      else
        // Most likely an exit was hit before the description could be parsed.
        log_write ("\r%s could not be added to the cache and is likely to stay"
                   " invisible to the client.", name);
      nvti_free (new_nvti);
    }

  if (plugin_args == NULL)
    {
      /* Discard invalid plugins */
      log_write ("%s: Failed to load", name);
      g_free (nvti);
      return NULL;
    }

  if (nvti_oid (nvti) == NULL)
    {
      /* Discard invalid plugins */
      log_write ("%s: Failed to load, no OID", name);
      plugin_free (plugin_args);
      g_free (nvti);
      return NULL;
    }

  plug_set_launch (plugin_args, LAUNCH_DISABLED);
  prev_plugin = arg_get_value (plugins, nvti_oid (nvti));

  // Was a plugin with the same oid already loaded? If so, remove it.
  if (prev_plugin == NULL)
    arg_add_value (plugins, nvti_oid (nvti), ARG_ARGLIST, plugin_args);
  else
    {
      plugin_free (prev_plugin);
      arg_set_value (plugins, nvti_oid (nvti), plugin_args);
    }

  nvti_free (nvti);

  return plugin_args;
}

struct nasl_thread_args {
  struct arglist *args;
  char *name;
  const char *oid;
};

static void
nasl_thread (struct nasl_thread_args *);

/**
 * @brief Launch a NASL plugin.
 */
int
nasl_plugin_launch (struct arglist *globals, struct arglist *plugin,
                    struct arglist *hostinfos, kb_t kb, char *name,
                    const char *oid)
{
  int module;
  struct nasl_thread_args nargs;

  arg_add_value (plugin, "HOSTNAME", ARG_ARGLIST, hostinfos);
  if (arg_get_value (plugin, "globals"))
    arg_set_value (plugin, "globals", globals);
  else
    arg_add_value (plugin, "globals", ARG_ARGLIST, globals);

  arg_add_value (plugin, "key", ARG_PTR, kb);

  nargs.args = plugin;
  nargs.name = name;
  nargs.oid = oid;

  module = create_process ((process_func_t) nasl_thread, &nargs);
  return module;
}

static void
nasl_thread (struct nasl_thread_args *nargs)
{
  struct arglist *args = nargs->args;
  struct arglist *globals = arg_get_value (args, "globals");
  char *name = nargs->name;
  int nasl_mode = 0, soc, old_soc;
  kb_t kb;
  GError *error = NULL;

  if (prefs_get_bool ("be_nice"))
    {
      int nice_retval;
      errno = 0;
      nice_retval = nice (-5);
      if (nice_retval == -1 && errno != 0)
        {
          log_write ("Unable to renice process: %d", errno);
        }
    }

  pluginlaunch_child_cleanup ();
  kb = arg_get_value (args, "key");
  kb_lnk_reset (kb);
  old_soc = arg_get_value_int (args, "SOCKET");
  /* XXX ugly hack */
  soc = dup2 (old_soc, 4);
  close (old_soc);
  if (soc < 0)
    {
      log_write ("dup2() failed ! - can not launch the plugin");
      return;
    }
  arg_set_value (args, "SOCKET", GSIZE_TO_POINTER (soc));
  arg_set_value (globals, "global_socket", GSIZE_TO_POINTER (soc));
  proctitle_set ("openvassd: testing %s (%s)",
                 arg_get_value (arg_get_value (args, "HOSTNAME"), "NAME"),
                 name);

  if (prefs_get_bool ("nasl_no_signature_check"))
    nasl_mode |= NASL_ALWAYS_SIGNED;

  if (prefs_get_bool ("drop_privileges"))
    {
      int drop_priv_res = drop_privileges (NULL, &error);
      if (drop_priv_res != OPENVAS_DROP_PRIVILEGES_OK)
        {
          if (drop_priv_res != OPENVAS_DROP_PRIVILEGES_FAIL_NOT_ROOT)
            log_write ("Failed to drop privileges for %s", name);
          g_error_free (error);
        }
    }

  exec_nasl_script (args, name, nargs->oid, nasl_mode);
  internal_send (soc, NULL,
                 INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
}
