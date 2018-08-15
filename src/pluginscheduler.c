/* OpenVAS
* $Id$
* Description: Tells openvassd which plugin should be executed next.
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
*
*
*/

#include <string.h> /* for strcmp() */

#include <gvm/util/nvticache.h>     /* for nvticache_t */
#include <gvm/base/prefs.h>         /* for prefs_get() */

#include "../misc/nvt_categories.h"  /* for ACT_SCANNER */
#include "../misc/plugutils.h"  /* for plug_get_launch */

#include <glib.h>
#include <malloc.h>

#include "pluginscheduler.h"
#include "pluginload.h"
#include "pluginlaunch.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/** @TODO
 * This important module needs documentation and comments.
 */

struct plugins_scheduler
{
  GSList *list[ACT_LAST + 1]; /**< Per-category linked-lists of the plugins. */
  int stopped;
};

struct scheduler_plugin *
plugin_next_unrun_dependency (GSList *deps)
{
  int flag = 0;

  if (deps == NULL)
    return NULL;

  while (deps)
    {
      struct scheduler_plugin *plugin;

      plugin = deps->data;
      if (plugin == NULL)
        continue;

      switch (plugin->running_state)
        {
        case PLUGIN_STATUS_UNRUN:
          {
            GSList *deps_ptr;
            struct scheduler_plugin *ret;

            deps_ptr = plugin->deps;
            if (deps_ptr == NULL)
              return plugin;

            ret = plugin_next_unrun_dependency (deps_ptr);
            if (ret == NULL)
              return plugin;

            if (ret == PLUG_RUNNING)
              flag = 1;
            else
              return ret;
          }
          break;
        case PLUGIN_STATUS_RUNNING:
          flag = 1;
          break;
        }
      deps = deps->next;
    }

  if (!flag)
    return NULL;

  return PLUG_RUNNING;
}

/*---------------------------------------------------------------------------*/

static void
plugin_add (plugins_scheduler_t sched, GHashTable *oids_table, int autoload,
            char *oid)
{
  struct scheduler_plugin *plugin;
  int category;
  nvti_t *nvti;

  if (g_hash_table_lookup (oids_table, oid))
    return;

  /* Check if the plugin is deprecated */
  nvti = nvticache_get_nvt (oid);
  if (nvti_tag (nvti)
      && (g_str_has_prefix (nvti_tag (nvti), "deprecated=1")
          || strstr (nvti_tag (nvti), "|deprecated=1")))
    {
      if (prefs_get_bool ("log_whole_attack"))
        {
          char *name = nvticache_get_filename (oid);
          g_message ("Plugin %s is deprecated. "
                     "It will neither loaded nor launched.", name);
          g_free (name);
        }
      nvti_free (nvti);
      return;
    }

  category = nvti_category (nvti);
  plugin = g_malloc0 (sizeof (struct scheduler_plugin));
  plugin->running_state = PLUGIN_STATUS_UNRUN;
  plugin->oid = g_strdup (oid);
  g_hash_table_insert (oids_table, plugin->oid, plugin);

  assert (category <= ACT_LAST);
  sched->list[category] = g_slist_prepend
                           (sched->list[category], plugin);


  /* Add the plugin's dependencies too. */
  if (autoload)
    {
      char *saveptr, *dep_name = NULL, *deps = nvti_dependencies (nvti);

      if (deps)
        dep_name = strtok_r (deps, ", ", &saveptr);
      while (dep_name)
        {
          struct scheduler_plugin *dep_plugin;
          char *dep_oid;

          if ((dep_oid = nvticache_get_oid (dep_name)))
            {
              plugin_add (sched, oids_table, autoload, dep_oid);
              dep_plugin = g_hash_table_lookup (oids_table, dep_oid);
              /* In case of autoload, no need to wait for plugin_add() to
               * fill all enabled plugins to start filling dependencies
               * lists. */
              if (dep_plugin)
                plugin->deps = g_slist_prepend (plugin->deps, dep_plugin);
              else
                g_warning ("There was a problem loading %s (%s), a "
                           "dependency of %s. This can happen e.g. when "
                           "depending on a deprecated NVT.",
                           dep_name, dep_oid, oid);
              g_free (dep_oid);
            }
          else
            g_warning ("There was a problem trying to load %s, a dependency "
                       "of  %s. This may be due to a parse error, or it failed "
                       "to find the dependency. Please check the path to the "
                       "file.", dep_name, oid);
          dep_name = strtok_r (NULL, ", ", &saveptr);
        }
    }
  nvti_free (nvti);
}

static void
plugins_scheduler_fill_deps (plugins_scheduler_t sched, GHashTable *oids_table)
{
  int category;

  for (category = ACT_FIRST; category <= ACT_LAST; category++)
    {
      GSList *element = sched->list[category];

      while (element)
      {
        char *deps;
        struct scheduler_plugin *plugin = element->data;

        assert (plugin->deps == NULL);
        deps = nvticache_get_dependencies (plugin->oid);
        if (deps)
          {
            int i;
            char **array = g_strsplit (deps, ", ", 0);

            for (i = 0; array[i]; i++)
              {
                struct scheduler_plugin *dep_plugin;
                char *dep_oid = nvticache_get_oid (array[i]);
                dep_plugin = g_hash_table_lookup (oids_table, dep_oid);
                if (dep_plugin)
                  plugin->deps = g_slist_prepend (plugin->deps, dep_plugin);
                g_free (dep_oid);
              }
            g_strfreev(array);
            g_free (deps);
          }
        element = element->next;
      }
    }
}

/*
 * Enable plugins in scheduler, from a list.
 *
 * param[in]    sched       Plugins scheduler.
 * param[in]    oid_list    List of plugins to enable.
 * param[in]    autoload    Whether to autoload dependencies.
 */
static void
plugins_scheduler_enable (plugins_scheduler_t sched, const char *oid_list,
                          int autoload)
{
  char *oids, *oid, *saveptr;
  GHashTable *oids_table;

  oids_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  /* Store list of plugins in hashtable. */
  oids = g_strdup (oid_list);
  oid = strtok_r (oids, ";", &saveptr);
  while (oid)
    {
      plugin_add (sched, oids_table, autoload, oid);
      oid = strtok_r (NULL, ";", &saveptr);
    }

  /* When autoload is disabled, each plugin's deps list is still empty. */
  if (!autoload)
    plugins_scheduler_fill_deps (sched, oids_table);

  g_hash_table_destroy (oids_table);
  g_free (oids);
}

int
find_plugin_in_deps (GHashTable *checked, struct scheduler_plugin **array,
                     int pos)
{
  GSList *element = array[pos]->deps;
  int i;

  for (i = 0; i < pos; i++)
    if (array[i] == array[pos])
      return pos;

  if (g_hash_table_lookup (checked, array[pos]))
    return -1;
  while (element)
    {
      int ret;

      array[pos + 1] = element->data;
      ret = find_plugin_in_deps (checked, array, pos + 1);
      if (ret != -1)
        return ret;
      element = element->next;
    }
  g_hash_table_insert (checked, array[pos], array[pos]);
  return -1;
}

int
check_dependency_cycles (plugins_scheduler_t sched)
{
  int i, j;
  GHashTable *checked;

  checked = g_hash_table_new_full (g_str_hash, g_direct_equal, NULL, NULL);
  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    {
      GSList *element = sched->list[i];

      while (element)
        {
          struct scheduler_plugin *array[1024];
          int pos;

          array[0] = element->data;
          pos = find_plugin_in_deps (checked, array, 0);
          if (pos >= 0)
            {
              g_warning ("Dependency cycle:");
              for (j = 0; j <= pos; j++)
                {
                  char *name = nvticache_get_filename (array[j]->oid);

                  g_message (" %s (%s)", name, array[j]->oid);
                  g_free (name);
                }

              g_hash_table_destroy (checked);
              return 1;
            }
          element = element->next;
        }
    }
  g_hash_table_destroy (checked);
  return 0;
}

plugins_scheduler_t
plugins_scheduler_init (const char *plugins_list, int autoload, int only_network)
{
  plugins_scheduler_t ret;
  int i;

  /* Fill our lists */
  ret = g_malloc0 (sizeof (*ret));
  plugins_scheduler_enable (ret, plugins_list, autoload);

  if (only_network)
    {
      for (i = ACT_GATHER_INFO; i <= ACT_LAST; i++)
        {
          ret->list[i] = NULL;
        }
    }

  if (check_dependency_cycles (ret))
    {
      plugins_scheduler_free (ret);
      return NULL;
    }
  malloc_trim (0);
  return ret;
}

int
plugins_scheduler_count_active (plugins_scheduler_t sched)
{
  int ret = 0, i;
  assert (sched);

  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    ret += g_slist_length (sched->list[i]);
  return ret;
}

static struct scheduler_plugin *
get_next_plugin (struct scheduler_plugin *plugin, int *still_running)
{
  assert (plugin);

  switch (plugin->running_state)
    {
    case PLUGIN_STATUS_UNRUN:
      {
        GSList *deps_ptr = plugin->deps;
        struct scheduler_plugin *p;

        if (!deps_ptr)
          {
            plugin->running_state = PLUGIN_STATUS_RUNNING;
            return plugin;
          }

        p = plugin_next_unrun_dependency (deps_ptr);
        switch (GPOINTER_TO_SIZE (p))
          {
          case GPOINTER_TO_SIZE (NULL):
            plugin->running_state = PLUGIN_STATUS_RUNNING;
            return plugin;

            break;
          case GPOINTER_TO_SIZE (PLUG_RUNNING):
            {
              /* One of the dependency is still running */
              *still_running = 1;
            }
            break;
          default:
            {
              /* Launch a dependency  - don't pay attention to the type */
              p->running_state = PLUGIN_STATUS_RUNNING;
              return p;
            }
          }
      }
      break;
    case PLUGIN_STATUS_RUNNING:
      *still_running = 1;
      break;
    }
  return NULL;
}

static struct scheduler_plugin *
get_next_in_range (plugins_scheduler_t h, int start, int end)
{
  int category;
  GSList *element;
  int still_running = 0;

  for (category = start; category <= end; category++)
    {
      element = h->list[category];
      if (category == ACT_SCANNER || category == ACT_KILL_HOST
          || category == ACT_FLOOD || category == ACT_DENIAL)
        pluginlaunch_disable_parallel_checks ();
      while (element)
        {
          struct scheduler_plugin *plugin = get_next_plugin (element->data,
                                                             &still_running);
          if (plugin)
            return plugin;
          element = element->next;
        }
      pluginlaunch_enable_parallel_checks ();
    }
  if (still_running)
    return PLUG_RUNNING;
  return NULL;
}

static void
scheduler_phase_cleanup (plugins_scheduler_t sched, int start, int end)
{
  int category;

  assert (sched);
  for (category = start; category <= end; category++)
    {
      GSList *element = sched->list[category];
      while (element)
        {
          struct scheduler_plugin *plugin = element->data;

          g_free (plugin->oid);
          g_slist_free (plugin->deps);
          plugin->oid = NULL;
          plugin->deps = NULL;
          element = element->next;
        }
      g_slist_free (sched->list[category]);
      sched->list[category] = NULL;
    }
  malloc_trim (0);
}

struct scheduler_plugin *
plugins_scheduler_next (plugins_scheduler_t h)
{
  struct scheduler_plugin *ret;
  static int scheduler_phase = 0;

  if (h == NULL)
    return NULL;

  if (scheduler_phase == 0)
    {
      ret = get_next_in_range (h, ACT_INIT, ACT_INIT);
      if (ret)
        return ret;
      scheduler_phase = 1;
      scheduler_phase_cleanup (h, ACT_INIT, ACT_INIT);
    }
  if (scheduler_phase <= 1)
    {
      ret = get_next_in_range (h, ACT_SCANNER, ACT_SCANNER);
      if (ret)
        return ret;
      scheduler_phase = 2;
      scheduler_phase_cleanup (h, ACT_SCANNER, ACT_SCANNER);
    }
  if (scheduler_phase <= 2)
    {
      ret = get_next_in_range (h, ACT_SETTINGS, ACT_GATHER_INFO);
      if (ret)
        return ret;
      scheduler_phase = 3;
      scheduler_phase_cleanup (h, ACT_SETTINGS, ACT_GATHER_INFO);
    }
  if (scheduler_phase <= 3)
    {
      ret = get_next_in_range (h, ACT_ATTACK, ACT_FLOOD);
      if (ret)
        return ret;
      scheduler_phase = 4;
      scheduler_phase_cleanup (h, ACT_ATTACK, ACT_FLOOD);
    }
  if (scheduler_phase <= 4)
    {
      ret = get_next_in_range (h, ACT_END, ACT_END);
      if (ret)
        return ret;
      scheduler_phase = 5;
      scheduler_phase_cleanup (h, ACT_END, ACT_END);
    }
  return NULL;
}

/*
 * @brief Set all non-ACT_END plugins to stopped.
 *
 * @param   sched   Plugins scheduler.
 */
void
plugins_scheduler_stop (plugins_scheduler_t sched)
{
  int category;

  if (sched->stopped)
    return;
  for (category = ACT_FIRST; category < ACT_END; category++)
    {
      GSList *element = sched->list[category];

      while (element)
      {
        struct scheduler_plugin *plugin = element->data;

        plugin->running_state = PLUGIN_STATUS_DONE;
        element = element->next;
      }
    }
  sched->stopped = 1;
}

void
scheduler_plugin_free (void *data)
{
  struct scheduler_plugin *plugin;
  if (!data)
    return;

  plugin = data;
  g_free (plugin->oid);
  g_slist_free (plugin->deps);
  g_free (plugin);
}

void
plugins_scheduler_free (plugins_scheduler_t sched)
{
  int i;

  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    g_slist_free_full (sched->list[i], scheduler_plugin_free);
  g_free (sched);
}
