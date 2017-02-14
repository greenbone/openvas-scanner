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

#include <openvas/misc/nvt_categories.h>  /* for ACT_SCANNER */
#include <openvas/misc/plugutils.h>  /* for plug_get_launch */

#include <glib.h>

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
};

struct scheduler_plugin *
plugin_next_unrun_dependency (plugins_scheduler_t sched, GSList *deps, int calls)
{
  int flag = 0;

  if (deps == NULL)
    return NULL;

  if (calls > 100)
    {
      g_debug ("Possible dependency cycle detected %s",
                 ((struct scheduler_plugin *) deps->data)->oid);
      return NULL;
    }

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

            deps_ptr = ((struct scheduler_plugin *) deps->data)->deps;
            if (deps_ptr == NULL)
              return plugin;

            ret = plugin_next_unrun_dependency (sched, deps_ptr, calls++);
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

  if (g_hash_table_lookup (oids_table, oid))
    return;

  category = nvticache_get_category (oid);
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
      char *deps = nvticache_get_dependencies (oid);

      if (deps)
        {
          int i;
          char **array = g_strsplit (deps, ", ", 0);

          for (i = 0; array[i]; i++)
            {
              struct scheduler_plugin *dep_plugin;
              char *dep_oid = nvticache_get_oid (array[i]);
              plugin_add (sched, oids_table, autoload, dep_oid);
              dep_plugin = g_hash_table_lookup (oids_table, dep_oid);
              /* In case of autoload, no need to wait for plugin_add() to fill
               * all enabled plugins to start filling dependencies lists. */
              assert (dep_plugin);
              plugin->deps = g_slist_prepend (plugin->deps, dep_plugin);
              g_free (dep_oid);
            }
          g_strfreev(array);
          g_free (deps);
        }
    }
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
  char *oids, *oid;
  GHashTable *oids_table;

  oids_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  /* Store list of plugins in hashtable. */
  oids = g_strdup (oid_list);
  oid = strtok (oids, ";");
  while (oid)
    {
      plugin_add (sched, oids_table, autoload, oid);
      oid = strtok (NULL, ";");
    }

  /* When autoload is disabled, each plugin's deps list is still empty. */
  if (!autoload)
    plugins_scheduler_fill_deps (sched, oids_table);

  g_hash_table_destroy (oids_table);
  g_free (oids);
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

struct scheduler_plugin *
plugins_scheduler_next (plugins_scheduler_t h)
{
  int category;
  int running_category = ACT_LAST;
  int flag = 0;

  if (h == NULL)
    return NULL;

  for (category = ACT_FIRST; category <= ACT_LAST; category++)
    {
      GSList *element = h->list[category];

      /*
       * Scanners (and DoS) must not be run in parallel
       */
      if ((category == ACT_SCANNER) || (category == ACT_KILL_HOST)
          || (category == ACT_FLOOD) || (category == ACT_DENIAL))
        pluginlaunch_disable_parrallel_checks ();
      else
        pluginlaunch_enable_parrallel_checks ();

      while (element != NULL)
        {
          struct scheduler_plugin *plugin = element->data;
          switch (plugin->running_state)
            {
            case PLUGIN_STATUS_UNRUN:
              {
                GSList *deps_ptr = plugin->deps;

                if (deps_ptr != NULL)
                  {
                    struct scheduler_plugin *p =
                      plugin_next_unrun_dependency (h, deps_ptr, 0);

                    switch (GPOINTER_TO_SIZE (p))
                      {
                      case GPOINTER_TO_SIZE (NULL):
                        plugin->running_state = PLUGIN_STATUS_RUNNING;
                        return plugin;

                        break;
                      case GPOINTER_TO_SIZE (PLUG_RUNNING):
                        {
                          /* One of the dependency is still running
                           * we write down its category */

                          int category = nvticache_get_category (plugin->oid);
                          if (category < running_category)
                            running_category = category;
                          flag++;
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
                else            /* No dependencies */
                  {
                    plugin->running_state = PLUGIN_STATUS_RUNNING;
                    return plugin;
                  }
              }
              break;
            case PLUGIN_STATUS_RUNNING:
              {
                int category = nvticache_get_category (plugin->oid);
                if (category < running_category)
                  running_category = category;
                flag++;
              }
              break;
            }
          element = element->next;
        }


      /* Could not find anything */
      if ((category == ACT_SCANNER || category == ACT_INIT
           || category == ACT_SETTINGS) && flag != 0)
        {
          pluginlaunch_wait_for_free_process ();
          flag = 0;
          category--;
        }

      if (category + 1 >= ACT_DENIAL && flag && running_category < ACT_DENIAL)
        {
          return PLUG_RUNNING;
        }
    }

  return flag != 0 ? PLUG_RUNNING : NULL;
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
