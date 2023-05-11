/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file pluginscheduler.c
 * @brief Tells openvas which plugin should be executed next.
 */

#include "pluginscheduler.h"

#include "../misc/nvt_categories.h" /* for ACT_SCANNER */
#include "../misc/plugutils.h"      /* for plug_get_launch */
#include "pluginlaunch.h"
#include "pluginload.h"

#include <glib.h>
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/util/nvticache.h> /* for nvticache_t */
#include <malloc.h>
#include <string.h> /* for strcmp() */

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
  GSList *list[ACT_END + 1]; /**< Per-category linked-lists of the plugins. */
  int stopped;
};

/*---------------------------------------------------------------------------*/

static int
plugin_add (plugins_scheduler_t sched, GHashTable *oids_table,
            GHashTable *names_table, int autoload, char *oid)
{
  struct scheduler_plugin *plugin;
  int category;
  nvti_t *nvti;
  int ret = 0;
  gchar *tag_value;

  if (g_hash_table_lookup (oids_table, oid))
    return 0;

  /* Check if the plugin is deprecated */
  nvti = nvticache_get_nvt (oid);
  if (nvti == NULL)
    {
      g_warning ("The NVT with oid %s was not found in the nvticache.", oid);
      return 1;
    }

  tag_value = nvti_get_tag (nvti, "deprecated");
  if (tag_value && !strcmp (tag_value, "1"))
    {
      if (prefs_get_bool ("log_whole_attack"))
        {
          char *name = nvticache_get_filename (oid);
          g_message ("Plugin %s is deprecated. "
                     "It will neither be loaded nor launched.",
                     name);
          g_free (name);
        }
      nvti_free (nvti);
      g_free (tag_value);
      return 0;
    }

  category = nvti_category (nvti);
  if (!(category >= ACT_INIT && category <= ACT_END))
    {
      g_warning ("The NVT with oid %s has no category assigned. This is "
                 "considered a fatal error, since the NVTI Cache "
                 "structure stored in Redis is out dated or corrupted.",
                 oid);
      nvti_free (nvti);
      return 1;
    }
  plugin = g_malloc0 (sizeof (struct scheduler_plugin));
  plugin->running_state = PLUGIN_STATUS_UNRUN;
  plugin->oid = g_strdup (oid);
  g_hash_table_insert (oids_table, plugin->oid, plugin);

  sched->list[category] = g_slist_prepend (sched->list[category], plugin);

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

          dep_oid = g_hash_table_lookup (names_table, dep_name);
          if (!dep_oid)
            {
              dep_oid = nvticache_get_oid (dep_name);
              g_hash_table_insert (names_table, g_strdup (dep_name), dep_oid);
            }
          if (dep_oid)
            {
              ret =
                plugin_add (sched, oids_table, names_table, autoload, dep_oid);
              if (ret)
                return 1;
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
            }
          else
            {
              char *name = nvticache_get_name (oid);
              g_warning (
                "There was a problem trying to load %s, a dependency "
                "of %s. This may be due to a parse error, or it failed "
                "to find the dependency. Please check the path to the "
                "file.",
                dep_name, name);
              g_free (name);
            }
          dep_name = strtok_r (NULL, ", ", &saveptr);
        }
    }
  nvti_free (nvti);
  return 0;
}

static void
plugins_scheduler_fill_deps (plugins_scheduler_t sched, GHashTable *oids_table)
{
  int category;

  for (category = ACT_INIT; category <= ACT_END; category++)
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
              g_strfreev (array);
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
 *
 * return       error_counter Number of errors found during the schecuduling.
 */
static int
plugins_scheduler_enable (plugins_scheduler_t sched, const char *oid_list,
                          int autoload)
{
  char *oids, *oid, *saveptr;
  GHashTable *oids_table, *names_table;
  int error_counter = 0;

  oids_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
  names_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  /* Store list of plugins in hashtable. */
  oids = g_strdup (oid_list);
  oid = strtok_r (oids, ";", &saveptr);
  while (oid)
    {
      error_counter +=
        plugin_add (sched, oids_table, names_table, autoload, oid);
      oid = strtok_r (NULL, ";", &saveptr);
    }

  /* When autoload is disabled, each plugin's deps list is still empty. */
  if (!autoload)
    plugins_scheduler_fill_deps (sched, oids_table);

  if (error_counter > 0)
    g_warning ("%s: %d errors were found during the plugin scheduling.",
               __func__, error_counter);

  g_hash_table_destroy (oids_table);
  g_hash_table_destroy (names_table);
  g_free (oids);

  return error_counter;
}

static int
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

static int
check_dependency_cycles (plugins_scheduler_t sched)
{
  int i, j;
  GHashTable *checked;

  checked = g_hash_table_new_full (g_str_hash, g_direct_equal, NULL, NULL);
  for (i = ACT_INIT; i <= ACT_END; i++)
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
plugins_scheduler_init (const char *plugins_list, int autoload, int *error)
{
  plugins_scheduler_t ret;

  /* Fill our lists */
  ret = g_malloc0 (sizeof (*ret));
  *error = plugins_scheduler_enable (ret, plugins_list, autoload);

  if (check_dependency_cycles (ret))
    {
      plugins_scheduler_free (ret);
      return NULL;
    }

#ifdef __GLIBC__
  malloc_trim (0);
#endif
  return ret;
}

int
plugins_scheduler_count_active (plugins_scheduler_t sched)
{
  int ret = 0, i;
  assert (sched);

  for (i = ACT_INIT; i <= ACT_END; i++)
    ret += g_slist_length (sched->list[i]);
  return ret;
}

static struct scheduler_plugin *
plugins_next_unrun (GSList *plugins)
{
  int still_running = 0;

  while (plugins)
    {
      struct scheduler_plugin *plugin = plugins->data;
      switch (plugin->running_state)
        {
        case PLUGIN_STATUS_UNRUN:
          {
            struct scheduler_plugin *nplugin;
            GSList *deps_list = plugin->deps;

            nplugin = plugins_next_unrun (deps_list);

            if (nplugin == PLUG_RUNNING)
              still_running = 1;
            else if (nplugin)
              {
                nplugin->running_state = PLUGIN_STATUS_RUNNING;
                return nplugin;
              }
            else
              {
                plugin->running_state = PLUGIN_STATUS_RUNNING;
                return plugin;
              }
            break;
          }
        case PLUGIN_STATUS_RUNNING:
          still_running = 1;
          break;
        case PLUGIN_STATUS_DONE:
          break;
        }
      plugins = plugins->next;
    }
  return still_running ? PLUG_RUNNING : NULL;
}

static struct scheduler_plugin *
get_next_in_range (plugins_scheduler_t h, int start, int end)
{
  int category;
  GSList *element;
  int still_running = 0;

  for (category = start; category <= end; category++)
    {
      struct scheduler_plugin *plugin;
      element = h->list[category];
      if (category == ACT_SCANNER || category == ACT_KILL_HOST
          || category == ACT_FLOOD || category == ACT_DENIAL)
        pluginlaunch_disable_parallel_checks ();

      plugin = plugins_next_unrun (element);
      if (plugin == PLUG_RUNNING)
        still_running = 1;
      else if (plugin)
        return plugin;
      pluginlaunch_enable_parallel_checks ();
    }
  return still_running ? PLUG_RUNNING : NULL;
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
    }
#ifdef __GLIBC__
  malloc_trim (0);
#endif
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
  for (category = ACT_INIT; category < ACT_END; category++)
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

static void
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

  for (i = ACT_INIT; i <= ACT_END; i++)
    g_slist_free_full (sched->list[i], scheduler_plugin_free);
  g_free (sched);
}
