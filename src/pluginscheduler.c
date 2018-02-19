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

#include <openvas/base/nvti.h>  /* for nvti_t */

#include <openvas/misc/nvt_categories.h>  /* for ACT_SCANNER */
#include <openvas/misc/plugutils.h>  /* for plug_get_launch */

#include <openvas/base/nvticache.h>     /* for nvticache_t */

#include <glib.h>

#include "pluginscheduler.h"
#include "pluginload.h"
#include "pluginlaunch.h"
#include "log.h"

/** @TODO
 * This important module needs documentation and comments.
 */

#define HASH_MAX 2713

struct hash
{
  struct scheduler_plugin *plugin;
  struct hash **dependencies_ptr;
  struct hash *next;
};

struct list
{
  struct scheduler_plugin *plugin;
  struct list *next;
  struct list *prev;
};

struct plist
{
  gchar *name;
  int occurences;
  struct plist *next;
  struct plist *prev;
};

struct plugins_scheduler
{
  struct hash *hash;                /**< Hash list of the plugins.   */
  struct list *list[ACT_LAST + 1];  /**< Linked list of the plugins. */
  struct plist *plist;              /**< Ports currently in use.     */
};

static unsigned int
mkhash (char *name)
{
  return g_str_hash (name) % HASH_MAX;
}


/*---------------------------------------------------------------------------*
 *
 * A minimalist HASH stucture
 *
 *---------------------------------------------------------------------------*/

static struct hash *
hash_init ()
{
  struct hash *h = g_malloc0 (HASH_MAX * sizeof (*h));

  return h;
}

static void
hash_link_destroy (struct hash *h)
{
  if (h == NULL)
    return;

  if (h->next != NULL)
    hash_link_destroy (h->next);

  g_free (h->dependencies_ptr);
  g_free (h->plugin);
  g_free (h);
}

static void
hash_destroy (struct hash *h)
{
  int i;

  for (i = 0; i < HASH_MAX; i++)
    {
      hash_link_destroy (h[i].next);
    }
  g_free (h);
}


static void
hash_add (struct hash *h, struct scheduler_plugin *plugin)
{
  struct hash *l = g_malloc0 (sizeof (struct hash));
  unsigned int idx = mkhash (plugin->oid);

  l->plugin = plugin;
  l->plugin->parent_hash = l;
  l->next = h[idx].next;
  h[idx].next = l;
  l->dependencies_ptr = NULL;

}


static struct hash *
_hash_get (struct hash *h, char *name)
{
  unsigned int idx = mkhash (name);
  struct hash *l = h[idx].next;
  while (l != NULL)
    {
      if (strcmp (l->plugin->oid, name) == 0)
        return l;
      else
        l = l->next;
    }
  return NULL;
}


static struct hash **
hash_get_deps_ptr (struct hash *h, char *name)
{
  struct hash *l = _hash_get (h, name);

  if (l == NULL)
    return NULL;

  return l->dependencies_ptr;
}

static void
hash_fill_deps (struct hash *h, struct hash *l)
{
  int i, j = 0, num_deps;
  char *dependencies, **array;

  if (!l->plugin)
    return;
  dependencies = nvticache_get_dependencies (l->plugin->oid);
  if (!dependencies)
    return;
  array = g_strsplit (dependencies, ", ", 0);
  g_free (dependencies);
  if (!array)
    return;

  for (num_deps = 0; array[num_deps]; num_deps++)
    ;
  if (num_deps == 0)
    return;

  l->dependencies_ptr = g_malloc0 ((1 + num_deps) * sizeof (struct hash *));
  for (i = 0; array[i]; i++)
    {
      char *oid;
      struct hash *d;

      oid = nvticache_get_oid (array[i]);
      if (!oid)
        {
          log_write ("scheduler: %s depends on %s which could not be found",
                     l->plugin->oid, array[i]);
          continue;
        }
      d = _hash_get (h, oid);
      if (d != NULL)
        l->dependencies_ptr[j++] = d;
      else
        log_write ("scheduler: %s depends on %s which could not be found",
                   l->plugin->oid, array[i]);
      g_free (oid);
    }
  l->dependencies_ptr[j] = NULL;
  g_strfreev (array);
}

/*----------------------------------------------------------------------*/

struct plist *
pl_get (struct plist *list, char *name)
{
  while (list != NULL)
    {
      if (strcmp (list->name, name) == 0)
        return list;
      else
        list = list->next;
    }
  return NULL;
}


/*----------------------------------------------------------------------*
 *									*
 * Utilities								*
 *									*
 *----------------------------------------------------------------------*/



void
scheduler_mark_running_ports (plugins_scheduler_t sched,
                              struct scheduler_plugin *plugin)
{
  char *ports, **array;
  int i;

  ports = nvticache_get_required_ports (plugin->oid);
  if (!ports)
    return;

  array = g_strsplit (ports, ", ", 0);
  g_free (ports);
  if (!array)
    return;
  for (i = 0; array[i] != NULL; i++)
    {
      struct plist *pl = pl_get (sched->plist, array[i]);

      if (pl != NULL)
        pl->occurences++;
      else
        {
          pl = g_malloc0 (sizeof (struct plist));
          pl->name = g_strdup (array[i]);
          pl->occurences = 1;
          pl->next = sched->plist;
          if (sched->plist != NULL)
            sched->plist->prev = pl;
          pl->prev = NULL;
          sched->plist = pl;
        }
    }
  g_strfreev (array);
}

void
scheduler_rm_running_ports (plugins_scheduler_t sched,
                            struct scheduler_plugin *plugin)
{
  char *ports, **array;
  int i;

  ports = nvticache_get_required_ports (plugin->oid);
  if (!ports)
    return;

  array = g_strsplit (ports, ", ", 0);
  g_free (ports);
  if (!array)
    return;
  for (i = 0; array[i] != NULL; i++)
    {
      struct plist *pl = pl_get (sched->plist, array[i]);

      if (pl != NULL)
        {
          pl->occurences--;
          if (pl->occurences == 0)
            {
              if (pl->next != NULL)
                pl->next->prev = pl->prev;

              if (pl->prev != NULL)
                pl->prev->next = pl->next;
              else
                sched->plist = pl->next;

              g_free (pl->name);
              g_free (pl);
            }
        }
      else
        log_write ("Warning: scheduler_rm_running_ports failed ?! (%s)\n",
                   array[i]);
    }
  g_strfreev (array);
}


struct scheduler_plugin *
plugin_next_unrun_dependency (plugins_scheduler_t sched,
                              struct hash **dependencies_ptr, int calls)
{
  int flag = 0;
  int i;

  if (dependencies_ptr == NULL)
    return NULL;

  if (calls > 100)
    {
      log_write ("Possible dependency cycle detected %s",
                 dependencies_ptr[0]->plugin->oid);
      return NULL;
    }

  for (i = 0; dependencies_ptr[i] != NULL; i++)
    {
      struct scheduler_plugin *plugin;

      plugin = dependencies_ptr[i]->plugin;
      if (plugin == NULL)
        continue;

      switch (plugin->running_state)
        {
        case PLUGIN_STATUS_UNRUN:
          {
            struct hash **deps_ptr;
            struct scheduler_plugin *ret;

            deps_ptr = dependencies_ptr[i]->dependencies_ptr;
            if (deps_ptr == NULL)
              return plugin;

            ret = plugin_next_unrun_dependency (sched, deps_ptr, calls + 1);
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
        case PLUGIN_STATUS_DONE:
          scheduler_rm_running_ports (sched, plugin);
          plugin->running_state = PLUGIN_STATUS_DONE_AND_CLEANED;
          break;
        case PLUGIN_STATUS_DONE_AND_CLEANED:
          break;
        }
    }

  if (!flag)
    return NULL;

  return PLUG_RUNNING;
}

/*---------------------------------------------------------------------------*/

/*
 * Enables a plugin and its dependencies
 */
static void
enable_plugin_and_dependencies (plugins_scheduler_t shed,
                                struct scheduler_plugin *plugin,
                                GHashTable *deps_table)
{
  struct hash **deps_ptr;
  int i;

  if (plugin == NULL)
    return;

  if (g_hash_table_lookup (deps_table, plugin->oid))
    return;
  else
    g_hash_table_insert (deps_table, g_strdup (plugin->oid), plugin->oid);

  plugin->enabled = TRUE;
  deps_ptr = hash_get_deps_ptr (shed->hash, plugin->oid);
  if (deps_ptr == NULL)
    return;
  for (i = 0; deps_ptr[i] != NULL; i++)
    {
      struct scheduler_plugin *p;
      p = deps_ptr[i]->plugin;
      if (p)
        enable_plugin_and_dependencies (shed, p, deps_table);
    }
}

/*---------------------------------------------------------------------------*/

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
  int i;
  char *oids, *oid;
  GHashTable *oids_table;

  oids_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  /* Store list of plugins in hashtable. */
  oids = g_strdup (oid_list);
  oid = strtok (oids, ";");
  while (oid)
    {
      g_hash_table_insert (oids_table, oid, oid);
      oid = strtok (NULL, ";");
    }

  /* Enable plugins found in hashtable. */
  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    {
      struct list *element = sched->list[i];

      while (element)
        {
          if (g_hash_table_lookup (oids_table, element->plugin->oid))
            element->plugin->enabled = TRUE;

          element = element->next;
        }
    }
  g_hash_table_destroy (oids_table);
  g_free (oids);

  if (autoload != 0)
    {
      for (i = ACT_FIRST; i <= ACT_LAST; i++)
        {
          struct list *element = sched->list[i];

          while (element)
            {
              /* deps_table is used to prevent circular dependencies. */
              GHashTable *deps_table;

              deps_table = g_hash_table_new_full
                            (g_str_hash, g_str_equal, g_free, NULL);
              if (element->plugin->enabled)
                enable_plugin_and_dependencies (sched, element->plugin,
                                                deps_table);

              g_hash_table_destroy (deps_table);
              element = element->next;
            }
        }
    }
}

static void
plugins_scheduler_fill (plugins_scheduler_t sched)
{
  int i;
  GSList *list, *element;

  list = element = nvticache_get_oids ();
  while (element)
    {
      struct scheduler_plugin *scheduler_plugin;
      struct list *dup;
      int category;

      category = nvticache_get_category (element->data);
      scheduler_plugin = g_malloc0 (sizeof (struct scheduler_plugin));
      scheduler_plugin->running_state = PLUGIN_STATUS_UNRUN;
      scheduler_plugin->oid = g_strdup (element->data);
      scheduler_plugin->enabled = FALSE;

      assert (category <= ACT_LAST);
      dup = g_malloc0 ( sizeof (struct list));
      dup->plugin = scheduler_plugin;
      dup->prev = NULL;
      dup->next = sched->list[category];
      if (sched->list[category] != NULL)
        sched->list[category]->prev = dup;
      sched->list[category] = dup;

      hash_add (sched->hash, scheduler_plugin);
      element = element->next;
    }
  g_slist_free_full (list, g_free);

  for (i = 0; i < HASH_MAX; i++)
    {
      struct hash *l = &sched->hash[i];
      while (l != NULL)
        {
          hash_fill_deps (sched->hash, l);
          l = l->next;
        }
    }

}

plugins_scheduler_t
plugins_scheduler_init (const char *plugins_list, int autoload, int only_network)
{
  plugins_scheduler_t ret;
  int i;

  /* Fill our lists */
  ret = g_malloc0 (sizeof (*ret));
  ret->hash = hash_init ();
  plugins_scheduler_fill (ret);

  plugins_scheduler_enable (ret, plugins_list, autoload);

  /* Now, remove the plugins that won't be launched */
  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    {
      struct list *plist = ret->list[i];

      while (plist != NULL)
        {
          if (!plist->plugin->enabled)
            {
              struct list *old = plist->next;

              if (plist->prev != NULL)
                plist->prev->next = plist->next;
              else
                ret->list[i] = plist->next;

              if (plist->next != NULL)
                plist->next->prev = plist->prev;

              g_free (plist);
              plist = old;
              continue;
            }
          plist = plist->next;
        }
    }

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
    {
      struct list *element = sched->list[i];

      while (element)
        {
          if (element->plugin->enabled)
            ret++;
          element = element->next;
        }
    }
  return ret;
}

static struct scheduler_plugin *
get_next_plugin (plugins_scheduler_t h, struct scheduler_plugin *plugin,
                 int *still_running)
{
  assert (plugin);

  switch (plugin->running_state)
    {
    case PLUGIN_STATUS_UNRUN:
      {
        struct hash **deps_ptr = plugin->parent_hash->dependencies_ptr;

        if (deps_ptr)
          {
            struct scheduler_plugin *p =
              plugin_next_unrun_dependency (h, deps_ptr, 0);

            switch (GPOINTER_TO_SIZE (p))
              {
              case GPOINTER_TO_SIZE (NULL):
                scheduler_mark_running_ports (h, plugin);
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
                  scheduler_mark_running_ports (h, p);
                  p->running_state = PLUGIN_STATUS_RUNNING;
                  return p;
                }
              }
          }
        else            /* No dependencies */
          {
            scheduler_mark_running_ports (h, plugin);
            plugin->running_state = PLUGIN_STATUS_RUNNING;
            return plugin;
          }
      }
      break;
    case PLUGIN_STATUS_RUNNING:
      *still_running = 1;
      break;
    case PLUGIN_STATUS_DONE:
      scheduler_rm_running_ports (h, plugin);
      plugin->running_state = PLUGIN_STATUS_DONE_AND_CLEANED;
      /* fallthrough */
    case PLUGIN_STATUS_DONE_AND_CLEANED:
      return NULL;
    }
  return NULL;
}

static struct scheduler_plugin *
get_next_in_range (plugins_scheduler_t h, int start, int end)
{
  int category;
  struct list *element;
  int still_running = 0;

  for (category = start; category <= end; category++)
    {
      element = h->list[category];
      if (category == ACT_SCANNER || category == ACT_KILL_HOST
          || category == ACT_FLOOD || category == ACT_DENIAL)
        pluginlaunch_disable_parrallel_checks ();
      while (element)
        {
          struct scheduler_plugin *plugin = get_next_plugin (h, element->plugin,
                                                             &still_running);
          if (plugin)
            return plugin;
          element = element->next;
        }
      pluginlaunch_enable_parrallel_checks ();
    }
  if (still_running)
    return PLUG_RUNNING;
  return NULL;
}

struct scheduler_plugin *
plugins_scheduler_next (plugins_scheduler_t h)
{
  struct scheduler_plugin *ret;

  if (h == NULL)
    return NULL;
  ret = get_next_in_range (h, ACT_INIT, ACT_INIT);
  if (ret)
    return ret;
  ret = get_next_in_range (h, ACT_SCANNER, ACT_SCANNER);
  if (ret)
    return ret;
  ret = get_next_in_range (h, ACT_SETTINGS, ACT_GATHER_INFO);
  if (ret)
    return ret;
  ret = get_next_in_range (h, ACT_ATTACK, ACT_FLOOD);
  if (ret)
    return ret;
  ret = get_next_in_range (h, ACT_END, ACT_END);
  if (ret)
    return ret;
  return NULL;
}

void
list_destroy (struct list *list)
{
  while (list != NULL)
    {
      struct list *next = list->next;
      g_free (list);
      list = next;
    }
}

void
plugins_scheduler_free (plugins_scheduler_t sched)
{
  int i;
  hash_destroy (sched->hash);
  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    list_destroy (sched->list[i]);
  g_free (sched);
}
