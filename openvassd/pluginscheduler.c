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


#include <includes.h>

#include <openvas/nvt_categories.h>  /* for ACT_SCANNER */
#include <openvas/misc/plugutils.h>  /* for plug_get_required_ports */
#include <openvas/misc/system.h>     /* for emalloc */
#include <openvas/misc/arglists.h>

#include <glib.h>

#define IN_SCHEDULER_CODE 1

#include "pluginscheduler.h"
#include "pluginload.h"
#include "pluginlaunch.h"
#include "preferences.h"
#include "log.h"


/** @TODO
 * The pluginscheduler uses a name cache for NVTs, depedencies and ports, as
 * they are referenced by strings (names or OIDs). To remove duplicate code, the
 * pluginscheduler was changed to share the name cache with the arglists.
 * But the cache of the arglist is much smaller. It should be evaluated whether
 * this influenced the performance (memory imprint should be smaller), and
 * whether the string references could not be replaced e.g. by pointers to NVTi
 * structs.
 */

/** @TODO
 * This important module needs documentation and comments.
 */

#define HASH_MAX 2713


/*-----------------------------------------------------------------------------*/

int
plugin_get_running_state (struct scheduler_plugin *plugin)
{
  return plugin->running_state;
}

void
plugin_set_running_state (plugins_scheduler_t shed,
                          struct scheduler_plugin *plugin, int state)
{
  if (plugin == NULL)
    return;

  plugin->running_state = state;
}

/*-----------------------------------------------------------------------------*/


static unsigned int
mkhash (char *name)
{
  return g_str_hash (name) % HASH_MAX;
}

/*------------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------*
 *
 * A minimalist HASH stucture
 *
 *---------------------------------------------------------------------------*/

static struct hash *
hash_init ()
{
  struct hash *h = emalloc (sizeof (*h) * HASH_MAX + 1);

  return h;
}

static void
hash_link_destroy (struct hash *h)
{
  int i;
  if (h == NULL)
    return;

  if (h->next != NULL)
    hash_link_destroy (h->next);

  if (h->dependencies != NULL)
    {
      for (i = 0; h->dependencies[i] != NULL; i++)
        {
          cache_dec (h->dependencies[i]);
        }
      efree (&h->dependencies);
    }

  efree (&h->dependencies_ptr);
  efree (&h->plugin);

  if (h->ports != NULL)
    {
      for (i = 0; h->ports[i] != NULL; i++)
        {
          cache_dec (h->ports[i]);
        }
      efree (&h->ports);
    }

  efree (&h);
}

static void
hash_destroy (struct hash *h)
{
  int i;

  for (i = 0; i < HASH_MAX; i++)
    {
      hash_link_destroy (h[i].next);
    }
  efree (&h);
}


static int
hash_add (struct hash *h, char *name, struct scheduler_plugin *plugin)
{
  struct hash *l = emalloc (sizeof (struct hash));
  unsigned int idx = mkhash (name);
  struct arglist *deps = plug_get_deps (plugin->arglist->value);
  struct arglist *ports = plug_get_required_ports (plugin->arglist->value);
  int num_deps = 0;

  l->plugin = plugin;
  l->plugin->parent_hash = l;
  l->name = name;
  l->next = h[idx].next;
  h[idx].next = l;
  l->dependencies_ptr = NULL;

  if (deps == NULL)
    l->dependencies = NULL;
  else
    {
      struct arglist *al = deps;
      int i = 0;
      while (al->next)
        {
          num_deps++;
          al = al->next;
        }
      l->dependencies = emalloc ((num_deps + 1) * sizeof (char *));
      al = deps;
      while (al->next != NULL)
        {
          l->dependencies[i++] = cache_inc (al->name);
          l->num_deps++;
          al = al->next;
        }
    }

  if (ports == NULL)
    l->ports = NULL;
  else
    {
      struct arglist *al = ports;
      int num_ports = 0;
      int i = 0;
      while (al->next != NULL)
        {
          num_ports++;
          al = al->next;
        }

      l->ports = emalloc ((num_ports + 1) * sizeof (char *));
      al = ports;
      while (al->next != NULL)
        {
          l->ports[i++] = cache_inc (al->name);
          al = al->next;
        }
    }
  return 0;
}




static struct hash *
_hash_get (struct hash *h, char *name)
{
  unsigned int idx = mkhash (name);
  struct hash *l = h[idx].next;
  while (l != NULL)
    {
      if (strcmp (l->name, name) == 0)
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

  if (l->dependencies_ptr == NULL)
    return NULL;

  return l->dependencies_ptr;
}

static void
hash_fill_deps (struct hash *h, struct hash *l)
{
  int i, j = 0;
  if (l->num_deps != 0)
    {
      l->dependencies_ptr =
        emalloc ((1 + l->num_deps) * sizeof (struct hash *));
      for (i = 0; l->dependencies[i]; i++)
        {
          struct hash *d = _hash_get (h, l->dependencies[i]);
          if (d != NULL)
            l->dependencies_ptr[j++] = d;
          else
            {
              gchar *path = g_path_get_dirname (l->plugin->arglist->name);
              if (g_ascii_strcasecmp (path, ".") != 0)
                {
                  gchar *dep_with_path =
                    g_build_filename (path, l->dependencies[i], NULL);
                  d = _hash_get (h, dep_with_path);
                  g_free (dep_with_path);
                }
              g_free (path);
              if (d != NULL)
                {
                  l->dependencies_ptr[j++] = d;
                }
              else
                {
                  log_write
                    ("scheduler: %s depends on %s which could not be found, thus this dependency is not considered for execution sequence\n",
                     l->plugin->arglist->name, l->dependencies[i]);
                }
            }
        }
      l->dependencies_ptr[j] = NULL;
    }
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
  char **ports = plugin->parent_hash->ports;
  int i;

  if (ports == NULL)
    return;

  for (i = 0; ports[i] != NULL; i++)
    {
      struct plist *pl = pl_get (sched->plist, ports[i]);

      if (pl != NULL)
        pl->occurences++;
      else
        {
          pl = emalloc (sizeof (struct plist));
          strncpy (pl->name, ports[i], sizeof (pl->name) - 1);  /* Share cache_inc() ? */
          pl->occurences = 1;
          pl->next = sched->plist;
          if (sched->plist != NULL)
            sched->plist->prev = pl;
          pl->prev = NULL;
          sched->plist = pl;
        }
    }
}

void
scheduler_rm_running_ports (plugins_scheduler_t sched,
                            struct scheduler_plugin *plugin)
{
  char **ports;
  int i;

  ports = plugin->parent_hash->ports;

  if (ports == NULL)
    return;

  for (i = 0; ports[i] != NULL; i++)
    {
      struct plist *pl = pl_get (sched->plist, ports[i]);

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

              efree (&pl);
            }
        }
      else
        printf ("Warning: scheduler_rm_running_ports failed ?! (%s)\n",
                ports[i]);
    }
}


#if DISABLED_AND_BROKEN

/*
 * Returns the 'score' of the plugin, which means the number of
 * plugins that are already hammering the port this plugin will
 * hammer too
 */
int
scheduler_plugin_score (plugins_scheduler_t sched,
                        struct scheduler_plugin *plugin)
{
  char **ports = hash_get_ports (sched->hash, plugin->arglist->name);
  int i;
  int score = 0;

  if (ports == NULL)
    return 0;

  for (i = 0; ports[i] != NULL; i++)
    {
      struct plist *pl = pl_get (sched->plist, ports[i]);
      if (pl != NULL)
        {
          if (pl->occurences > score)
            score = pl->occurences;
        }
    }
  return score;
}


void
scheduler_plugin_best_score (plugins_scheduler_t sched, int *bscore,
                             struct arglist **bplugin, struct arglist *plugin)
{
  int score = scheduler_plugin_score (sched, plugin);

  if (score < *bscore)
    {
      *bscore = score;
      *bplugin = plugin;
    }
}


#endif




struct scheduler_plugin *
plugin_next_unrun_dependencie (plugins_scheduler_t sched,
                               struct hash **dependencies_ptr,
                               int already_in_dependencie)
{
  int flag = 0;
  int counter = 0;
  int i;

  if (dependencies_ptr == NULL)
    return NULL;

  for (i = 0; dependencies_ptr[i] != NULL; i++)
    {
      struct scheduler_plugin *plugin = dependencies_ptr[i]->plugin;
      if (plugin != NULL)
        {
          int state = plugin_get_running_state (plugin);
          switch (state)
            {
            case PLUGIN_STATUS_UNRUN:
              {
                struct hash **deps_ptr = dependencies_ptr[i]->dependencies_ptr;
                struct scheduler_plugin *ret;
                counter++;
                if (deps_ptr == NULL)
                  return plugin;
                else
                  {
                    ret = plugin_next_unrun_dependencie (sched, deps_ptr, 1);
                    if (ret == NULL)
                      return plugin;
                    else if (ret == PLUG_RUNNING)
                      flag++;
                    else
                      return ret;
                  }
            case PLUGIN_STATUS_RUNNING:
                flag++;
                break;
            case PLUGIN_STATUS_DONE:
                scheduler_rm_running_ports (sched, plugin);
                plugin_set_running_state (sched, plugin,
                                          PLUGIN_STATUS_DONE_AND_CLEANED);
                break;
            case PLUGIN_STATUS_DONE_AND_CLEANED:
                break;
              }
            }
        }
    }

  if (flag == 0)
    return NULL;
  else
    return PLUG_RUNNING;
}

/*---------------------------------------------------------------------------*/

/*
 * Enables a plugin and its dependencies
 */
static void
enable_plugin_and_dependencies (plugins_scheduler_t shed,
                                struct arglist *plugin, char *name, int silent)
{
  struct hash **deps_ptr;
  int i;
  int status;

  if (plugin == NULL)
    return;

  deps_ptr = hash_get_deps_ptr (shed->hash, name);

  status = plug_get_launch (plugin);
  if (status == LAUNCH_DISABLED)
    {
      if (silent == 0)
        plug_set_launch (plugin, LAUNCH_RUN);
      else
        plug_set_launch (plugin, LAUNCH_SILENT);
    }

  if (deps_ptr != NULL)
    {
      for (i = 0; deps_ptr[i] != NULL; i++)
        {
          struct scheduler_plugin *p;
          p = deps_ptr[i]->plugin;
          if (p != NULL && p->arglist != NULL)
            enable_plugin_and_dependencies (shed, p->arglist->value,
                                            p->arglist->name, silent);
        }
    }
}

/*---------------------------------------------------------------------------*/

plugins_scheduler_t
plugins_scheduler_init (struct arglist *plugins, int autoload,
                        int silent_dependencies, int only_network)
{
  plugins_scheduler_t ret = emalloc (sizeof (*ret));
  struct arglist *arg;
  int i;
  struct hash *l;


  if (plugins == NULL)
    return NULL;


  /* Fill our lists */
  ret->hash = hash_init ();
  arg = plugins;
  while (arg->next != NULL)
    {
      struct scheduler_plugin *scheduler_plugin;
      struct list *dup;
      int category = plug_get_category (arg->value);

      scheduler_plugin = emalloc (sizeof (struct scheduler_plugin));
      scheduler_plugin->arglist = arg;
      scheduler_plugin->running_state = PLUGIN_STATUS_UNRUN;
      scheduler_plugin->category = plug_get_category (arg->value);
      scheduler_plugin->timeout = plug_get_timeout (arg->value);

      scheduler_plugin->required_ports = plug_get_required_ports (arg->value);
      scheduler_plugin->required_udp_ports =
        plug_get_required_udp_ports (arg->value);
      scheduler_plugin->required_keys = plug_get_required_keys (arg->value);
      scheduler_plugin->mandatory_keys = plug_get_mandatory_keys (arg->value);
      scheduler_plugin->excluded_keys = plug_get_excluded_keys (arg->value);


      if (category > ACT_LAST)
        category = ACT_LAST;
      dup = emalloc (sizeof (struct list));
      dup->name = scheduler_plugin->arglist->name;
      dup->plugin = scheduler_plugin;
      dup->prev = NULL;
      dup->next = ret->list[category];
      if (ret->list[category] != NULL)
        ret->list[category]->prev = dup;
      ret->list[category] = dup;

      hash_add (ret->hash, arg->name, scheduler_plugin);
      arg = arg->next;
    }


  for (i = 0; i < HASH_MAX; i++)
    {
      l = &ret->hash[i];
      while (l != NULL)
        {
          hash_fill_deps (ret->hash, l);
          l = l->next;
        }
    }

  if (autoload != 0)
    {
      arg = plugins;
      while (arg->next != NULL)
        {
          if (plug_get_launch (arg->value) != LAUNCH_DISABLED)
            enable_plugin_and_dependencies (ret, arg->value, arg->name,
                                            silent_dependencies);
          arg = arg->next;
        }
    }


  /* Now, remove the plugins that won't be launched */
  for (i = ACT_FIRST; i <= ACT_LAST; i++)
    {
      struct list *l = ret->list[i];
      while (l != NULL)
        {
          if (plug_get_launch (l->plugin->arglist->value) == LAUNCH_DISABLED
              && plug_get_category (l->plugin->arglist->value) != ACT_INIT
              && plug_get_category (l->plugin->arglist->value) != ACT_SETTINGS)
            {
              struct list *old = l->next;

              if (l->prev != NULL)
                l->prev->next = l->next;
              else
                ret->list[i] = l->next;


              if (l->next != NULL)
                l->next->prev = l->prev;

              efree (&l);
              l = old;
              continue;
            }
          l = l->next;
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



struct scheduler_plugin *
plugins_scheduler_next (plugins_scheduler_t h)
{
  struct list *l;
  int category;
  int running_category = ACT_LAST;
  int flag = 0;

  if (h == NULL)
    return NULL;

  for (category = ACT_FIRST; category <= ACT_LAST; category++)
    {
      l = h->list[category];

      /*
       * Scanners (and DoS) must not be run in parallel
       */
      if ((category == ACT_SCANNER) || (category == ACT_KILL_HOST)
          || (category == ACT_FLOOD) || (category == ACT_DENIAL))
        pluginlaunch_disable_parrallel_checks ();
      else
        pluginlaunch_enable_parrallel_checks ();

      while (l != NULL)
        {
          int state;

          state = plugin_get_running_state (l->plugin);

          switch (state)
            {
            case PLUGIN_STATUS_UNRUN:
              {
                struct hash **deps_ptr =
                  l->plugin->parent_hash->dependencies_ptr;

                if (deps_ptr != NULL)
                  {
                    struct scheduler_plugin *p =
                      plugin_next_unrun_dependencie (h, deps_ptr, 0);

                    switch (GPOINTER_TO_SIZE (p))
                      {
                      case GPOINTER_TO_SIZE (NULL):
                        scheduler_mark_running_ports (h, l->plugin);
                        plugin_set_running_state (h, l->plugin,
                                                  PLUGIN_STATUS_RUNNING);
                        return l->plugin;

                        break;
                      case GPOINTER_TO_SIZE (PLUG_RUNNING):
                        {
                          /* One of the dependencie is still running  -  we write down its category */
                          if (l->plugin->category < running_category)
                            running_category = l->plugin->category;
                          flag++;
                        }
                        break;
                      default:
                        {
                          /* Launch a dependencie  - don't pay attention to the type */
                          scheduler_mark_running_ports (h, p);
                          plugin_set_running_state (h, p,
                                                    PLUGIN_STATUS_RUNNING);
                          return p;
                        }
                      }
                  }
                else            /* No dependencies */
                  {
                    scheduler_mark_running_ports (h, l->plugin);
                    plugin_set_running_state (h, l->plugin,
                                              PLUGIN_STATUS_RUNNING);
                    return l->plugin;
                  }
              }
              break;
            case PLUGIN_STATUS_RUNNING:
              {
                if (l->plugin->category < running_category)
                  running_category = l->plugin->category;
                flag++;
              }
              break;

            case PLUGIN_STATUS_DONE:
              scheduler_rm_running_ports (h, l->plugin);
              plugin_set_running_state (h, l->plugin,
                                        PLUGIN_STATUS_DONE_AND_CLEANED);
              /* no break - we remove it right away */
            case PLUGIN_STATUS_DONE_AND_CLEANED:
              {
                struct list *old = l->next;

                if (l->prev != NULL)
                  l->prev->next = l->next;
                else
                  h->list[category] = l->next;

                if (l->next != NULL)
                  l->next->prev = l->prev;

                efree (&l);
                l = old;

                continue;
              }
              break;
            }
          l = l->next;
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
list_destroy (struct list *list)
{
  while (list != NULL)
    {
      struct list *next = list->next;
      efree (&list);
      list = next;
    }
}


void
plugins_scheduler_free (plugins_scheduler_t sched)
{
  int i;
  hash_destroy (sched->hash);
  for (i = ACT_FIRST; i < ACT_LAST; i++)
    list_destroy (sched->list[i]);
  efree (&sched);
}
