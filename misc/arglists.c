/* OpenVAS
 * $Id$
 * Description: Arglists management.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <gvm/base/logging.h>

#include "arglists.h"

#define HASH_MAX 2713

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/**
 * @brief Make a hash value from string.
 *
 * Hash vlaues of argument names are used to speed up the lookups when calling
 * arg_get_value().
 */
static int
mkhash (const char *name)
{
  return g_str_hash (name) % HASH_MAX;
}

/**
 * @brief Struct to cache names (keys) of arglist entries.
 *
 * A lot of entries in our arglists have the same name.
 * We use a caching system to avoid to allocate twice the same name
 *
 * This saves about 300Kb of memory, with minimal performance impact
 */
struct name_cache
{
  char *name;
  int occurences;
  struct name_cache *next;
  struct name_cache *prev;
};

static int cache_inited = 0;
static struct name_cache cache[HASH_MAX + 1];


static void
cache_init ()
{
  int i;
  for (i = 0; i < HASH_MAX + 1; i++)
    {
      bzero (&(cache[i]), sizeof (cache[i]));
    }
  cache_inited = 1;
}

static struct name_cache *
cache_get_name (const char *name, int h)
{
  struct name_cache *nc;

  if (cache_inited == 0)
    cache_init ();

  if (!name)
    return NULL;

  nc = cache[h].next;

  while (nc != NULL)
    {
      if (nc->name != NULL && !strcmp (nc->name, name))
        return nc;
      else
        nc = nc->next;
    }
  return NULL;
}

static struct name_cache *
cache_add_name (const char *name, int h)
{
  struct name_cache *nc;

  if (name == NULL)
    return NULL;

  nc = g_malloc0 (sizeof (struct name_cache));
  nc->next = cache[h].next;
  nc->prev = NULL;
  nc->name = g_strdup (name);
  nc->occurences = 1;
  if (cache[h].next != NULL)
    cache[h].next->prev = nc;

  cache[h].next = nc;

  return nc;
}

static char *
cache_inc (const char *name)
{
  struct name_cache *nc;
  int h = mkhash (name);
  nc = cache_get_name (name, h);
  if (nc != NULL)
    nc->occurences++;
  else
    nc = cache_add_name (name, h);
  return nc->name;
}


static void
cache_dec (const char *name)
{
  struct name_cache *nc;
  int h;

  if (!name)
    return;

  h = mkhash (name);
  nc = cache_get_name (name, h);
  if (nc == NULL)
    return;

  nc->occurences--;
  if (nc->occurences == 0)
    {
      int h = mkhash (name);
      g_free (nc->name);
      nc->name = NULL;
      if (nc->next != NULL)
        nc->next->prev = nc->prev;

      if (nc->prev != NULL)
        nc->prev->next = nc->next;
      else
        cache[h].next = nc->next;

      g_free (nc);
    }
}

void
arg_add_value (arglst, name, type, value)
     struct arglist *arglst;
     const char *name;
     int type;
     void *value;
{
  if (!arglst)
    return;
  while (arglst->next)
    arglst = arglst->next;

  arglst->name = cache_inc (name);
  arglst->value = value;
  arglst->type = type;
  arglst->next = g_malloc0 (sizeof (struct arglist));
  arglst->hash = mkhash (arglst->name);
}

void
arg_prepend_value (struct arglist **list, const char *name, int type,
                   void *value)
{
  struct arglist *new;

  if (!list || !*list)
    return;

  new = g_malloc0 (sizeof (struct arglist));
  new->name = cache_inc (name);
  new->value = value;
  new->type = type;
  new->next = *list;
  new->hash = mkhash (new->name);
  *list = new;
}

static struct arglist *
arg_get (struct arglist *arg, const char *name)
{
  int h = mkhash (name);
  if (arg == NULL)
    return NULL;

  while (arg->next != NULL)
    {
      if (arg->hash == h && strcmp (arg->name, name) == 0)
        return arg;
      else
        arg = arg->next;
    }
  return NULL;
}


int
arg_set_value (arglst, name, value)
     struct arglist *arglst;
     const char *name;
     void *value;
{

  if (name == NULL)
    return -1;

  arglst = arg_get (arglst, name);

  if (arglst != NULL)
    {
      arglst->value = value;
      return 0;
    }
  else
    return -1;
}

int
arg_get_value_int (struct arglist *args, const char *name)
{
  return GPOINTER_TO_SIZE (arg_get_value (args, name));
}

void *
arg_get_value (args, name)
     struct arglist *args;
     const char *name;
{

  if (args == NULL)
    return NULL;

  args = arg_get (args, name);
  if (args == NULL)
    return NULL;
  else
    return (args->value);
}

int
arg_get_type (args, name)
     struct arglist *args;
     const char *name;
{
  args = arg_get (args, name);
  if (args != NULL)
    return (args->type);
  else
    return -1;
}

void
arg_dump (args, level)
     struct arglist *args;
     int level;
{
  const char *spaces = "--------------------";
  if (!args)
    {
      g_message ("Error ! args == NULL");
      return;
    }

  if (args)
    while (args->next)
      {
        switch (args->type)
          {
          case ARG_STRING:

            g_message ("%sargs->%s : %s", spaces + (20 - level),
                       args->name, (char *) args->value);
            break;
          case ARG_ARGLIST:

            g_message ("%sargs->%s :", spaces + (20 - level),
                       args->name);
            arg_dump (args->value, level + 1);
            break;
          case ARG_INT:
            g_message ("%sargs->%s : %d", spaces + (20 - level),
                       args->name, (int) GPOINTER_TO_SIZE (args->value));
            break;
          default:
            g_message ("%sargs->%s : %d", spaces + (20 - level),
                       args->name, (int) GPOINTER_TO_SIZE (args->value));
            break;
          }
        args = args->next;
      }
}

void
arg_free (arg)
     struct arglist *arg;
{
  while (arg)
    {
      struct arglist *next = arg->next;
      cache_dec (arg->name);
      g_free (arg);
      arg = next;
    }
}


void
arg_free_all (arg)
     struct arglist *arg;
{
  while (arg)
    {
      struct arglist *next = arg->next;
      switch (arg->type)
        {
        case ARG_ARGLIST:
          arg_free_all (arg->value);
          break;
        case ARG_STRING:
          g_free (arg->value);
          break;
        }
      cache_dec (arg->name);
      g_free (arg);
      arg = next;
    }
}

void
arg_del_value (args, name)
     struct arglist *args;
     const char *name;
{
  int h = mkhash (name);
  struct arglist *pivot;
  struct arglist *element = NULL;
  struct arglist store;

  if (args == NULL)
    return;

  pivot = args;

  while (pivot->next != NULL)
    {
      if (pivot->hash == h && strcmp (pivot->name, name) == 0)
        {
          element = pivot;
          break;
        }
      pivot = pivot->next;
    }

  if (!element || element->hash != h || strcmp (element->name, name))
    return;

  if (args == element)
    {
      element = args->next;
      memcpy (&store, element, sizeof (struct arglist));
      memcpy (element, args, sizeof (struct arglist));
      memcpy (args, &store, sizeof (struct arglist));
    }
  else
    {
      pivot = args;
      while (pivot->next != NULL && pivot->next != element)
        pivot = pivot->next;
      pivot->next = element->next;
    }
  element->next = NULL;

  arg_free (element);
}
