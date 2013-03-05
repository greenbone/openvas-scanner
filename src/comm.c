 /* OpenVAS
  * $Id$
  * Description: Communication manager; it manages the NTP Protocol version 1.0 and 1.1.
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

#include <string.h> /* for strchr() */
#include <stdio.h>  /* for fprintf() */
#include <stdlib.h> /* for atoi() */

#include <stdarg.h>

#include <glib.h>

#include <openvas/nasl/nasl.h>
#include <openvas/misc/nvt_categories.h>/* for ACT_FIRST */
#include <openvas/misc/plugutils.h>     /* for plug_set_launch */
#include <openvas/misc/network.h>       /* for recv_line */
#include <openvas/misc/otp.h>           /* for OTP_10 */
#include <openvas/misc/system.h>        /* for emalloc */

#include <openvas/base/nvticache.h>     /* for nvticache_t */

#include "auth.h"

#include "comm.h"
#include "ntp_11.h"
#include "log.h"
#include "pluginscheduler.h"    /* for define LAUNCH_DISABLED */
#include "rules.h"
#include "sighand.h"
#include "utils.h"

/**
 * @brief Initializes the communication between the scanner (us) and the client.
 */
int
comm_init (int soc)
{
  char buf[1024];
  int version = 0;
  int n;

  /* We must read the version of the OTP the client
     wants us to use */
  n = recv_line (soc, buf, sizeof (buf) - 1);
  if (n <= 0)
    exit (0);

  buf[sizeof (buf) - 1] = '\0';
  if (!strncmp (buf, "< OTP/1.0 >", 11))
    {
      version = OTP_10;
      nsend (soc, "< OTP/1.0 >\n", 12, 0);
    }
  else if (!strncmp (buf, "< OTP/1.1 >", 11))
    {
      version = OTP_11;
      nsend (soc, "< OTP/1.1 >\n", 12, 0);
    }
  else
    {
      exit (0);
    }
#ifdef DEBUG
  log_write ("Client requested protocol %s.\n", buf);
#endif
  return (version);
}


/**
 * @brief This function must be called at the end of a session.
 */
void
comm_terminate (struct arglist *globals)
{
  auth_printf (globals, "SERVER <|> BYE <|> BYE <|> SERVER\n");
  /*
     auth_gets(globals, buf, 199);
     if(!strlen(buf))exit(0);
     efree(&buf);
   */
}

/**
 * @brief Checks if a plugin has all new nvt style tags.
 */
static int
plugin_is_newstyle (const nvti_t *nvti)
{
  const char* tag = nvti_tag (nvti);

  return (tag
          && strstr (tag, "summary=")
          && strstr (tag, "affected=")
          && strstr (tag, "insight=")
          && strstr (tag, "detection=")
          && strstr (tag, "impact=")
          && strstr (tag, "solution="));
}

/**
 * @brief Sends a plugin info.
 */
void
send_plug_info (struct arglist *globals, struct arglist *plugins)
{
  int j;
  static const char *categories[] = { ACT_STRING_LIST_ALL };
#define CAT_MAX	(sizeof(categories) / sizeof(categories[0]))
  char *t;
  const char *name, *copyright, *summary, *version, *family = NULL;
  char *description = NULL;
  unsigned int mem_size = 0;
  char *str;
  int ignored = 0;
  char *oid = (char *)arg_get_value (plugins->value, "OID");
  nvticache_t *nvticache = (nvticache_t *)arg_get_value (
    arg_get_value (plugins->value, "preferences"), "nvticache");
  nvti_t *nvti = (oid == NULL ? NULL : nvticache_get_by_oid (nvticache, oid));

  if (!nvti_oid (nvti))
    {
      log_write ("NVT without OID found. Will not be sent.\n");
      nvti_free (nvti);
      return;
    }

  if (plugin_is_newstyle (nvti))
    description = "NODESC";
  else
    {
      t = nvti_description (nvti);
      if (t != NULL)
        {
          description = t = estrdup (t);
          while ((t = strchr (t, '\n')))
            t[0] = ';';
        }
    }

  j = nvti_category (nvti);
  if (j >= CAT_MAX || j < ACT_FIRST)
    j = CAT_MAX - 1;

  version = nvti_version (nvti);
  if (!version)
    version = "?";

  if ((name = nvti_name (nvti)) == NULL)
    {
      log_write ("Inconsistent data (no name): %s - not applying this plugin\n",
                 nvti_oid (nvti));
      name = "Unknown NAME";
      ignored = 1;
    }

  if ((copyright = nvti_copyright (nvti)) == NULL)
    {
      log_write
        ("Inconsistent data (no copyright): %s - not applying this plugin\n",
         name ? name : nvti_oid (nvti));
      copyright = "Unknown COPYRIGHT";
      ignored = 1;
    }

  if (description == NULL)
    {
      log_write ("Inconsistent data (no desc): %s - not applying this plugin\n",
                 name ? name : nvti_oid (nvti));
      ignored = 1;
    }

  if (nvti_tag (nvti) && strstr (nvti_tag (nvti), "summary="))
    summary = "NOSUMMARY";
  else
    summary = nvti_summary (nvti);
  if (summary == NULL)
    {
      log_write
        ("Inconsistent data (no summary): %s - not applying this plugin\n",
         name ? name : nvti_oid (nvti));
      summary = "Unknown SUMMARY";
      ignored = 1;
    }

  if ((family = nvti_family (nvti)) == NULL)
    {
      log_write
        ("Inconsistent data (no family): %s - not applying this plugin\n",
         name ? name : nvti_oid (nvti));
      family = "Unknown FAMILY";
      ignored = 1;
    }


  if (strchr (name, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in name) - %s %s\n", nvti_oid (nvti),
               name);
      ignored = 1;
    }

  if (strchr (copyright, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in copyright)- %s %s\n",
               nvti_oid (nvti), copyright);
      ignored = 1;
    }

  if (description && strchr (description, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in desc) - %s %s\n", nvti_oid (nvti),
               description);
      ignored = 1;
    }

  if (strchr (summary, '\n'))
    {
      fprintf (stderr, "ERROR (newline in summary) - %s %s\n",
               nvti_oid (nvti), summary);
      ignored = 1;
    }

  if (!ignored)
    {
      char *cve_id, *bid, *xref, *sign_keys, *tag;

      cve_id = nvti_cve (nvti);
      if (cve_id == NULL || strcmp (cve_id, "") == 0)
        cve_id = "NOCVE";

      bid = nvti_bid (nvti);
      if (bid == NULL || strcmp (bid, "") == 0)
        bid = "NOBID";

      xref = nvti_xref (nvti);
      if (xref == NULL || strcmp (xref, "") == 0)
        xref = "NOXREF";

      sign_keys = nvti_sign_key_ids (nvti);
      if (sign_keys == NULL || strcmp (sign_keys, "") == 0)
        sign_keys = "NOSIGNKEYS";

      {
        char *index;
        tag = estrdup (nvti_tag (nvti));
        index = tag;
        if (tag == NULL || strcmp (tag, "") == 0)
          tag = "NOTAG";
        else
          while (*index)
            {
              if (*index == '\n')
                *index = ';';
              index++;
            }
      }

      mem_size = strlen (name) +
        strlen (copyright) +
        strlen (description) +
        strlen (summary) +
        strlen (family) +
        strlen (version) +
        strlen (cve_id) +
        strlen (bid) +
        strlen (xref) +
        strlen (sign_keys) +
        strlen (tag) +
        100;                    /* Separators etc. */

      str = emalloc (mem_size);
      snprintf (str, mem_size,
                "%s <|> %s <|> %s <|> "
                "%s <|> %s <|> %s <|> "
                "%s <|> %s <|> %s <|> %s <|> %s <|> %s <|> %s",
                nvti_oid (nvti), name, categories[j],
                copyright, description, summary,
                family, version, cve_id, bid, xref, sign_keys, tag);

      if (tag != NULL && strcmp (tag, "NOTAG"))
        efree (&tag);
      auth_printf (globals, "%s\n", str);
      efree (&str);
    }

  if (description != NULL && strcmp (description, "NODESC"))
    efree (&description);

  nvti_free (nvti);
}

/**
 * @brief Sends the plugin info for a single plugin.
 * @param globals The global arglist holding all plugins.
 * @param oid OID of the plugin to send.
 * @see send_plug_info
 */
void
plugin_send_infos (struct arglist *globals, char *oid)
{
  struct arglist *plugins = arg_get_value (globals, "plugins");

  if (!oid)
    return;
  if (!plugins)
    return;

  while (plugins)
    {
      struct arglist *args = plugins->value;
      if (args && !strcmp (oid, arg_get_value (args, "OID")))
        {
          send_plug_info (globals, plugins);
          return;
        }
      plugins = plugins->next;
    }
}


/**
 * @brief Sends the list of plugins that the scanner could load to the client,
 * @brief using the OTP format (calls send_plug_info for each).
 * @param globals The global arglist.
 * @see send_plug_info
 */
void
comm_send_pluginlist (struct arglist *globals)
{
  struct arglist *plugins = arg_get_value (globals, "plugins");

  auth_printf (globals, "SERVER <|> PLUGIN_LIST <|>\n");
  while (plugins && plugins->next)
    {
      send_plug_info (globals, plugins);
      plugins = plugins->next;
    }
  auth_printf (globals, "<|> SERVER\n");
}

/**
 * @brief Sends the rules of the user.
 */
void
comm_send_rules (struct arglist *globals)
{
  auth_printf (globals, "SERVER <|> RULES <|>\n");
#ifdef USELESS_AS_OF_NOW
  struct openvas_rules *rules = arg_get_value (globals, "rules");
  while (rules && rules->next)
    {
      if (rules->rule == RULES_ACCEPT)
        auth_printf (globals, "accept %c%s/%d\n", rules->not ? '!' : '',
                     inet_ntoa (rules->ip), rules->mask);
      else
        auth_printf (globals, "reject %c%s/%d\n", rules->not ? '!' : '',
                     inet_ntoa (rules->ip), rules->mask);
      rules = rules->next;
    }
#endif
  auth_printf (globals, "<|> SERVER\n");
}

/**
 * @brief Sends the preferences of the scanner.
 * @param globals The global arglist with a "preferences" sub-arglist.
 */
void
comm_send_preferences (struct arglist *globals)
{
  struct arglist *prefs = arg_get_value (globals, "preferences");

  /* We have to be backward compatible with the NTP/1.0 */
  auth_printf (globals, "SERVER <|> PREFERENCES <|>\n");

  while (prefs && prefs->next)
    {
      if (prefs->type == ARG_STRING)
        {
          /*
           * No need to send openvassd-specific preferences
           */
          if (strcmp (prefs->name, "logfile")
              && strcmp (prefs->name, "config_file")
              && strcmp (prefs->name, "plugins_folder")
              && strcmp (prefs->name, "dumpfile")
              && strcmp (prefs->name, "rules")
              && strcmp (prefs->name, "negot_timeout")
              && strcmp (prefs->name, "force_pubkey_auth")
              && strcmp (prefs->name, "log_while_attack")
              && strcmp (prefs->name, "ca_file")
              && strcmp (prefs->name, "key_file")
              && strcmp (prefs->name, "cert_file")
              && strcmp (prefs->name, "be_nice")
              && strcmp (prefs->name, "log_plugins_name_at_load"))
            auth_printf (globals, "%s <|> %s\n", prefs->name,
                         (const char *) prefs->value);
        }
      prefs = prefs->next;
    }
  auth_printf (globals, "server_info_openvassd_version <|> %s\n",
               OPENVASSD_VERSION);
  auth_printf (globals, "server_info_libnasl_version <|> %s\n",
               nasl_version ());
  auth_printf (globals, "server_info_libnessus_version <|> %s\n",
               openvaslib_version ());
  auth_printf (globals, "server_info_thread_manager <|> fork\n");
  auth_printf (globals, "<|> SERVER\n");
}


/**
 * @brief This function waits for the attack order of the client.
 * Meanwhile, it processes all the messages the client could send.
 */
void
comm_wait_order (struct arglist *globals)
{
  int soc = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));

  for (;;)
    {
      static char str[2048];
      int n;

      n = recv_line (soc, str, sizeof (str) - 1);
      if (n < 0)
        {
          log_write ("Client closed the communication\n");
          exit (0);
        }
      if (str[0] == '\0')
        if (!is_client_present (soc))
          exit (0);

      if (ntp_11_parse_input (globals, str) == 0)
        break;
    }
}

/*-------------------------------------------------------------------------------*/

/** @TODO Consolidate sorting mechanisms spread over the openvas project.
 *        Rename function (qsort_oid?). */

/**
 * Q-Sort comparison function.
 * @param a An arglist** to compare against b.
 * @param b An arglist** to compare against a.
 */
static int
qsort_cmp (const void *a, const void *b)
{
  struct arglist **plugin_a = (struct arglist **) a;
  struct arglist **plugin_b = (struct arglist **) b;

  return (strcmp
          (arg_get_value ((*plugin_a)->value, "OID"),
           arg_get_value ((*plugin_b)->value, "OID")));
}

/**
 * Retrieves a plugin defined by its OID from a range within a sorted plugin
 * array.
 * Recursively defined, uses divide and conquer approach.
 */
static struct arglist *
_get_plug_by_oid (struct arglist **array, char *oid, int start, int end,
                  int rend)
{
  int mid;
  char *plugin_oid;

  if (start >= rend)
    return NULL;

  if (start == end)
    {
      plugin_oid = arg_get_value (array[start]->value, "OID");
      if (strcmp (plugin_oid, oid) == 0)
        return array[start];
      else
        return NULL;
    }

  mid = (start + end) / 2;
  plugin_oid = arg_get_value (array[mid]->value, "OID");
  if (strcmp (plugin_oid, oid) > 0)
    return _get_plug_by_oid (array, oid, start, mid, rend);
  else if (strcmp (plugin_oid, oid) < 0)
    return _get_plug_by_oid (array, oid, mid + 1, end, rend);

  return array[mid];
}

/**
 * @brief Retrieves a plugin defined by its OID from a plugin arrray.
 */
static struct arglist *
get_plug_by_oid (struct arglist **array, char *oid, int num_plugins)
{
  return _get_plug_by_oid (array, oid, 0, num_plugins, num_plugins);
}

/*-------------------------------------------------------------------------------*/


/**
 * Enable the plugins which have been selected by the user, or all if
 * list == NULL or list == "-1;";
 * @param globals The Global context to retrieve plugins from.
 * @param list A user (client) defined semicolon delimited list, of plugin(oids)
 *             that shall be enabled. If NULL or "-1;" all plugins are enabled!
 */
void
comm_setup_plugins (struct arglist *globals, char *list)
{
  int num_plugins = 0;
  struct arglist *plugins = arg_get_value (globals, "plugins");
  struct arglist *p = plugins;
  struct arglist **array;
  char *t;
  char *oid;
  int i;
  int enable = LAUNCH_DISABLED;

  if (p == NULL)
    return;
  if (list == NULL)
    list = "-1;";

  if (atoi (list) == -1)
    enable = LAUNCH_RUN;
  /* Disable every plugin */
  while (p->next != NULL)
    {
      num_plugins++;
      plug_set_launch (p->value, enable);
      p = p->next;
    }

  if (num_plugins == 0 || enable != 0)
    return;

  /* Store the plugins in an array for quick access */
  p = plugins;
  i = 0;
  array = emalloc (num_plugins * sizeof (struct arglist **));
  while (p->next != NULL)
    {
      array[i++] = p;
      p = p->next;
    }

  qsort (array, num_plugins, sizeof (struct arglist *), qsort_cmp);

  t = list;
  oid = strtok (t, ";");

  /* Read the list provided by the user and enable the plugins accordingly */
  while (oid != NULL)
    {
      p = get_plug_by_oid (array, oid, num_plugins);
      if (p != NULL)
        plug_set_launch (p->value, LAUNCH_RUN);
#ifdef DEBUG
      else
        log_write ("PLUGIN ID %s NOT FOUND!!!\n", oid);
#endif
      oid = strtok (NULL, ";");
    }

  efree (&array);
}

/**
 * @brief Send the OTP NVT_INFO message and then handle any COMPLETE_LIST
 * and PLUGIN_INFO commands.
 */
void
comm_send_nvt_info (struct arglist *globals)
{
  char buf[2048];

  // @todo It might make sense to send the revision of the feed instead
  // of the static text "DUMMY".
  auth_printf (globals, "SERVER <|> NVT_INFO <|> DUMMY <|> SERVER\n");

  for (;;)
    {
      bzero (buf, sizeof (buf));
      auth_gets (globals, buf, sizeof (buf) - 1);
      if (strstr (buf, "COMPLETE_LIST"))
        comm_send_pluginlist (globals);
      else if (strstr (buf, "PLUGIN_INFO"))
        {
          char *t = strstr (buf, " <|> ");
          char *s;
          if (!t)
            continue;
          t = strstr (t + 5, " <|> ");
          if (!t)
            continue;
          s = t + 5;
          t = strchr (s, ' ');
          if (!t)
            continue;
          t[0] = '\0';
          plugin_send_infos (globals, s);
        }
      else
        break;
    }
}
