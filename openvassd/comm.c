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
  *
  *
  */

#include <includes.h>
#include <corevers.h>
#include <stdarg.h>

#include <glib.h>

#include <openvas/nasl/nasl.h>
#include <openvas/nvt_categories.h>     /* for ACT_FIRST */

#include "auth.h"

#include "comm.h"
#include "network.h"            /* for recv_line */
#include "otp.h"                /* for OTP_10 */
#include "ntp_11.h"
#include "log.h"
#include "plugs_hash.h"
#include "pluginscheduler.h"    /* for define LAUNCH_DISABLED */
#include "plugutils.h"          /* for plug_get_oid */
#include "rules.h"
#include "sighand.h"
#include "system.h"             /* for emalloc */
#include "utils.h"


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif


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
    EXIT (0);

  buf[sizeof (buf) - 1] = '\0';
  if (!strncmp (buf, "< OTP/1.0 >", 11))
    {
      version = OTP_10;
      nsend (soc, "< OTP/1.0 >\n", 12, 0);
    }
  else
    {
      EXIT (0);
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
     if(!strlen(buf))EXIT(0);
     efree(&buf);
   */
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
  struct arglist *args;
  char *t;
  const char *a, *b, *d, *e = NULL;
  char *desc = NULL;
  unsigned int mem_size = 0;
  char *str;
  int ignored = 0;

  args = plugins->value;

  if (!plug_get_oid (args))
    {
      log_write ("NVT without OID found. Will not be sent.\n");
      return;
    }

  t = plug_get_description (args);

  if (t != NULL)
    {
      desc = t = estrdup (t);
      while ((t = strchr (t, '\n')))
        t[0] = ';';
    }

  j = plug_get_category (args);
  if (j >= CAT_MAX || j < ACT_FIRST)
    j = CAT_MAX - 1;

  e = plug_get_version (args);
  if (!e)
    e = "?";

  if ((a = plug_get_name (args)) == NULL)
    {
      log_write ("Inconsistent data (no name): %s - not applying this plugin\n",
                 plug_get_oid (args));
      a = "Unknown NAME";
      ignored = 1;
    }

  if ((b = plug_get_copyright (args)) == NULL)
    {
      log_write
        ("Inconsistent data (no copyright): %s - not applying this plugin\n",
         a ? a : plug_get_oid (args));
      b = "Unknown COPYRIGHT";
      ignored = 1;
    }

  if (desc == NULL)
    {
      log_write ("Inconsistent data (no desc): %s - not applying this plugin\n",
                 a ? a : plug_get_oid (args));
      ignored = 1;
    }

  if ((d = plug_get_summary (args)) == NULL)
    {
      log_write
        ("Inconsistent data (no summary): %s - not applying this plugin\n",
         a ? a : plug_get_oid (args));
      d = "Unknown SUMMARY";
      ignored = 1;
    }

  if (strchr (a, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in name) - %s %s\n", plug_get_oid (args),
               a);
      ignored = 1;
    }

  if (strchr (b, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in copyright)- %s %s\n",
               plug_get_oid (args), b);
      ignored = 1;

    }

  if (desc && strchr (desc, '\n') != NULL)
    {
      fprintf (stderr, "ERROR (newline in desc) - %s %s\n", plug_get_oid (args),
               desc);
      ignored = 1;

    }

  if (strchr (d, '\n'))
    {
      fprintf (stderr, "ERROR (newline in summary) - %s %s\n",
               plug_get_oid (args), d);
      ignored = 1;
    }

  if (!ignored)
    {
      mem_size = strlen (a) +   /* Name */
        strlen (b) +            /* Copyright */
        strlen (desc) +         /* Description */
        strlen (d) +            /* Summary */
        strlen (e) +            /* Version */
        strlen (plug_get_family (args)) +       /* Family */
        7170 +                  /* CVEs + BIDs + XREFs + Tags + Keys */
        100;                    /* Separators etc. */

      str = emalloc (mem_size);
      snprintf (str, mem_size, "%s <|> %s <|> %s <|> %s <|> %s <|> %s <|> %s",  /* RATS: ignore */
                plug_get_oid (args), a, categories[j], b, desc, d,
                plug_get_family (args));

      strcat (str, " <|> ");    /* RATS: ignore */
      strcat (str, e);          /* RATS: ignore */

      {
        char *id = plug_get_cve_id (args);
        if (id == NULL || strcmp (id, "") == 0)
          id = "NOCVE";
        strcat (str, " <|> ");  /* RATS: ignore */
        strcat (str, id);       /* RATS: ignore */
      }

      {
        char *bid = plug_get_bugtraq_id (args);
        if (bid == NULL || strcmp (bid, "") == 0)
          bid = "NOBID";
        strcat (str, " <|> ");  /* RATS: ignore */
        strcat (str, bid);      /* RATS: ignore */
      }

      {
        char *xref = plug_get_xref (args);
        if (xref == NULL || strcmp (xref, "") == 0)
          xref = "NOXREF";
        strcat (str, " <|> ");  /* RATS: ignore */
        strcat (str, xref);     /* RATS: ignore */
      }

      {
        char *sign_keys = plug_get_sign_key_ids (args);
        if (sign_keys == NULL || strcmp (sign_keys, "") == 0)
          sign_keys = "NOSIGNKEYS";
        strcat (str, " <|> ");  /* RATS: ignore */
        strcat (str, sign_keys);        /* RATS: ignore */
      }

      {
        char *tag = plug_get_tag (args);
        if (tag == NULL || strcmp (tag, "") == 0)
          tag = "NOTAG";
        strcat (str, " <|> ");  /* RATS: ignore */
        strcat (str, tag);      /* RATS: ignore */
      }

      auth_printf (globals, "%s\n", str);
      efree (&str);
    }

  if (desc != NULL)
    efree (&desc);
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
      if (args && !strcmp (oid, plug_get_oid (args)))
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
              && strcmp (prefs->name, "dumpfile") &&
              /* TODO: users is deprecated since 3.0. It may still
                 be around in the config files though.
                 Same is likely the case for various other
                 preferences in this list here. */
              strcmp (prefs->name, "users") && strcmp (prefs->name, "rules") &&
              /* TODO: Same for peks_* */
              strncmp (prefs->name, "peks_", 5)
              && strcmp (prefs->name, "negot_timeout") &&
              /* TODO: Same for cookie_logpipe */
              strcmp (prefs->name, "cookie_logpipe")
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
               OPENVAS_VERSION);
  auth_printf (globals, "server_info_libnasl_version <|> %s\n",
               nasl_version ());
  auth_printf (globals, "server_info_libnessus_version <|> %s\n",
               openvaslib_version ());
#ifdef USE_FORK_THREADS
  auth_printf (globals, "server_info_thread_manager <|> fork\n");
#endif
  auth_printf (globals, "server_info_os <|> %s\n", OVS_OS_NAME);
  auth_printf (globals, "server_info_os_version <|> %s\n", OVS_OS_VERSION);
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
          EXIT (0);
        }
      if (str[0] == '\0')
        if (!is_client_present (soc))
          EXIT (0);

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
          (plug_get_oid ((*plugin_a)->value),
           plug_get_oid ((*plugin_b)->value)));
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
      plugin_oid = plug_get_oid (array[start]->value);
      if (strcmp (plugin_oid, oid) == 0)
        return array[start];
      else
        return NULL;
    }

  mid = (start + end) / 2;
  plugin_oid = plug_get_oid (array[mid]->value);
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
 * @brief Send the OTP PLUGINS_MD5 command.
 */
void
comm_send_md5_plugins (struct arglist *globals)
{
  char *md5;
  char buf[2048];

  md5 = plugins_hash (globals);
  if (md5 == NULL)
    {
      /* This should only happen in severe circumstances */
      log_write ("comm_send_md5_plugins: could not determine plugins hash\n");
      return;
    }
  auth_printf (globals, "SERVER <|> PLUGINS_MD5 <|> %s <|> SERVER\n", md5);
  efree (&md5);


  for (;;)
    {
      bzero (buf, sizeof (buf));
      auth_gets (globals, buf, sizeof (buf) - 1);
      if (strstr (buf, "COMPLETE_LIST"))
        comm_send_pluginlist (globals);
      else if (strstr (buf, "SEND_PLUGINS_MD5"))
        {
          plugins_send_md5 (globals);
        }
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
