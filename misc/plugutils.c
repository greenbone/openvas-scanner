/* Portions Copyright (C) 2009-2020 Greenbone Networks GmbH
 * Based on work Copyright (C) 1998 - 2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file plugutils.c
 * @brief Plugin-specific stuff.
 */

#include "plugutils.h"

#include "network.h" // for OPENVAS_ENCAPS_IP

#include <errno.h>               // for errno
#include <gvm/base/hosts.h>      // for g_vhost_t
#include <gvm/base/networking.h> // for port_protocol_t
#include <gvm/base/prefs.h>      // for prefs_get_bool
#include <gvm/util/nvticache.h>  // for nvticache_initialized
#include <stdio.h>               // for snprintf
#include <stdlib.h>              // for exit
#include <string.h>              // for strcmp
#include <sys/wait.h>            // for wait
#include <unistd.h>              // for fork

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/* Used to allow debugging for openvas-nasl */
int global_nasl_debug = 0;

/* In case of multiple vhosts fork, this holds the value of the current vhost
 * we're scanning.
 */
gvm_vhost_t *current_vhost = NULL;

/* @brief: Return the currently scanned vhost. */
const char *
plug_current_vhost (void)
{
  return current_vhost->value;
}

static int plug_fork_child (kb_t);

void
plug_set_dep (struct script_infos *args, const char *depname)
{
  nvti_t *n = args->nvti;
  gchar *old = nvti_dependencies (n);
  gchar *new;

  if (!depname)
    return;

  if (old)
    {
      new = g_strdup_printf ("%s, %s", old, depname);
      nvti_set_dependencies (n, new);
      g_free (new);
    }
  else
    nvti_set_dependencies (n, depname);
}

void
host_add_port_proto (struct script_infos *args, int portnum, char *proto)
{
  char port_s[255];
  snprintf (port_s, sizeof (port_s), "Ports/%s/%d", proto, portnum);
  plug_set_key (args, port_s, ARG_INT, (void *) 1);
}

/**
 * @brief Report state of preferences "unscanned_closed".
 *
 * @return 0 if pref is "yes", 1 otherwise.
 */
static int
unscanned_ports_as_closed (port_protocol_t ptype)
{
  if (ptype == PORT_PROTOCOL_UDP)
    return (prefs_get_bool ("unscanned_closed_udp") ? 0 : 1);

  return (prefs_get_bool ("unscanned_closed") ? 0 : 1);
}

/**
 * @param proto Protocol (udp/tcp). If NULL, "tcp" will be used.
 */
int
kb_get_port_state_proto (kb_t kb, int portnum, char *proto)
{
  char port_s[255], *kbstr;
  const char *prange = prefs_get ("port_range");
  port_protocol_t port_type;
  array_t *port_ranges;

  if (!proto)
    proto = "tcp";
  if (!strcmp (proto, "udp"))
    {
      port_type = PORT_PROTOCOL_UDP;
      kbstr = "Host/udp_scanned";
    }
  else
    {
      port_type = PORT_PROTOCOL_TCP;
      kbstr = "Host/scanned";
    }

  /* Check that we actually scanned the port */
  if (kb_item_get_int (kb, kbstr) <= 0)
    return unscanned_ports_as_closed (port_type);

  port_ranges = port_range_ranges (prange);
  if (!port_in_port_ranges (portnum, port_type, port_ranges))
    {
      array_free (port_ranges);
      return unscanned_ports_as_closed (port_type);
    }
  array_free (port_ranges);

  /* Ok, we scanned it. What is its state ? */
  snprintf (port_s, sizeof (port_s), "Ports/%s/%d", proto, portnum);
  return kb_item_get_int (kb, port_s) > 0;
}

int
host_get_port_state_proto (struct script_infos *args, int portnum, char *proto)
{
  return kb_get_port_state_proto (args->key, portnum, proto);
}

int
host_get_port_state (struct script_infos *plugdata, int portnum)
{
  return (host_get_port_state_proto (plugdata, portnum, "tcp"));
}

int
host_get_port_state_udp (struct script_infos *plugdata, int portnum)
{
  return (host_get_port_state_proto (plugdata, portnum, "udp"));
}

/**
 * @brief Check for  duplicated vhosts before inserting a new one.
 *
 * @param args script info structure
 * @param hostname  hostname to check
 *
 * @return 0 if the vhosts was still not added. -1 if the vhosts already exists.
 */
static int
check_duplicated_vhost (struct script_infos *args, const char *hostname)
{
  GSList *vhosts = NULL;
  kb_t host_kb = NULL;
  struct kb_item *current_vhosts = NULL;

  /* Check for duplicate vhost value in args. */
  vhosts = args->vhosts;
  while (vhosts)
    {
      gvm_vhost_t *tmp = vhosts->data;

      if (!strcmp (tmp->value, hostname))
        {
          g_warning ("%s: Value '%s' exists already", __func__, hostname);
          return -1;
        }
      vhosts = vhosts->next;
    }

  /* Check for duplicate vhost value already added by other forked child of the
   * same plugin. */
  host_kb = args->key;
  current_vhosts = kb_item_get_all (host_kb, "internal/vhosts");
  if (!current_vhosts)
    return 0;

  while (current_vhosts)
    {
      if (!strcmp (current_vhosts->v_str, hostname))
        {
          g_warning ("%s: Value '%s' exists already", __func__, hostname);
          kb_item_free (current_vhosts);

          return -1;
        }
      current_vhosts = current_vhosts->next;
    }

  kb_item_free (current_vhosts);
  return 0;
}

int
plug_add_host_fqdn (struct script_infos *args, const char *hostname,
                    const char *source)
{
  gvm_vhost_t *vhost;
  char **excluded;

  if (!prefs_get_bool ("expand_vhosts") || !hostname || !source)
    return -1;

  if (check_duplicated_vhost (args, hostname))
    return -1;

  /* Check for excluded vhost value. */
  if (prefs_get ("exclude_hosts"))
    {
      char **tmp = excluded = g_strsplit (prefs_get ("exclude_hosts"), ",", 0);

      while (*tmp)
        {
          if (!strcmp (g_strstrip (*tmp), hostname))
            {
              g_strfreev (excluded);
              return -1;
            }
          tmp++;
        }
      g_strfreev (excluded);
    }
  vhost = gvm_vhost_new (g_strdup (hostname), g_strdup (source));
  args->vhosts = g_slist_prepend (args->vhosts, vhost);
  return 0;
}

char *
plug_get_host_fqdn (struct script_infos *args)
{
  GSList *vhosts = args->vhosts;

  if (!args->vhosts)
    return addr6_as_str (args->ip);

  /* Workaround for rapid growth of forked processes ie. http_get() calls
   * within foreach() loops. */
  if (current_vhost)
    return g_strdup (current_vhost->value);
  while (vhosts)
    {
      pid_t pid = plug_fork_child (args->key);

      if (pid == 0)
        {
          current_vhost = vhosts->data;
          return g_strdup (current_vhost->value);
        }
      else if (pid == -1)
        return NULL;
      vhosts = vhosts->next;
    }
  exit (0);
}

GSList *
plug_get_host_fqdn_list (struct script_infos *args)
{
  GSList *results = NULL, *vhosts = args->vhosts;

  if (!args->vhosts)
    results = g_slist_prepend (results, addr6_as_str (args->ip));

  while (vhosts)
    {
      gvm_vhost_t *vhost = vhosts->data;

      results = g_slist_prepend (results, g_strdup (vhost->value));
      vhosts = vhosts->next;
    }
  return results;
}

char *
plug_get_host_source (struct script_infos *args, const char *hostname)
{
  if (!args->vhosts)
    return g_strdup ("IP-address");

  if (hostname)
    {
      GSList *vhosts = args->vhosts;

      /* Search for source of specified hostname/vhost. */
      while (vhosts)
        {
          gvm_vhost_t *vhost = vhosts->data;

          if (!strcmp (vhost->value, hostname))
            return g_strdup (vhost->source);
          vhosts = vhosts->next;
        }
      return NULL;
    }
  /* Call plug_get_host_fqdn() to set current_vhost (and fork, in case of
   * multiple vhosts.) */
  if (!current_vhost)
    g_free (plug_get_host_fqdn (args));
  return g_strdup (current_vhost->source);
}

struct in6_addr *
plug_get_host_ip (struct script_infos *args)
{
  return args->ip;
}

char *
plug_get_host_ip_str (struct script_infos *desc)
{
  return addr6_as_str (plug_get_host_ip (desc));
}

/**
 * @brief Post a security message (e.g. LOG, NOTE, WARNING ...).
 *
 * @param oid   The oid of the NVT
 * @param desc  The script infos where to get settings.
 * @param port  Port number related to the issue.
 * @param proto Protocol related to the issue (tcp or udp).
 * @param action The actual result text
 * @param what   The type, like "LOG".
 * @param uri   Location like file path or webservice URL.
 */
void
proto_post_wrapped (const char *oid, struct script_infos *desc, int port,
                    const char *proto, const char *action, const char *what,
                    const char *uri)
{
  const char *hostname = "";
  char *buffer, *data, port_s[16] = "general";
  char ip_str[INET6_ADDRSTRLEN];
  GString *action_str;
  gsize length;
  kb_t kb;

  /* Should not happen, just to avoid trouble stop here if no NVTI found */
  if (!oid)
    return;

  if (action == NULL)
    action_str = g_string_new ("");
  else
    {
      action_str = g_string_new (action);
      g_string_append (action_str, "\n");
    }

  if (port > 0)
    snprintf (port_s, sizeof (port_s), "%d", port);
  if (current_vhost)
    hostname = current_vhost->value;
  else if (desc->vhosts)
    hostname = ((gvm_vhost_t *) desc->vhosts->data)->value;
  addr6_to_str (plug_get_host_ip (desc), ip_str);
  buffer =
    g_strdup_printf ("%s|||%s|||%s/%s|||%s|||%s|||%s", what, hostname ?: " ",
                     port_s, proto, oid, action_str->str, uri ?: "");
  /* Convert to UTF-8 before sending to Manager. */
  data = g_convert (buffer, -1, "UTF-8", "ISO_8859-1", NULL, &length, NULL);
  kb = plug_get_kb (desc);
  kb_item_push_str (kb, "internal/results", data);
  g_free (data);
  g_free (buffer);
  g_string_free (action_str, TRUE);
}

void
proto_post_alarm (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, "ALARM", uri);
}

void
post_alarm (const char *oid, struct script_infos *desc, int port,
            const char *action, const char *uri)
{
  proto_post_alarm (oid, desc, port, "tcp", action, uri);
}

/**
 * @brief Post a log message
 */
void
proto_post_log (const char *oid, struct script_infos *desc, int port,
                const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, "LOG", uri);
}

/**
 * @brief Post a log message about a tcp port.
 */
void
post_log (const char *oid, struct script_infos *desc, int port,
          const char *action)
{
  proto_post_log (oid, desc, port, "tcp", action, NULL);
}

/**
 * @brief Post a log message about a tcp port with a uri
 */
void
post_log_with_uri (const char *oid, struct script_infos *desc, int port,
                   const char *action, const char *uri)
{
  proto_post_log (oid, desc, port, "tcp", action, uri);
}

void
proto_post_error (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action, const char *uri)
{
  proto_post_wrapped (oid, desc, port, proto, action, "ERRMSG", uri);
}

void
post_error (const char *oid, struct script_infos *desc, int port,
            const char *action, const char *uri)
{
  proto_post_error (oid, desc, port, "tcp", action, uri);
}

/**
 * @brief Get the a plugins preference.
 *
 * Search in the preferences set by the client. If it is not
 * present, search in redis cache for the default.
 *
 * @param[in] oid Script OID to get the preference from
 * @param[in] name Name of the preference to get
 * @param[in] pref_id Id of the preferences to get
 *
 * @return script preference on success, Null otherwise.
 **/
char *
get_plugin_preference (const char *oid, const char *name, int pref_id)
{
  GHashTable *prefs;
  GHashTableIter iter;
  char *cname = NULL, *retval = NULL;
  void *itername, *itervalue;
  char prefix[1024], suffix[1024];

  prefs = preferences_get ();
  if (!prefs || !nvticache_initialized () || !oid || (!name && pref_id < 1))
    return NULL;

  g_hash_table_iter_init (&iter, prefs);

  if (pref_id > 0)
    {
      snprintf (prefix, sizeof (prefix), "%s:%d:", oid, pref_id);
      while (g_hash_table_iter_next (&iter, &itername, &itervalue))
        {
          if (g_str_has_prefix (itername, prefix))
            {
              retval = g_strdup (itervalue);
              break;
            }
        }
    }
  else
    {
      cname = g_strdup (name);
      g_strchomp (cname);
      snprintf (prefix, sizeof (prefix), "%s:", oid);
      snprintf (suffix, sizeof (suffix), ":%s", cname);
      /* NVT preferences received in OID:PrefID:PrefType:PrefName form */
      while (g_hash_table_iter_next (&iter, &itername, &itervalue))
        {
          if (g_str_has_prefix (itername, prefix)
              && g_str_has_suffix (itername, suffix))
            {
              retval = g_strdup (itervalue);
              break;
            }
        }
    }

  /* If no value set by the user, get the default one. */
  if (!retval)
    {
      GSList *nprefs, *tmp;

      tmp = nprefs = nvticache_get_prefs (oid);
      while (tmp)
        {
          if ((cname && !strcmp (cname, nvtpref_name (tmp->data)))
              || (pref_id >= 0 && pref_id == nvtpref_id (tmp->data)))
            {
              if (!strcmp (nvtpref_type (tmp->data), "radio"))
                {
                  char **opts =
                    g_strsplit (nvtpref_default (tmp->data), ";", -1);

                  retval = g_strdup (opts[0]);
                  g_strfreev (opts);
                }
              else
                retval = g_strdup (nvtpref_default (tmp->data));

              break;
            }
          tmp = tmp->next;
        }
      g_slist_free_full (nprefs, (void (*) (void *)) nvtpref_free);
    }
  if (cname)
    g_free (cname);
  return retval;
}

/**
 * @brief Get the file name of a plugins preference that is of type "file".
 *
 * As files sent to the server (e.g. as plugin preference) are stored at
 * pseudo-random locations with different names, the "real" file name has to be
 * looked up in a hashtable.
 *
 * @return Filename on disc for \p filename, NULL if not found or setup
 *         broken.
 */
const char *
get_plugin_preference_fname (struct script_infos *desc, const char *filename)
{
  const char *content;
  long contentsize = 0;
  gint tmpfile;
  gchar *tmpfilename;
  GError *error = NULL;

  content = get_plugin_preference_file_content (desc, filename);
  if (content == NULL)
    {
      return NULL;
    }
  contentsize = get_plugin_preference_file_size (desc, filename);
  if (contentsize <= 0)
    return NULL;

  tmpfile =
    g_file_open_tmp ("openvas-file-upload.XXXXXX", &tmpfilename, &error);
  if (tmpfile == -1)
    {
      g_message ("get_plugin_preference_fname: Could not open temporary"
                 " file for %s: %s",
                 filename, error->message);
      g_error_free (error);
      return NULL;
    }
  close (tmpfile);

  if (!g_file_set_contents (tmpfilename, content, contentsize, &error))
    {
      g_message ("get_plugin_preference_fname: could set contents of"
                 " temporary file for %s: %s",
                 filename, error->message);
      g_error_free (error);
      return NULL;
    }

  return tmpfilename;
}

/**
 * @brief Get the file contents of a plugins preference that is of type "file".
 *
 * As files sent to the scanner (e.g. as plugin preference) are stored in a hash
 * table with an identifier supplied by the client as the key, the contents have
 * to be looked up here.
 *
 * @param identifier Identifier that was supplied by the client when the file
 *                   was uploaded.
 *
 * @return Contents of the file identified by \p identifier, NULL if not found
 * or setup broken.
 */
char *
get_plugin_preference_file_content (struct script_infos *desc,
                                    const char *identifier)
{
  struct scan_globals *globals = desc->globals;
  GHashTable *trans;

  if (!globals)
    return NULL;

  trans = globals->files_translation;
  if (!trans)
    return NULL;

  return g_hash_table_lookup (trans, identifier);
}

/**
 * @brief Get the file size of a plugins preference that is of type "file".
 *
 * Files sent to the scanner (e.g. as plugin preference) are stored in a hash
 * table with an identifier supplied by the client as the key. The size of the
 * file is stored in a separate hash table with the same identifier as key,
 * which can be looked up here.
 *
 * @param identifier Identifier that was supplied by the client when the file
 *                   was uploaded.
 *
 * @return Size of the file identified by \p identifier, -1 if not found or
 *         setup broken.
 */
long
get_plugin_preference_file_size (struct script_infos *desc,
                                 const char *identifier)
{
  struct scan_globals *globals = desc->globals;
  GHashTable *trans;
  gchar *filesize_str;

  if (!globals)
    return -1;

  trans = globals->files_size_translation;
  if (!trans)
    return -1;

  filesize_str = g_hash_table_lookup (trans, identifier);
  if (filesize_str == NULL)
    return -1;

  return atol (filesize_str);
}

void
plug_set_key_len (struct script_infos *args, char *name, int type,
                  const void *value, size_t len)
{
  kb_t kb = plug_get_kb (args);

  if (name == NULL || value == NULL)
    return;

  if (type == ARG_STRING)
    kb_item_add_str_unique (kb, name, value, len);
  else if (type == ARG_INT)
    kb_item_add_int_unique (kb, name, GPOINTER_TO_SIZE (value));
  if (global_nasl_debug == 1)
    {
      if (type == ARG_STRING)
        g_message ("set key %s -> %s", name, (char *) value);
      else if (type == ARG_INT)
        g_message ("set key %s -> %d", name, (int) GPOINTER_TO_SIZE (value));
    }
}

void
plug_set_key (struct script_infos *args, char *name, int type,
              const void *value)
{
  plug_set_key_len (args, name, type, value, 0);
}

void
plug_replace_key_len (struct script_infos *args, char *name, int type,
                      void *value, size_t len)
{
  kb_t kb = plug_get_kb (args);

  if (name == NULL || value == NULL)
    return;

  if (type == ARG_STRING)
    kb_item_set_str (kb, name, value, len);
  else if (type == ARG_INT)
    kb_item_set_int (kb, name, GPOINTER_TO_SIZE (value));
  if (global_nasl_debug == 1)
    {
      if (type == ARG_STRING)
        g_message ("replace key %s -> %s", name, (char *) value);
      else if (type == ARG_INT)
        g_message ("replace key %s -> %d", name,
                   (int) GPOINTER_TO_SIZE (value));
    }
}

void
plug_replace_key (struct script_infos *args, char *name, int type, void *value)
{
  plug_replace_key_len (args, name, type, value, 0);
}

void
scanner_add_port (struct script_infos *args, int port, char *proto)
{
  host_add_port_proto (args, port, proto);
}

kb_t
plug_get_kb (struct script_infos *args)
{
  return args->key;
}

static void
plug_get_key_sigchld ()
{
  int status;

  wait (&status);
}

static void
sig_n (int signo, void (*fnc) (int))
{
  struct sigaction sa;

  sa.sa_handler = fnc;
  sa.sa_flags = 0;
  sigemptyset (&sa.sa_mask);
  sigaction (signo, &sa, (struct sigaction *) 0);
}

static void
sig_term (void (*fcn) ())
{
  sig_n (SIGTERM, fcn);
}

static void
sig_chld (void (*fcn) ())
{
  sig_n (SIGCHLD, fcn);
}

static int
plug_fork_child (kb_t kb)
{
  pid_t pid;

  if ((pid = fork ()) == 0)
    {
      sig_term (_exit);
      kb_lnk_reset (kb);
      nvticache_reset ();
      srand48 (getpid () + getppid () + time (NULL));
      return 0;
    }
  else if (pid < 0)
    {
      g_warning ("%s(): fork() failed (%s)", __func__, strerror (errno));
      return -1;
    }
  else
    waitpid (pid, NULL, 0);
  return 1;
}

/**
 * @brief Get values from a kb under the given key name.
 *
 * @param[in]     args   The script infos where to get the kb from.
 * @param[in]     name   Key name to search in the kb.
 * @param[in/out] type   If 1 is given, the answer is forced to be KB_TYPE_INT
 *                       type. Otherwise it returns the fetched type.
 * @param[in]     len    Desired string length to be returned.
 * @param[in]     single In case of a list, fetch only the last element
 *
 * @return Null if no result, or a void pointer to the result in success.
 */
void *
plug_get_key (struct script_infos *args, char *name, int *type, size_t *len,
              int single)
{
  kb_t kb = args->key;
  struct kb_item *res = NULL, *res_list;

  if (type != NULL && *type != KB_TYPE_INT)
    *type = -1;

  if (kb == NULL)
    return NULL;

  if (single && *type != KB_TYPE_INT)
    res = kb_item_get_single (kb, name, KB_TYPE_UNSPEC);
  else if (*type == KB_TYPE_INT)
    res = kb_item_get_single (kb, name, KB_TYPE_INT);
  else
    res = kb_item_get_all (kb, name);

  if (res == NULL)
    return NULL;

  if (!res->next) /* No fork - good */
    {
      void *ret;
      if (res->type == KB_TYPE_INT)
        {
          if (type != NULL)
            *type = KB_TYPE_INT;
          ret = g_memdup (&res->v_int, sizeof (res->v_int));
        }
      else
        {
          if (type != NULL)
            *type = KB_TYPE_STR;
          if (len)
            *len = res->len;
          ret = g_memdup (res->v_str, res->len + 1);
        }
      kb_item_free (res);
      return ret;
    }

  /* More than  one value - we will fork() then */
  sig_chld (plug_get_key_sigchld);
  res_list = res;
  while (res)
    {
      pid_t pid = plug_fork_child (kb);

      if (pid == 0)
        {
          /* Forked child. */
          void *ret;

          if (res->type == KB_TYPE_INT)
            {
              if (type != NULL)
                *type = KB_TYPE_INT;
              ret = g_memdup (&res->v_int, sizeof (res->v_int));
            }
          else
            {
              if (type != NULL)
                *type = KB_TYPE_STR;
              if (len)
                *len = res->len;
              ret = g_memdup (res->v_str, res->len + 1);
            }
          kb_item_free (res_list);
          return ret;
        }
      else if (pid == -1)
        return NULL;
      res = res->next;
    }
  kb_item_free (res_list);
  exit (0);
}

/**
 * Don't always return the first open port, otherwise
 * we might get bitten by OSes doing active SYN flood
 * countermeasures. Also, avoid returning 80 and 21 as
 * open ports, as many transparent proxies are acting for these...
 */
unsigned int
plug_get_host_open_port (struct script_infos *desc)
{
  kb_t kb = plug_get_kb (desc);
  struct kb_item *res, *k;
  int open21 = 0, open80 = 0;
#define MAX_CANDIDATES 16
  u_short candidates[MAX_CANDIDATES];
  int num_candidates = 0;

  k = res = kb_item_get_pattern (kb, "Ports/tcp/*");
  if (res == NULL)
    return 0;
  else
    {
      int ret;
      char *s;

      for (;;)
        {
          s = res->name + sizeof ("Ports/tcp/") - 1;
          ret = atoi (s);
          if (ret == 21)
            open21 = 1;
          else if (ret == 80)
            open80 = 1;
          else
            {
              candidates[num_candidates++] = ret;
              if (num_candidates >= MAX_CANDIDATES)
                break;
            }
          res = res->next;
          if (res == NULL)
            break;
        }

      kb_item_free (k);
      if (num_candidates != 0)
        return candidates[lrand48 () % num_candidates];
      else if (open21)
        return 21;
      else if (open80)
        return 80;
    }

  /* Not reachable */
  return 0;
}

/** @todo
 * Those brain damaged functions should probably be in another file
 * They are use to remember who speaks SSL or not
 */

void
plug_set_port_transport (struct script_infos *args, int port, int tr)
{
  char s[256];

  snprintf (s, sizeof (s), "Transports/TCP/%d", port);
  plug_set_key (args, s, ARG_INT, GSIZE_TO_POINTER (tr));
}

/* Return the transport encapsulation mode (OPENVAS_ENCAPS_*) for the
   given PORT.  If no such encapsulation mode has been stored in the
   knowledge base (or its value is < 0), OPENVAS_ENCAPS_IP is
   currently returned.  */
int
plug_get_port_transport (struct script_infos *args, int port)
{
  char s[256];
  int trp;

  snprintf (s, sizeof (s), "Transports/TCP/%d", port);
  trp = kb_item_get_int (plug_get_kb (args), s);
  if (trp >= 0)
    return trp;
  else
    return OPENVAS_ENCAPS_IP; /* Change this to 0 for ultra smart SSL
                                 negotiation, at the expense of possibly
                                 breaking stuff */
}

static void
plug_set_ssl_item (struct script_infos *args, char *item, char *itemfname)
{
  char s[256];
  snprintf (s, sizeof (s), "SSL/%s", item);
  plug_set_key (args, s, ARG_STRING, itemfname);
}

void
plug_set_ssl_cert (struct script_infos *args, char *cert)
{
  plug_set_ssl_item (args, "cert", cert);
}

void
plug_set_ssl_key (struct script_infos *args, char *key)
{
  plug_set_ssl_item (args, "key", key);
}

void
plug_set_ssl_pem_password (struct script_infos *args, char *key)
{
  plug_set_ssl_item (args, "password", key);
}

/** @TODO Also, all plug_set_ssl*-functions set values that are only accessed
 *        in network.c:open_stream_connection under specific conditions.
 *        Check whether these conditions can actually occur. Document the
 *        functions on the way. */
void
plug_set_ssl_CA_file (struct script_infos *args, char *key)
{
  plug_set_ssl_item (args, "CA", key);
}
