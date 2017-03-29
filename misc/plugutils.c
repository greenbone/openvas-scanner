/* OpenVAS
 * $Id$
 * Description: Plugin-specific stuff.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2003 Renaud Deraison
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#include <glib.h>

#include <gvm/base/networking.h>
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h>          /* for prefs_get_bool */
#include <gvm/util/kb.h>
#include <gvm/util/nvticache.h>      /* for nvticache_get_by_oid() */

#include "network.h"
#include "plugutils.h"
#include "internal_com.h"


#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/* Used to allow debugging for openvas-nasl */
int global_nasl_debug = 0;

void
plug_set_xref (struct script_infos *args, char *name, char *value)
{
  nvti_t *n = args->nvti;
  char *new;

  if (nvti_xref (n))
    new = g_strconcat (nvti_xref (n), ", ", name, ":", value, NULL);
  else
    new = g_strconcat (name, ":", value, NULL);

  nvti_set_xref (n, new);
  g_free (new);
}

void
plug_set_tag (struct script_infos *args, char *name, char *value)
{
  nvti_t *n = args->nvti;
  char *new;

  if (nvti_tag (n))
    new = g_strconcat (nvti_tag (n), "|", name, "=", value, NULL);
  else
    new = g_strconcat (name, "=", value, NULL);

  nvti_set_tag (n, new);
  g_free (new);
}

void
plug_set_dep (struct script_infos *args, const char *depname)
{
  nvti_t *n = args->nvti;
  gchar * old = nvti_dependencies (n);
  gchar * new;

  if (!depname) return;

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


const char *
plug_get_hostname (struct script_infos *args)
{
  struct host_info *hinfo = args->hostname;
  if (hinfo)
    return hinfo->name;
  else
    return (NULL);
}

char *
plug_get_host_fqdn (struct script_infos *args)
{
  struct host_info *hinfos = args->hostname;
  if (hinfos)
    {
      int type;
      char *vhosts = plug_get_key (args, "hostinfos/vhosts", &type, NULL, 0);
      if (vhosts)
        return vhosts;
      else
        return g_strdup (hinfos->fqdn);
    }
  else
    return (NULL);
}


struct in6_addr *
plug_get_host_ip (struct script_infos *args)
{
  struct host_info *hinfos = args->hostname;
  if (hinfos)
    return hinfos->ip;
  return NULL;
}

char *
plug_get_host_ip_str (struct script_infos *desc)
{
  return addr6_as_str (plug_get_host_ip (desc));
}

/**
 * @brief Sets a Success kb- entry for the plugin described with parameter desc.
 *
 * @param desc Plugin script infos.
 */
static void
mark_successful_plugin (const char *oid, struct script_infos *desc)
{
  char data[512];

  bzero (data, sizeof (data));
  snprintf (data, sizeof (data), "Success/%s", oid);
  plug_set_key (desc, data, ARG_INT, (void *) 1);
}

static void
mark_post (const char *oid, struct script_infos *desc, const char *action,
           const char *content)
{
  char entry_name[255];

  if (strlen (action) > (sizeof (entry_name) - 20))
    return;

  snprintf (entry_name, sizeof (entry_name), "SentData/%s/%s", oid, action);
  plug_set_key (desc, entry_name, ARG_STRING, content);
}

/**
 * @brief Post a security message (e.g. LOG, NOTE, WARNING ...).
 *
 * @param oid   The oid of the NVT
 * @param desc  The script infos where to get the nvtichache from and some
 *              other settings and it is used to send the messages
 * @param port  Port number related to the issue.
 * @param proto Protocol related to the issue (tcp or udp).
 * @param action The actual result text
 * @param what   The type, like "LOG".
 */
void
proto_post_wrapped (const char *oid, struct script_infos *desc, int port,
                    const char *proto, const char *action, const char *what)
{
  int soc, len;
  const char *prepend_tags, *append_tags;
  char *buffer, *data, **nvti_tags = NULL;
  struct scan_globals *globals;
  GString *action_str;
  gsize length;

  /* Should not happen, just to avoid trouble stop here if no NVTI found */
  if (!nvticache_initialized () || !oid)
    return;

  if (action == NULL)
    action_str = g_string_new ("");
  else
    {
      action_str = g_string_new (action);
      g_string_append (action_str, "\n");
    }

  prepend_tags = prefs_get ("result_prepend_tags");
  append_tags = prefs_get ("result_append_tags");

  if (prepend_tags || append_tags)
    {
      char *tags = nvticache_get_tags (oid);
      nvti_tags = g_strsplit (tags, "|", 0);
      g_free (tags);
    }

  /* This is convenience functionality in preparation for the breaking up of the
   * NVT description block and adding proper handling of refined meta
   * information all over the OpenVAS Framework.
   */
  if (nvti_tags != NULL)
    {
      if (prepend_tags != NULL)
        {
          gchar **tags = g_strsplit (prepend_tags, ",", 0);
          int i = 0;
          gchar *tag_prefix;
          gchar *tag_value;
          while (tags[i] != NULL)
            {
              int j = 0;
              tag_value = NULL;
              tag_prefix = g_strconcat (tags[i], "=", NULL);
              while (nvti_tags[j] != NULL && tag_value == NULL)
                {
                  if (g_str_has_prefix (nvti_tags[j], tag_prefix))
                    {
                      tag_value = g_strstr_len (nvti_tags[j], -1, "=");
                    }
                  j++;
                }
              g_free (tag_prefix);

              if (tag_value != NULL)
                {
                  tag_value = tag_value + 1;
                  gchar *tag_line = g_strdup_printf ("%s:\n%s\n\n", tags[i],
                                                     tag_value);
                  g_string_prepend (action_str, tag_line);

                  g_free (tag_line);
                }
              i++;
            }
          g_strfreev (tags);
        }

      if (append_tags != NULL)
        {
          gchar **tags = g_strsplit (append_tags, ",", 0);
          int i = 0;
          gchar *tag_prefix;
          gchar *tag_value;

          while (tags[i] != NULL)
            {
              int j = 0;
              tag_value = NULL;
              tag_prefix = g_strconcat (tags[i], "=", NULL);
              while (nvti_tags[j] != NULL && tag_value == NULL)
                {
                  if (g_str_has_prefix (nvti_tags[j], tag_prefix))
                    {
                      tag_value = g_strstr_len (nvti_tags[j], -1, "=");
                    }
                  j++;
                }
              g_free (tag_prefix);

              if (tag_value != NULL)
                {
                  tag_value = tag_value + 1;
                  gchar *tag_line = g_strdup_printf ("%s:\n%s\n\n", tags[i],
                                                     tag_value);
                  g_string_append (action_str, tag_line);

                  g_free (tag_line);
                }
              i++;
            }
          g_strfreev (tags);
        }
    }

  len = action_str->len;
  buffer = g_malloc0 (1024 + len + 1);
  char idbuffer[105];
  if (oid == NULL)
    {
      *idbuffer = '\0';
    }
  else
    {
      snprintf (idbuffer, sizeof (idbuffer), "<|> %s ", oid);
    }
  if (port > 0)
    {
      snprintf (buffer, 1024 + len,
                "SERVER <|> %s <|> %s <|> %d/%s <|> %s %s<|> SERVER\n",
                what, plug_get_hostname (desc), port, proto,
                action_str->str, idbuffer);
    }
  else
    snprintf (buffer, 1024 + len,
              "SERVER <|> %s <|> %s <|> general/%s <|> %s %s<|> SERVER\n", what,
              plug_get_hostname (desc), proto, action_str->str,
              idbuffer);

  mark_post (oid, desc, what, action);
  globals = desc->globals;
  soc = globals->global_socket;
  /* Convert to UTF-8 before sending to Manager. */
  data = g_convert (buffer, -1, "UTF-8", "ISO_8859-1", NULL, &length, NULL);
  internal_send (soc, data, INTERNAL_COMM_MSG_TYPE_DATA);
  g_free (data);

  /* Mark in the KB that the plugin was successful */
  mark_successful_plugin (oid, desc);

  g_free (buffer);
  g_string_free (action_str, TRUE);
}

void
proto_post_alarm (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action)
{
  proto_post_wrapped (oid, desc, port, proto, action, "ALARM");
}

void
post_alarm (const char *oid, struct script_infos *desc, int port,
            const char *action)
{
  proto_post_alarm (oid, desc, port, "tcp", action);
}


/**
 * @brief Post a log message
 */
void
proto_post_log (const char *oid, struct script_infos *desc, int port,
                const char *proto, const char *action)
{
  proto_post_wrapped (oid, desc, port, proto, action, "LOG");
}

/**
 * @brief Post a log message about a tcp port.
 */
void
post_log (const char *oid, struct script_infos *desc, int port,
          const char *action)
{
  proto_post_log (oid, desc, port, "tcp", action);
}

void
proto_post_error (const char *oid, struct script_infos *desc, int port,
                  const char *proto, const char *action)
{
  proto_post_wrapped (oid, desc, port, proto, action, "ERRMSG");
}


void
post_error (const char *oid, struct script_infos *desc, int port,
            const char *action)
{
  proto_post_error (oid, desc, port, "tcp", action);
}

void
add_plugin_preference (struct script_infos *desc, const char *name,
                       const char *type, const char *defaul)
{
  nvti_t *n = desc->nvti;
  nvtpref_t *np = nvtpref_new ((gchar *)name, (gchar *)type, (gchar *)defaul);

  nvti_add_pref (n, np);
}


char *
get_plugin_preference (const char *oid, const char *name)
{
  GHashTable *prefs;
  GHashTableIter iter;
  char *plug_name, *cname;
  void *itername, *itervalue;

  prefs = preferences_get ();
  if (!prefs || !nvticache_initialized () || !oid || !name)
    return NULL;

  plug_name = nvticache_get_name (oid);
  if (!plug_name)
    return NULL;
  cname = g_strdup (name);

  g_strchomp (cname);
  g_hash_table_iter_init (&iter, prefs);
  while (g_hash_table_iter_next (&iter, &itername, &itervalue))
    {
      char *a, *b;

      a = strchr (itername, '[');
      b = strchr (itername, ']');
      if (a && b && b[1] == ':')
        {
          b += 2 * sizeof (char);
          if (!strcmp (cname, b))
            {
              int old = a[0];
              a[0] = 0;
              if (!strcmp (itername, plug_name))
                {
                  a[0] = old;
                  g_free (cname);
                  return itervalue;
                }
              a[0] = old;
            }
        }
    }
  g_free (cname);
  return (NULL);
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
    g_file_open_tmp ("openvassd-file-upload.XXXXXX", &tmpfilename, &error);
  if (tmpfile == -1)
    {
      g_message ("get_plugin_preference_fname: Could not open temporary"
                 " file for %s: %s", filename, error->message);
      g_error_free (error);
      return NULL;
    }
  close (tmpfile);

  if (!g_file_set_contents (tmpfilename, content, contentsize, &error))
    {
      g_message ("get_plugin_preference_fname: could set contents of"
                 " temporary file for %s: %s", filename, error->message);
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
 * @return Contents of the file identified by \p identifier, NULL if not found or setup
 *         broken.
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
    kb_item_add_str (kb, name, value, len);
  else if (type == ARG_INT)
    kb_item_add_int (kb, name, GPOINTER_TO_SIZE (value));
  if (global_nasl_debug == 1)
    {
      if (type == ARG_STRING)
        g_message ("set key %s -> %s", name, (char *) value);
      else if (type == ARG_INT)
        g_message ("set key %s -> %d", name,
                   (int) GPOINTER_TO_SIZE (value));
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

/*
 * plug_get_key() may fork(). We use this signal handler to kill
 * its son in case the process which calls this function is killed
 * itself
 */
static int _plug_get_key_son = 0;

static void
plug_get_key_sighand_term ()
{
  int son = _plug_get_key_son;

  if (son != 0)
    {
      kill (son, SIGTERM);
      _plug_get_key_son = 0;
    }
  _exit (0);
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

void *
plug_get_key (struct script_infos *args, char *name, int *type, size_t *len,
              int single)
{
  kb_t kb = args->key;
  struct kb_item *res = NULL, *res_list;
  int sockpair[2];
  int upstream = 0;

  if (type != NULL)
    *type = -1;

  if (kb == NULL)
    return NULL;

  res = kb_item_get_all (kb, name);

  if (res == NULL)
    return NULL;

  if (res->next == NULL || single)        /* No fork - good */
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
  while (res != NULL)
    {
      pid_t pid;

      socketpair (AF_UNIX, SOCK_STREAM, 0, sockpair);
      if ((pid = fork ()) == 0)
        {
          int old;
          struct scan_globals *globals;
          void *ret;

          sig_term (_exit);
          kb_lnk_reset (kb);
          nvticache_reset ();
          close (sockpair[0]);
          globals = args->globals;
          old = globals->global_socket;
          if (old > 0)
            close (old);
          globals->global_socket = sockpair[1];

          srand48 (getpid () + getppid () + time (NULL));

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
      else if (pid < 0)
        {
          g_message ("libopenvas:%s:%s(): fork() failed (%s)", __FILE__,
                     __func__, strerror (errno));
          kb_item_free (res_list);
          return NULL;
        }
      else
        {
          int e;
          int status;
          struct scan_globals *globals;

          globals = args->globals;
          upstream = globals->global_socket;
          close (sockpair[1]);
          _plug_get_key_son = pid;
          sig_term (plug_get_key_sighand_term);
          for (;;)
            {
              fd_set rd;
              struct timeval tv;
              int type;

              do
                {
                  tv.tv_sec = 0;
                  tv.tv_usec = 100000;
                  FD_ZERO (&rd);
                  FD_SET (sockpair[0], &rd);
                  e = select (sockpair[0] + 1, &rd, NULL, NULL, &tv);
                }
              while (e < 0 && errno == EINTR);

              if (e > 0)
                {
                  char *buf = NULL;
                  int bufsz = 0;

                  e = internal_recv (sockpair[0], &buf, &bufsz, &type);
                  if (e < 0 || (type & INTERNAL_COMM_MSG_TYPE_CTRL))
                    {
                      waitpid (pid, &status, WNOHANG);
                      _plug_get_key_son = 0;
                      close (sockpair[0]);
                      sig_term (_exit);
                      g_free (buf); /* Left NULL on error, harmless */
                      break;
                    }
                  else
                    internal_send (upstream, buf, type);

                  g_free (buf);
                }
            }
        }
      res = res->next;
    }
  kb_item_free (res_list);
  internal_send (upstream, NULL,
                 INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
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
      else
        return 0;
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
    return OPENVAS_ENCAPS_IP;   /* Change this to 0 for ultra smart SSL negotiation, at the expense
                                   of possibly breaking stuff */
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

char *
find_in_path (char *name, int safe)
{
  char *buf = getenv ("PATH"), *pbuf, *p1, *p2;
  static char cmd[MAXPATHLEN];
  int len = strlen (name);

  if (len >= MAXPATHLEN)
    return NULL;

  if (buf == NULL)              /* Should we use a standard PATH here? */
    return NULL;

  pbuf = buf;
  while (*pbuf != '\0')
    {
      for (p1 = pbuf, p2 = cmd; *p1 != ':' && *p1 != '\0';)
        *p2++ = *p1++;
      *p2 = '\0';
      if (*p1 == ':')
        p1++;
      pbuf = p1;
      if (p2 == cmd)            /* :: found in $PATH */
        strcpy (cmd, ".");

      if (cmd[0] != '/' && safe)
        continue;
      if (p2 - cmd + 1 + len >= MAXPATHLEN)
        /* path too long: cannot be reached */
        continue;

      snprintf (p2, MAXPATHLEN, "/%s", name);
      if (access (cmd, X_OK) == 0)
        {
          struct stat st;
          if (stat (cmd, &st) < 0)
            perror (cmd);
          else if (S_ISREG (st.st_mode))
            {
              *p2 = '\0';
              return cmd;
            }
        }
    }
  return NULL;
}
