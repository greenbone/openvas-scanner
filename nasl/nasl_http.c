/* NASL Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>

#include <ctype.h>              /* for isspace */
#include <string.h>             /* for strlen */

#include <gvm/base/prefs.h>      /* for prefs_get */
#include <gvm/util/kb.h>         /* for kb_item_get_str */

#include "../misc/plugutils.h"  /* plug_get_host_fqdn */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"
#include "nasl_socket.h"

#include "nasl_http.h"


/*-----------------[ http_* functions ]-------------------------------*/


tree_cell *
http_open_socket (lex_ctxt * lexic)
{
  return nasl_open_sock_tcp_bufsz (lexic, 65536);
}

tree_cell *
http_close_socket (lex_ctxt * lexic)
{
  return nasl_close_socket (lexic);
}

static char *
build_encode_URL (char *method, char *path, char *name, char *httpver)
{
  char *ret, *ret2;

  if (path == NULL)
    ret = g_strdup (name);
  else
    ret = g_strdup_printf ("%s/%s", path, name);

#ifdef URL_DEBUG
  g_message ("Request => %s", ret);
#endif

  ret2 = g_strdup_printf ("%s %s %s", method, ret, httpver);
  g_free (ret);
  return ret2;
}

static tree_cell *
_http_req (lex_ctxt * lexic, char *keyword)
{
  tree_cell *retc;
  char *request, *auth, tmp[32];
  char *item = get_str_var_by_name (lexic, "item");
  char *data = get_str_var_by_name (lexic, "data");
  int port = get_int_var_by_name (lexic, "port", -1);
  struct script_infos *script_infos = lexic->script_infos;
  int ver;
  kb_t kb;


  if (item == NULL || port < 0)
    {
      nasl_perror (lexic,
                   "Error : http_* functions have the following syntax :\n");
      nasl_perror (lexic, "http_*(port:<port>, item:<item> [, data:<data>]\n");
      return NULL;
    }

  if (port <= 0 || port > 65535)
    {
      nasl_perror (lexic, "http_req: invalid value %d for port parameter\n",
                   port);
      return NULL;
    }

  kb = plug_get_kb (script_infos);
  g_snprintf (tmp, sizeof (tmp), "/tmp/http/auth/%d", port);
  auth = kb_item_get_str (kb, tmp);

  if (!auth)
    auth = kb_item_get_str (kb, "http/auth");

  g_snprintf (tmp, sizeof (tmp), "http/%d", port);
  ver = kb_item_get_int (kb, tmp);

  if ((ver <= 0) || (ver == 11))
    {
      char *hostname, *ua, *hostheader, *url;

      hostname = plug_get_host_fqdn (script_infos);
      if (hostname == NULL)
        return NULL;
      /* global_settings.nasl */
      ua = get_plugin_preference ("1.3.6.1.4.1.25623.1.0.12288", "HTTP User-Agent");
      if (!ua || strlen (g_strstrip (ua)) == 0)
        {
          g_free (ua);
          ua = g_strdup ("Mozilla/5.0 [en] (X11, U; OpenVAS)");
        }

      /* Servers should not have a problem with port 80 or 443 appended.
       * RFC2616 allows to omit the port in which case the default port for
       * that service is assumed.
       * However, some servers like IIS/OWA wrongly respond with a "404"
       * instead of a "200" in case the port is appended. Because of this,
       * ports 80 and 443 are not appended.
       */
      if (port == 80 || port == 443)
        hostheader = g_strdup (hostname);
      else
        hostheader = g_strdup_printf ("%s:%d", hostname, port);

      url = build_encode_URL (keyword, NULL, item, "HTTP/1.1");
      request = g_strdup_printf ("%s\r\n\
Connection: Close\r\n\
Host: %s\r\n\
Pragma: no-cache\r\n\
Cache-Control: no-cache\r\n\
User-Agent: %s\r\n\
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n\
Accept-Language: en\r\n\
Accept-Charset: iso-8859-1,*,utf-8\r\n", url, hostheader, ua);
      g_free (hostname);
      g_free (hostheader);
      g_free (ua);
      g_free (url);
    }
  else
    request = build_encode_URL (keyword, NULL, item, "HTTP/1.0\r\n");

  if (auth)
    {
      char *tmp = g_strconcat (request, auth, "\r\n", NULL);
      g_free (request);
      request = tmp;
    }
  if (data)
    {
      char content_length[128], *tmp;

      g_snprintf (content_length, sizeof (content_length),
                  "Content-Length: %lu\r\n\r\n", strlen (data));
      tmp = g_strconcat (request, content_length, data, NULL);
      g_free (request);
      request = tmp;
    }
  else
    {
      char *tmp = g_strconcat (request, "\r\n", NULL);
      g_free (request);
      request = tmp;
    }

  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->size = strlen (request);
  retc->x.str_val = request;
  return retc;
}

/*
 * Syntax :
 *
 * http_get(port:<port>, item:<item>);
 *
 */
tree_cell *
http_get (lex_ctxt * lexic)
{
  return _http_req (lexic, "GET");
}

/*
 * Syntax :
 *
 * http_head(port:<port>, item:<item>);
 *
 */
tree_cell *
http_head (lex_ctxt * lexic)
{
  return _http_req (lexic, "HEAD");
}


/*
 * Syntax :
 * http_post(port:<port>, item:<item>)
 */
tree_cell *
http_post (lex_ctxt * lexic)
{
  return _http_req (lexic, "POST");
}

/*
 * http_delete(port:<port>, item:<item>)
 */
tree_cell *
http_delete (lex_ctxt * lexic)
{
  return _http_req (lexic, "DELETE");
}

/*
 * http_put(port:<port>, item:<item>, data:<data>)
 */
tree_cell *
http_put (lex_ctxt * lexic)
{
  return _http_req (lexic, "PUT");
}


/*-------------------[ cgibin() ]--------------------------------*/


tree_cell *
cgibin (lex_ctxt * lexic)
{
  const char *path = prefs_get ("cgi_path");
  tree_cell *retc;

  (void) lexic;
  if (path == NULL)
    path = "/cgi-bin:/scripts";
  retc = alloc_tree_cell ();
  retc->type = CONST_DATA;
  retc->x.str_val = g_strdup (path);
  retc->size = strlen (path);

  return retc;
}
