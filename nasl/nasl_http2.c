/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_http2.h"

#include "../misc/plugutils.h"  /* plug_get_host_fqdn */
#include "../misc/user_agent.h" /* for user_agent_get */
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_socket.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <ctype.h> /* for isspace */
#include <curl/curl.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <gvm/util/kb.h>    /* for kb_item_get_str */
#include <string.h>         /* for strlen */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/*-----------------[ http2_* functions ]-------------------------------*/

/** @brief Allowed methods
 **/
typedef enum KEYWORD_E
{
  POST,
  GET,
  PUT,
  DELETE,
  HEAD,
} KEYWORD;

/** @brief Struct to store handles
 **/
struct handle_table_s
{
  int handle_id;
  CURL *handle;
  long http_code;
};

#define MAX_HANDLES 10

/** @brief Handle Table
 **/
static struct handle_table_s *handle_table[MAX_HANDLES];

/** @brief Get the new available handle identifier
 **/
static int
next_handle_id (void)
{
  static int last = 9000;
  last++;

  return last;
}

/**
 * @brief Creates a handle for http requests
 * @naslfn{http2_handle}
 *
 * @naslret Handle identifier. Null on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with the handle
 *         identifier. Null on error.
 */
tree_cell *
nasl_http2_handle (lex_ctxt *lexic)
{
  (void) lexic;
  tree_cell *retc = NULL;
  CURL *handle = curl_easy_init ();
  unsigned int table_slot;

  if (!handle)
    return NULL;

  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    if (!handle_table[table_slot] || !handle_table[table_slot]->handle_id)
      break;

  if (!(table_slot < MAX_HANDLES))
    {
      g_message ("%s: No space left in HTTP2 handle table", __func__);
      curl_easy_cleanup (handle);
      return NULL;
    }

  handle_table[table_slot] = g_malloc0 (sizeof (struct handle_table_s));
  handle_table[table_slot]->handle = handle;
  handle_table[table_slot]->handle_id = next_handle_id ();

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = handle_table[table_slot]->handle_id;
  return retc;
}

/**
 * @brief Close a handle for http requests previously initialized
 * @naslfn{http2_handle}
 *
 * @naslnparam
 * - @a handle The handle identifier for the handle to be closed
 *
 * @naslret O on success, -1 on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The function returns a tree-cell with a integer.
 *         O on success, -1 on error.
 */
tree_cell *
nasl_http2_close_handle (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  int handle_id = get_int_var_by_num (lexic, 0, -1);
  unsigned int table_slot;
  int ret = 0;

  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    {
      if (handle_table[table_slot]->handle_id == handle_id)
        {
          curl_easy_cleanup (handle_table[table_slot]->handle);
          handle_table[table_slot]->handle = NULL;
          handle_table[table_slot]->handle_id = 0;
          handle_table[table_slot] = NULL;
        }
      else
        {
          g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
          ret = -1;
        }
    }
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/** @brief Define a string struct for storing the response or header.
 */
struct string
{
  char *ptr;
  size_t len;
};

/** @brief Initialize the string struct to hold the response or header
 *
 *  @param s[in/out] The string struct to be initialized
 */
static void
init_string (struct string *s)
{
  s->len = 0;
  s->ptr = g_malloc0 (s->len + 1);
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return;
    }
  s->ptr[0] = '\0';
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  struct string *s = struct_string;
  size_t new_len = s->len + size * nmemb;
  char *ptr_aux = g_realloc (s->ptr, new_len + 1);
  s->ptr = ptr_aux;
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0; // no memory left
    }
  memcpy (s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

/** @brief Call back function to stored the header.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the header in s. It reallocate memory if necessary.
 */
static size_t
header_callback_fn (char *buffer, size_t size, size_t nmemb,
                    void *struct_string)
{
  struct string *s = struct_string;
  size_t new_len = s->len + size * nmemb;
  char *ptr_aux = g_realloc (s->ptr, new_len + 1);
  s->ptr = ptr_aux;
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0; // no memory left
    }
  memcpy (s->ptr + s->len, buffer, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

/**
 * @brief Perform an HTTP request. Forcing HTTP2 if possible.
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * - @a port The port to use for the connection
 *
 * - @a item The path
 *
 * - @a schema Optional URL schema to be used. http or https. Default to https.
 *
 * - @a data Optional data to be sent with POST or PUT
 *
 * @naslret http header followed by the response from the server. Null on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with the http header
 *         followed by the response from the server. Null on error.
 */
static tree_cell *
_http2_req (lex_ctxt *lexic, KEYWORD keyword)
{
  tree_cell *retc;
  char *item = get_str_var_by_name (lexic, "item");
  char *data = get_str_var_by_name (lexic, "data");
  int port = get_int_var_by_name (lexic, "port", -1);
  char *schema = get_str_var_by_name (lexic, "schema");
  struct script_infos *script_infos = lexic->script_infos;
  char *hostname;
  GString *url = NULL;
  CURL *handle = NULL;
  int handle_id = get_int_var_by_name (lexic, "handle", -1);
  struct string response, header_data;

  if (item == NULL || port < 0 || handle_id < 0)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic, "http_*(handle: <handle>, port:<port>, item:<item> "
                          "[,schema:<schema>][, data:<data>]\n");
      return NULL;
    }

  unsigned int table_slot;
  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    {
      if (handle_table[table_slot]->handle_id == handle_id)
        break;
      else
        {
          g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
          return NULL;
        }
    }

  handle = handle_table[table_slot]->handle;

  if (port <= 0 || port > 65535)
    {
      nasl_perror (lexic, "http2_req: invalid value %d for port parameter\n",
                   port);
      return NULL;
    }

  // Fork here for every vhost
  hostname = plug_get_host_fqdn (script_infos);
  if (hostname == NULL)
    return NULL;

  curl_easy_reset (handle);

  // force http2
  curl_easy_setopt (handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  // Build URL
  url = schema ? g_string_new (schema) : g_string_new ("https");
  g_string_append (url, "://");
  g_string_append (url, hostname);

  /* Servers should not have a problem with port 80 or 443 appended.
   * RFC2616 allows to omit the port in which case the default port for
   * that service is assumed.
   * However, some servers like IIS/OWA wrongly respond with a "404"
   * instead of a "200" in case the port is appended. Because of this,
   * ports 80 and 443 are not appended.
   */
  if (port != 80 && port != 443)
    {
      char buf[12];
      snprintf (buf, sizeof (buf), ":%d", port);
      g_string_append (url, buf);
    }
  g_string_append (url, item);

  g_message ("%s: URL: %s", __func__, url->str);
  // Set URL
  if (curl_easy_setopt (handle, CURLOPT_URL, url->str) != CURLE_OK)
    {
      g_warning ("Not possible to set the URL");
      curl_easy_cleanup (handle);
      return NULL;
    }
  g_string_free (url, TRUE);

  // Accept an insecure connection. Don't verify the server certificate
  curl_easy_setopt (handle, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt (handle, CURLOPT_SSL_VERIFYHOST, 0L);

  // Set User Agent
  char *ua = NULL;
  if ((user_agent_get (lexic->script_infos->ipc_context, &ua) == -2)
      && !script_infos->standalone)
    {
      g_message ("Not possible to send the User Agent to the host process. "
                 "Invalid IPC context");
    }
  if (ua)
    {
      curl_easy_setopt (handle, CURLOPT_USERAGENT, g_strdup (url->str));
      g_free (ua);
    }

  // Init the struct where the response is stored and set the callback function
  init_string (&response);
  curl_easy_setopt (handle, CURLOPT_WRITEFUNCTION, response_callback_fn);
  curl_easy_setopt (handle, CURLOPT_WRITEDATA, &response);

  init_string (&header_data);
  curl_easy_setopt (handle, CURLOPT_HEADERFUNCTION, header_callback_fn);
  curl_easy_setopt (handle, CURLOPT_HEADERDATA, &header_data);

  switch (keyword)
    {
    case DELETE:
      curl_easy_setopt (handle, CURLOPT_CUSTOMREQUEST, "DELETE");
      break;
    case HEAD:
      curl_easy_setopt (handle, CURLOPT_NOBODY, 1);
      break;
    case PUT:
      curl_easy_setopt (handle, CURLOPT_CUSTOMREQUEST, "PUT");
      if (data)
        {
          curl_easy_setopt (handle, CURLOPT_POSTFIELDS, data);
          curl_easy_setopt (handle, CURLOPT_POSTFIELDSIZE, strlen (data));
        }
      break;
    case GET:
      curl_easy_setopt (handle, CURLOPT_HTTPGET, 1);
      break;
    case POST:
      // Set body. POST is set automatically with this options
      if (data)
        {
          curl_easy_setopt (handle, CURLOPT_POSTFIELDS, data);
          curl_easy_setopt (handle, CURLOPT_POSTFIELDSIZE, strlen (data));
        }
      break;
    default:
      g_message ("%s: Invalid http method.", __func__);
      break;
    }

  int ret = CURLE_OK;
  if ((ret = curl_easy_perform (handle)) != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %d", __func__, ret);
      curl_easy_cleanup (handle);
      g_free (response.ptr);
      return NULL;
    }

  GString *complete_resp = g_string_new (header_data.ptr);
  g_string_append (complete_resp, "\n");
  g_string_append (complete_resp, response.ptr);
  g_free (response.ptr);
  g_free (header_data.ptr);

  long http_code = -1;
  curl_easy_getinfo (handle, CURLINFO_RESPONSE_CODE, &http_code);
  handle_table[table_slot]->http_code = http_code;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = complete_resp->len;
  retc->x.str_val = g_strdup (complete_resp->str);

  g_string_free (complete_resp, TRUE);
  return retc;
}

/**
 * @brief Get the http response code after performing a HTTP request.
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * @naslret http code or 0 if not set. NULL on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with and integer
 *         representing the http code response. Null on error.
 */
tree_cell *
nasl_http2_get_response_code (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  unsigned int table_slot;
  int handle_id = get_int_var_by_name (lexic, "handle", -1);

  if (handle_id < 0)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic, "http_*(handle: <handle>\n");
      return NULL;
    }

  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    {
      if (handle_table[table_slot]->handle_id == handle_id)
        break;
      else
        {
          g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
          return NULL;
        }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = handle_table[table_slot]->http_code;
  return retc;
}

/**
 * @brief Set a custom header element in the header
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * - @a header_item A string to add to the header
 *
 * @naslret 0 on success. NULL on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell
 *         integer 0 on success. Null on error.
 */
tree_cell *
nasl_http2_set_custom_header (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct curl_slist *customheader = NULL;
  unsigned int table_slot;
  CURL *handle;
  int handle_id = get_int_var_by_name (lexic, "handle", -1);
  char *headeritem = get_str_var_by_name (lexic, "header_item");

  if (handle_id < 0 || headeritem == NULL)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic,
                   "http_*(handle: <handle>, header_item:<header_item>\n");
      return NULL;
    }

  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    {
      if (handle_table[table_slot]->handle_id == handle_id)
        break;
      else
        {
          g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
          return NULL;
        }
    }
  handle = handle_table[table_slot]->handle;

  // SET Content type
  customheader = curl_slist_append (customheader, headeritem);
  curl_easy_setopt (handle, CURLOPT_HTTPHEADER, customheader);

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 0;

  return retc;
}

/** @brief Wrapper function for GET request. See @_http2_req
 */
tree_cell *
nasl_http2_get (lex_ctxt *lexic)
{
  return _http2_req (lexic, GET);
}

/** @brief Wrapper function for HEAD request. See @_http2_req
 */
tree_cell *
nasl_http2_head (lex_ctxt *lexic)
{
  return _http2_req (lexic, HEAD);
}

/** @brief Wrapper function for POST request. See @_http2_req
 */
tree_cell *
nasl_http2_post (lex_ctxt *lexic)
{
  return _http2_req (lexic, POST);
}

/** @brief Wrapper function for DELETE request. See @_http2_req
 */
tree_cell *
nasl_http2_delete (lex_ctxt *lexic)
{
  return _http2_req (lexic, DELETE);
}

/** @brief Wrapper function for PUT request. See @_http2_req
 */
tree_cell *
nasl_http2_put (lex_ctxt *lexic)
{
  return _http2_req (lexic, PUT);
}
