/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_host.c
 *
 * @brief Remote host helper functions.
 *
 * This file contains all the functions which deal with the remote
 * host: which ports are open, what is its IP, what is our IP, what
 * transport is on the remote port, and so on...
 */

#include "nasl_host.h"

#include "../misc/ipc_openvas.h"
#include "../misc/network.h"
#include "../misc/pcap_openvas.h" /* for v6_is_local_ip */
#include "../misc/plugutils.h"    /* for plug_get_host_fqdn */
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <arpa/inet.h> /* for inet_aton */
#include <gvm/base/networking.h>
#include <gvm/util/kb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>      /* for gethostbyaddr */
#include <netinet/in.h> /* for in_addr */
#include <string.h>     /* for strlen */
#include <sys/ioctl.h>
#include <unistd.h> /* for gethostname */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   nasl"
tree_cell *
get_hostnames (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  int i = 0;
  nasl_array *arr;
  GSList *tmp, *hostnames;

  hostnames = tmp = plug_get_host_fqdn_list (script_infos);
  if (!hostnames)
    return NULL;

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = arr = g_malloc0 (sizeof (nasl_array));
  while (tmp)
    {
      anon_nasl_var v;

      v.var_type = VAR2_DATA;
      v.v.v_str.s_siz = strlen (tmp->data);
      v.v.v_str.s_val = tmp->data;
      add_var_to_list (arr, i++, &v);
      tmp = tmp->next;
    }

  g_slist_free_full (hostnames, g_free);
  return retc;
}

tree_cell *
get_hostname (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *hostname = plug_get_host_fqdn (script_infos);
  tree_cell *retc;

  if (hostname == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_STR);
  retc->size = strlen (hostname);
  retc->x.str_val = hostname;
  return retc;
}

tree_cell *
get_hostname_source (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  char *source;
  tree_cell *retc;

  source = plug_get_host_source (script_infos,
                                 get_str_var_by_name (lexic, "hostname"));
  if (!source)
    return NULL;

  retc = alloc_typed_cell (CONST_STR);
  retc->size = strlen (source);
  retc->x.str_val = source;
  return retc;
}

tree_cell *
add_hostname (lex_ctxt *lexic)
{
  struct ipc_data *hn = NULL;
  char *lower;
  const char *json = NULL;
  char *value = get_str_var_by_name (lexic, "hostname");
  char *source = get_str_var_by_name (lexic, "source");

  if (!value)
    {
      nasl_perror (lexic, "%s: Empty hostname\n", __func__);
      return NULL;
    }
  if (!source || !*source)
    source = "NASL";
  /* Add to current process' vhosts list. */
  lower = g_ascii_strdown (value, -1);
  hn = ipc_data_type_from_hostname (source, strlen (source), lower,
                                    strlen (lower));
  json = ipc_data_to_json (hn);
  ipc_data_destroy (&hn);
  if (plug_add_host_fqdn (lexic->script_infos, lower, source))
    goto end_add_hostname;

  // send it to host process to extend vhosts list there
  if (ipc_send (lexic->script_infos->ipc_context, IPC_MAIN, json, strlen (json))
      < 0)
    g_warning ("Unable to send %s to host process", lower);

end_add_hostname:
  g_free (lower);
  g_free ((void *) json);
  return NULL;
}

/**
 * @brief Resolve a hostname and return all ip addresses as nasl array.
 *
 */
tree_cell *
resolve_hostname_to_multiple_ips (lex_ctxt *lexic)
{
  GSList *list = NULL;
  char *value = get_str_var_by_name (lexic, "hostname");
  tree_cell *retc;
  nasl_array *arr;
  int i = 0;

  if (!value)
    {
      nasl_perror (lexic, "%s: Empty hostname\n", __func__);
      return NULL;
    }

  list = gvm_resolve_list (value);

  retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = arr = g_malloc0 (sizeof (nasl_array));
  while (list)
    {
      anon_nasl_var var_aux;

      var_aux.var_type = VAR2_DATA;
      var_aux.v.v_str.s_siz = strlen (addr6_as_str (list->data));
      var_aux.v.v_str.s_val = (unsigned char *) addr6_as_str (list->data);
      add_var_to_list (arr, i++, &var_aux);
      list = list->next;
    }
  g_slist_free_full (list, g_free);
  return retc;
}

tree_cell *
resolve_hostname (lex_ctxt *lexic)
{
  struct in6_addr in6addr;
  char *value = get_str_var_by_name (lexic, "hostname");

  if (!value)
    {
      nasl_perror (lexic, "%s: Empty hostname\n", __func__);
      return NULL;
    }

  if (!gvm_resolve_as_addr6 (value, &in6addr))
    {
      tree_cell *retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = addr6_as_str (&in6addr);
      retc->size = strlen (retc->x.str_val);
      return retc;
    }
  return NULL;
}

tree_cell *
get_host_ip (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *ip = plug_get_host_ip (script_infos);
  tree_cell *retc;

  if (ip == NULL) /* WTF ? */
    {
      return FAKE_CELL;
    }

  retc = alloc_typed_cell (CONST_STR);
  retc->x.str_val = addr6_as_str (ip);
  retc->size = strlen (retc->x.str_val);

  return retc;
}

tree_cell *
get_host_open_port (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  unsigned int port = plug_get_host_open_port (script_infos);
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = port;

  return retc;
}

tree_cell *
get_port_state (lex_ctxt *lexic)
{
  int open;
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  int port;

  port = get_int_var_by_num (lexic, 0, -1);
  if (port < 0)
    return FAKE_CELL;

  retc = alloc_typed_cell (CONST_INT);
  open = host_get_port_state (script_infos, port);
  retc->x.i_val = open;
  return retc;
}

tree_cell *
get_udp_port_state (lex_ctxt *lexic)
{
  int open;
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  int port;

  port = get_int_var_by_num (lexic, 0, -1);
  if (port < 0)
    return FAKE_CELL;

  retc = alloc_typed_cell (CONST_INT);
  open = host_get_port_state_udp (script_infos, port);
  retc->x.i_val = open;
  return retc;
}

tree_cell *
nasl_islocalhost (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *dst = plug_get_host_ip (script_infos);
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = v6_islocalhost (dst);
  return retc;
}

tree_cell *
nasl_islocalnet (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *ip = plug_get_host_ip (script_infos);
  tree_cell *retc;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = v6_is_local_ip (ip);
  return retc;
}

tree_cell *
nasl_this_host (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  char hostname[255];
  struct in6_addr *ia = plug_get_host_ip (script_infos);
  struct in6_addr in6addr;
  struct in6_addr src6;

  retc = alloc_typed_cell (CONST_DATA);

  if (gvm_source_iface_is_set ())
    {
      struct in6_addr addr;

      /* Use source_iface's IP address when available. */
      if (IN6_IS_ADDR_V4MAPPED (ia))
        gvm_source_addr_as_addr6 (&addr);
      else
        gvm_source_addr6 (&addr);
      retc->x.str_val = addr6_as_str (&addr);
      retc->size = strlen (retc->x.str_val);
      return retc;
    }
  else
    {
      /* Manually find the source IP that will be used. */
      int err = 1;
      if (v6_islocalhost (ia))
        memcpy (&src6, ia, sizeof (struct in6_addr));
      else
        err = v6_getsourceip (&src6, ia);

      if (err && !IN6_ARE_ADDR_EQUAL (&src6, &in6addr_any))
        {
          retc->x.str_val = addr6_as_str (&src6);
          retc->size = strlen (retc->x.str_val);

          return retc;
        }

      hostname[sizeof (hostname) - 1] = '\0';
      gethostname (hostname, sizeof (hostname) - 1);
      if (gvm_resolve_as_addr6 (hostname, &in6addr))
        {
          retc->x.str_val = addr6_as_str (&in6addr);
          retc->size = strlen (retc->x.str_val);
        }
    }
  return retc;
}

tree_cell *
nasl_this_host_name (lex_ctxt *lexic)
{
  char *hostname;
  tree_cell *retc;

  (void) lexic;
  retc = alloc_typed_cell (CONST_DATA);

  hostname = g_malloc0 (256);
  gethostname (hostname, 255);

  retc->x.str_val = hostname;
  retc->size = strlen (hostname);
  return retc;
}

/**
 * @brief Return the encapsulation mode of a port.
 * @naslfn{get_port_transport}
 *
 * Takes a port number and returns its encapsulation mode (ENCAPS_*)
 * The defined encapsulation modes are:
 *          - @a ENCAPS_AUTO   Automatic encapsulation detection.
 *          - @a ENCAPS_IP     No encapsulation
 *          - @a ENCAPS_SSLv23 Request compatibility options
 *          - @a ENCAPS_SSLv2  SSL version 2
 *          - @a ENCAPS_SSLv3  SSL version 3
 *          - @a ENCAPS_TLSv1  TLS version 1.0
 *          - @a ENCAPS_TLSv11 TLS version 1.1
 *          - @a ENCAPS_TLSv12 TLS version 1.2
 *          - @a ENCAPS_TLSv13 TLS version 1.3
 *          - @a ENCAPS_TLScustom SSL or TLS with custom priorities
 *
 * @nasluparam
 *
 * - An integer with the port number.
 *
 * @naslnparam
 *
 * -@a asstring If not 0 return a human readabale string instead of
 *   an integer.
 *
 * @naslret An integer or a string with the encapsulation mode or NULL
 * on error.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return A tree cell.
 */
tree_cell *
get_port_transport (lex_ctxt *lexic)
{
  struct script_infos *script_infos = lexic->script_infos;
  tree_cell *retc;
  int port = get_int_var_by_num (lexic, 0, -1);

  if (port >= 0)
    {
      int trp = plug_get_port_transport (script_infos, port);

      retc = alloc_typed_cell (CONST_STR);
      if (get_int_var_by_name (lexic, "asstring", 0))
        {
          const char *s = get_encaps_name (trp);
          retc->x.str_val = g_strdup (s);
          retc->size = strlen (s);
        }
      else
        {
          retc->type = CONST_INT;
          retc->x.i_val = trp;
        }
      return retc;
    }
  return NULL;
}

tree_cell *
nasl_same_host (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct hostent *h;
  char *hn[2], **names[2];
  struct in_addr ia, *a[2];
  int i, j, n[2], names_nb[2], flag;
  int cmp_hostname = get_int_var_by_name (lexic, "cmp_hostname", 0);

  memset (names_nb, '\0', sizeof (names_nb));
  memset (names, '\0', sizeof (names));
  memset (a, '\0', sizeof (a));
  for (i = 0; i < 2; i++)
    {
      hn[i] = get_str_var_by_num (lexic, i);
      if (hn[i] == NULL)
        {
          nasl_perror (lexic, "same_host needs two parameters!\n");
          return NULL;
        }
      if (strlen (hn[i]) >= 256)
        {
          nasl_perror (lexic, "same_host(): Too long hostname !\n");
          return NULL;
        }
    }
  for (i = 0; i < 2; i++)
    {
      if (!inet_aton (hn[i], &ia)) /* Not an IP address */
        {
          h = gethostbyname (hn[i]);
          if (h == NULL)
            {
              nasl_perror (lexic, "same_host: %s does not resolve\n", hn[i]);
              n[i] = 0;
              if (cmp_hostname)
                {
                  names_nb[i] = 1;
                  names[i] = g_malloc0 (sizeof (char *));
                  names[i][0] = g_strdup (hn[i]);
                }
            }
          else
            {
              for (names_nb[i] = 0; h->h_aliases[names_nb[i]] != NULL;
                   names_nb[i]++)
                ;
              names_nb[i]++;
              names[i] = g_malloc0 (sizeof (char *) * names_nb[i]);
              names[i][0] = g_strdup (h->h_name);
              for (j = 1; j < names_nb[i]; j++)
                names[i][j] = g_strdup (h->h_aliases[j - 1]);

              /* Here, we should check that h_addrtype == AF_INET */
              for (n[i] = 0; ((struct in_addr **) h->h_addr_list)[n[i]] != NULL;
                   n[i]++)
                ;
              a[i] = g_malloc0 ((gsize) h->h_length * n[i]);
              for (j = 0; j < n[i]; j++)
                a[i][j] = *((struct in_addr **) h->h_addr_list)[j];
            }
        }
      else
        {
          if (cmp_hostname)
            h = gethostbyaddr ((const char *) &ia, sizeof (ia), AF_INET);
          else
            h = NULL;
          if (h == NULL)
            {
              a[i] = g_malloc0 (sizeof (struct in_addr));
              memcpy (a[i], &ia, sizeof (struct in_addr));
              n[i] = 1;
            }
          else
            {
              for (names_nb[i] = 0; h->h_aliases[names_nb[i]] != NULL;
                   names_nb[i]++)
                ;
              names_nb[i]++;
              names[i] = g_malloc0 (sizeof (char *) * names_nb[i]);
              names[i][0] = g_strdup (h->h_name);
              for (j = 1; j < names_nb[i]; j++)
                names[i][j] = g_strdup (h->h_aliases[j - 1]);

              /* Here, we should check that h_addrtype == AF_INET */
              for (n[i] = 0; ((struct in_addr **) h->h_addr_list)[n[i]] != NULL;
                   n[i]++)
                ;
              a[i] = g_malloc0 ((gsize) h->h_length * n[i]);
              for (j = 0; j < n[i]; j++)
                a[i][j] = *((struct in_addr **) h->h_addr_list)[j];
            }
        }
    }
  flag = 0;
  for (i = 0; i < n[0] && !flag; i++)
    for (j = 0; j < n[1] && !flag; j++)
      if (a[0][i].s_addr == a[1][j].s_addr)
        {
          flag = 1;
        }

  if (cmp_hostname)
    for (i = 0; i < names_nb[0] && !flag; i++)
      for (j = 0; j < names_nb[1] && !flag; j++)
        if (strcmp (names[0][i], names[1][j]) == 0)
          {
            flag = 1;
          }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = flag;

  for (i = 0; i < 2; i++)
    g_free (a[i]);

  for (i = 0; i < 2; i++)
    {
      for (j = 0; j < names_nb[i]; j++)
        g_free (names[i][j]);
      g_free (names[i]);
    }

  return retc;
}

tree_cell *
nasl_target_is_ipv6 (lex_ctxt *lexic)
{
  tree_cell *retc;
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *addr;

  addr = plug_get_host_ip (script_infos);
  retc = alloc_typed_cell (CONST_INT);

  if (addr == NULL)
    {
      nasl_perror (lexic, "address is NULL!\n");
      return NULL;
    }
  if (IN6_IS_ADDR_V4MAPPED (addr) == 1)
    retc->x.i_val = 0;
  else
    retc->x.i_val = 1;

  return retc;
}
