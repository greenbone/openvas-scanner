/* OpenVAS
 * $Id$
 * Description: Header file for module plugutils.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
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

#ifndef OPENVAS_PLUGUTILS_H
#define OPENVAS_PLUGUTILS_H

#include "arglists.h"

#include <gvm/base/nvti.h>  /* for nvti_t */
#include <gvm/util/kb.h>

#define LEGACY_OID "1.3.6.1.4.1.25623.1.0."


void scanner_add_port (struct arglist *, int, char *);

/*
 * Arglist management at plugin-level
 */

void plug_set_dep (struct arglist *, const char *);

void plug_set_xref (struct arglist *, char *, char *);

void plug_set_tag (struct arglist *, char *, char *);

void plug_set_ssl_cert (struct arglist *, char *);
void plug_set_ssl_key (struct arglist *, char *);
void plug_set_ssl_pem_password (struct arglist *, char *);
void plug_set_ssl_CA_file (struct arglist *, char *);


const char *plug_get_hostname (struct arglist *);
char *plug_get_host_fqdn (struct arglist *);
unsigned int plug_get_host_open_port (struct arglist *desc);

void plug_set_port_transport (struct arglist *, int, int);

int plug_get_port_transport (struct arglist *, int);

struct arglist *
plug_create_from_nvti_and_prefs (const nvti_t *);

/*
 * Reporting functions
 */
void proto_post_alarm (const char *, struct arglist *, int, const char *, const char *);
void post_alarm (const char *, struct arglist *, int, const char *);
void post_alarm_udp (struct arglist *, int, const char *);
#define post_alarm_tcp post_alarm

void proto_post_error (const char *, struct arglist *, int, const char *, const char *);
void post_error (const char *, struct arglist *, int, const char *);
#define post_error_tcp post_error

void proto_post_log (const char *, struct arglist *, int, const char *, const char *);
void post_log (const char *, struct arglist *, int, const char *);
#define post_log_tcp post_log


/*
 * Management of the portlists
 */
int host_get_port_state (struct arglist *, int);
int host_get_port_state_udp (struct arglist *, int);

/* Not implemented
char * host_get_port_banner(struct arglist *, int);
*/


/*
 * Inter Plugins Communication functions
 */
void plug_set_key (struct arglist *, char *, int, const void *);
void plug_set_key_len (struct arglist *, char *, int, const void *, size_t);
void plug_replace_key (struct arglist *, char *, int, void *);
void plug_replace_key_len (struct arglist *, char *, int, void *, size_t);
kb_t plug_get_kb (struct arglist *);
void *plug_get_key (struct arglist *, char *, int *, size_t *);

struct in6_addr *plug_get_host_ip (struct arglist *);
char *plug_get_host_ip_str (struct arglist *);
void add_plugin_preference (struct arglist *, const char *, const char *,
                            const char *);
char *get_plugin_preference (const char *, const char *);
const char *get_plugin_preference_fname (struct arglist *, const char *);
char *get_plugin_preference_file_content (struct arglist *, const char *);
long get_plugin_preference_file_size (struct arglist *, const char *);

char *find_in_path (char *, int);

#endif
