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

#include "scanneraux.h"

#include <gvm/base/nvti.h>  /* for nvti_t */
#include <gvm/util/kb.h>

#define LEGACY_OID "1.3.6.1.4.1.25623.1.0."

#define ARG_STRING  1
#define ARG_INT     2

void scanner_add_port (struct script_infos *, int, char *);

/*
 * Arglist management at plugin-level
 */

void plug_set_dep (struct script_infos *, const char *);

void plug_set_xref (struct script_infos *, char *, char *);

void plug_set_tag (struct script_infos *, char *, char *);

void plug_set_ssl_cert (struct script_infos *, char *);
void plug_set_ssl_key (struct script_infos *, char *);
void plug_set_ssl_pem_password (struct script_infos *, char *);
void plug_set_ssl_CA_file (struct script_infos *, char *);

const char *
plug_current_vhost (void);

char *plug_get_host_fqdn (struct script_infos *);
unsigned int plug_get_host_open_port (struct script_infos *desc);

void plug_set_port_transport (struct script_infos *, int, int);

int plug_get_port_transport (struct script_infos *, int);

struct script_infos *
plug_create_from_nvti_and_prefs (const nvti_t *);

/*
 * Reporting functions
 */
void proto_post_alarm (const char *, struct script_infos *, int, const char *, const char *);
void post_alarm (const char *, struct script_infos *, int, const char *);
void post_alarm_udp (struct script_infos *, int, const char *);
#define post_alarm_tcp post_alarm

void proto_post_error (const char *, struct script_infos *, int, const char *, const char *);
void post_error (const char *, struct script_infos *, int, const char *);
#define post_error_tcp post_error

void proto_post_log (const char *, struct script_infos *, int, const char *, const char *);
void post_log (const char *, struct script_infos *, int, const char *);
#define post_log_tcp post_log


/*
 * Management of the portlists
 */
int host_get_port_state (struct script_infos *, int);
int host_get_port_state_udp (struct script_infos *, int);

/* Not implemented
char * host_get_port_banner(struct script_infos *, int);
*/


/*
 * Inter Plugins Communication functions
 */
void plug_set_key (struct script_infos *, char *, int, const void *);
void plug_set_key_len (struct script_infos *, char *, int, const void *, size_t);
void plug_replace_key (struct script_infos *, char *, int, void *);
void plug_replace_key_len (struct script_infos *, char *, int, void *, size_t);
kb_t plug_get_kb (struct script_infos *);
void *plug_get_key (struct script_infos *, char *, int *, size_t *, int);

struct in6_addr *plug_get_host_ip (struct script_infos *);
char *plug_get_host_ip_str (struct script_infos *);
void add_plugin_preference (struct script_infos *, const char *, const char *,
                            const char *);
char *get_plugin_preference (const char *, const char *);
const char *get_plugin_preference_fname (struct script_infos *, const char *);
char *get_plugin_preference_file_content (struct script_infos *, const char *);
long get_plugin_preference_file_size (struct script_infos *, const char *);

char *find_in_path (char *, int);

#endif
