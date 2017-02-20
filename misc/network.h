/* OpenVAS
 * $Id$
 * Description: Header file for module network.
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

#ifndef OPENVAS_NETWORK_H
#define OPENVAS_NETWORK_H

#include <sys/select.h>         /* at least for fd_set */
#include <netinet/in.h>         /* struct in_addr, struct in6_addr */

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "arglists.h"

/*
 * Type of "transport layer", for encapsulated connections
 * Only SSL is supported at this time.
 * (Bad) examples of other layers could be SOCKS, httptunnel, icmptunnel,
 * RMI over HTTP, DCOM over HTTP, TCP over TCP, etc.
 */
typedef enum openvas_encaps {
    OPENVAS_ENCAPS_AUTO = 0,   /* Request auto detection.  */
    OPENVAS_ENCAPS_IP,
    OPENVAS_ENCAPS_SSLv23, /* Ask for compatibility options */
    OPENVAS_ENCAPS_SSLv2,
    OPENVAS_ENCAPS_SSLv3,
    OPENVAS_ENCAPS_TLSv1,
    OPENVAS_ENCAPS_TLSv11,
    OPENVAS_ENCAPS_TLSv12,
    OPENVAS_ENCAPS_TLScustom, /* SSL/TLS using custom priorities.  */
    OPENVAS_ENCAPS_MAX,
} openvas_encaps_t;

struct host_info {
  char *name;           /* Hostname. */
  char *fqdn;           /* Fully qualified domain name, e.g. host.domain.net */
  char *vhosts;         /* Comma separated list of vhosts */
  struct in6_addr *ip;  /* IP address. */
};

#define IS_ENCAPS_SSL(x) ((x) >= OPENVAS_ENCAPS_SSLv23 && (x) <= OPENVAS_ENCAPS_TLScustom)

/* Plugin specific network functions */
int open_sock_tcp (struct arglist *, unsigned int, int);
int open_sock_option (struct arglist *, unsigned int, int, int, int);
int recv_line (int, char *, size_t);
int nrecv (int, void *, int, int);
int socket_close (int);
int get_sock_infos (int sock, int *r_transport, void **r_tls_session);
unsigned short *getpts (char *, int *);

int open_stream_connection (struct arglist *, unsigned int, int, int);
int open_stream_connection_ext (struct arglist *, unsigned int, int, int,
                                const char *);
int open_stream_auto_encaps_ext (struct arglist *args, unsigned int port,
                                 int timeout, int force);

int write_stream_connection (int, void *buf, int n);
int read_stream_connection (int, void *, int);
int read_stream_connection_min (int, void *, int, int);
int nsend (int, void *, int, int);
void add_close_stream_connection_hook (int (*)(int));
int close_stream_connection (int);

const char *get_encaps_name (openvas_encaps_t);
const char *get_encaps_through (openvas_encaps_t);

/* Additional functions -- should not be used by the plugins */
int open_sock_opt_hn (const char *, unsigned int, int, int, int);

struct host_info *
host_info_init (const char *name, const struct in6_addr *,
                const char *, const char *);

void
host_info_free (struct host_info *);

int openvas_SSL_init (void);

int stream_set_buffer (int, int);
int stream_get_buffer_sz (int);
int stream_get_err (int);

int openvas_register_connection (int s, void *ssl,
                                 gnutls_certificate_credentials_t certcred,
                                 openvas_encaps_t encaps);
int openvas_deregister_connection (int);
int openvas_get_socket_from_connection (int);
gnutls_session_t ovas_get_tlssession_from_connection (int);

int stream_zero (fd_set *);
int stream_set (int, fd_set *);

int os_send (int, void *, int, int);
int os_recv (int, void *, int, int);

int internal_send (int, char *, int);
int internal_recv (int, char **, int *, int *);

int fd_is_stream (int);

int stream_set_timeout (int, int);

int socket_negotiate_ssl (int, openvas_encaps_t, struct arglist *);
void socket_get_cert (int, void **, int *);
int socket_get_ssl_version (int);
void socket_get_ssl_session_id (int, void **, size_t *);
int socket_get_ssl_compression (int);
int socket_get_ssl_ciphersuite (int);

#endif
