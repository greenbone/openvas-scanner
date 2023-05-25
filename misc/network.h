/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2007 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file network.h
 * @brief Header file for module network.
 */

#ifndef MISC_NETWORK_H
#define MISC_NETWORK_H

#include "scanneraux.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <netinet/in.h> /* struct in_addr, struct in6_addr */
#include <sys/select.h> /* at least for fd_set */

/*
 * Type of "transport layer", for encapsulated connections
 * Only SSL is supported at this time.
 * (Bad) examples of other layers could be SOCKS, httptunnel, icmptunnel,
 * RMI over HTTP, DCOM over HTTP, TCP over TCP, etc.
 */
typedef enum openvas_encaps
{
  OPENVAS_ENCAPS_AUTO = 0, /* Request auto detection.  */
  OPENVAS_ENCAPS_IP,
  OPENVAS_ENCAPS_SSLv23, /* Ask for compatibility options */
  OPENVAS_ENCAPS_SSLv2,
  OPENVAS_ENCAPS_SSLv3,
  OPENVAS_ENCAPS_TLSv1,
  OPENVAS_ENCAPS_TLSv11,
  OPENVAS_ENCAPS_TLSv12,
  OPENVAS_ENCAPS_TLSv13,
  OPENVAS_ENCAPS_TLScustom, /* SSL/TLS using custom priorities.  */
  OPENVAS_ENCAPS_MAX,
} openvas_encaps_t;

#define IS_ENCAPS_SSL(x) \
  ((x) >= OPENVAS_ENCAPS_SSLv23 && (x) <= OPENVAS_ENCAPS_TLScustom)

/* Define FLAGS for setting other priorities in
   open_stream_connection_ext */
#define NO_PRIORITY_FLAGS 0
#define INSECURE_DH_PRIME_BITS (1 << 0) // 1

/* Plugin specific network functions */
int
open_sock_tcp (struct script_infos *, unsigned int, int);

int
open_sock_option (struct script_infos *, unsigned int, int, int, int);

int
recv_line (int, char *, size_t);

int
nrecv (int, void *, int, int);

int
socket_close (int);

int
get_sock_infos (int sock, int *r_transport, void **r_tls_session);

unsigned short *
getpts (char *, int *);

void
open_stream_tls_default_priorities (const char *p, const int pflag);

int
open_stream_connection (struct script_infos *, unsigned int, int, int);

int
open_stream_connection_ext (struct script_infos *, unsigned int, int, int,
                            const char *, int);

int
open_stream_auto_encaps_ext (struct script_infos *, unsigned int port,
                             int timeout, int force);

int
write_stream_connection (int, void *buf, int n);

int
read_stream_connection (int, void *, int);

int
read_stream_connection_min (int, void *, int, int);

int
nsend (int, void *, int, int);

void
add_close_stream_connection_hook (int (*) (int));

int
close_stream_connection (int);

const char *get_encaps_name (openvas_encaps_t);

const char *get_encaps_through (openvas_encaps_t);

/* Additional functions -- should not be used by the plugins */
int
open_sock_opt_hn (const char *, unsigned int, int, int, int);

int
openvas_SSL_init (void);

int
stream_set_buffer (int, int);

int
stream_get_buffer_sz (int);

int
stream_get_err (int);

int
openvas_register_connection (int s, void *ssl,
                             gnutls_certificate_credentials_t certcred,
                             openvas_encaps_t encaps);
int
openvas_deregister_connection (int);

int
openvas_get_socket_from_connection (int);

gnutls_session_t
ovas_get_tlssession_from_connection (int);

int
stream_zero (fd_set *);

int
stream_set (int, fd_set *);

int
os_send (int, void *, int, int);

int
os_recv (int, void *, int, int);

int
fd_is_stream (int);

int
stream_set_timeout (int, int);

int
socket_ssl_safe_renegotiation_status (int);
int
socket_ssl_do_handshake (int);

int
socket_negotiate_ssl (int, openvas_encaps_t, struct script_infos *);

void
socket_get_cert (int, void **, int *);

int
socket_get_ssl_version (int);

void
socket_get_ssl_session_id (int, void **, size_t *);

int
socket_get_ssl_compression (int);

int
socket_get_ssl_ciphersuite (int);

#endif
