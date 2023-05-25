/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file ftp_funcs.h
 * @brief Header file for module ftp_funcs.
 */

#ifndef MISC_FTP_FUNCS_H
#define MISC_FTP_FUNCS_H

#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

int
ftp_log_in (int, char *, char *);

int
ftp_get_pasv_address (int, struct sockaddr_in *);

#endif
