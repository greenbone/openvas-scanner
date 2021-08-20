/* Copyright (C) 2021 Greenbone Networks GmbH
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
 * @file messageutils.h
 * @brief Header file for the reporting module.
 */
#ifndef OPENVAS_REPORTING_H
#define OPENVAS_REPORTING_H

#include "scanneraux.h" /* for struct script_infos */

typedef enum
{
  ERRMSG,
  HOST_START,
  HOST_END,
  LOG,
  HOST_DETAIL,
  ALARM,
  DEADHOST,
  HOSTS_COUNT
} msg_t;

/*
 *  Messages generated from scan process.
 */

/*
 * Messages generated from host processes.
 */
void
host_message_nvt_timeout (const gchar*, const gchar*, const gchar*);

void
host_message (msg_t, const gchar*, const gchar*);


/*
 * Messages generated from plugin processes.
 */
void
proto_post_alarm (const char *, struct script_infos *, int, const char *,
                  const char *, const char *);

void
post_alarm (const char *, struct script_infos *, int, const char *,
            const char *);

void
post_alarm_udp (struct script_infos *, int, const char *, const char *);

#define post_alarm_tcp post_alarm

void
proto_post_error (const char *, struct script_infos *, int, const char *,
                  const char *, const char *);
void
post_error (const char *, struct script_infos *, int, const char *,
            const char *);

#define post_error_tcp post_error

void
proto_post_log (const char *, struct script_infos *, int, const char *,
                const char *, const char *);

void
post_log (const char *, struct script_infos *, int, const char *);

void
post_log_with_uri (const char *, struct script_infos *, int, const char *,
                   const char *);

#define post_log_tcp post_log

#endif
