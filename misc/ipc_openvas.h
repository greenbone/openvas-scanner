/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MISC_IPC_OPENVAS_H
#define MISC_IPC_OPENVAS_H

#include "ipc.h"

#include <glib.h>

// ipc_data_type defines
enum ipc_data_type
{
  IPC_DT_ERROR = -1,
  IPC_DT_NO_DATA = 0,
  IPC_DT_HOSTNAME = 1,
  IPC_DT_USER_AGENT = 2,
  IPC_DT_LSC = 4,
};

typedef struct ipc_data ipc_data_t;

// prototypes for getting internal ipc_data_t information
enum ipc_data_type
ipc_get_data_type_from_data (ipc_data_t *data);

gchar *
ipc_get_hostname_from_data (ipc_data_t *data);

gchar *
ipc_get_hostname_source_from_data (ipc_data_t *data);

gchar *
ipc_get_user_agent_from_data (ipc_data_t *data);

gboolean
ipc_get_lsc_data_ready_flag (ipc_data_t *data);

gchar *
ipc_get_lsc_os_release_from_data (ipc_data_t *data);

// prototypes for handling of ipc_data_t and json
ipc_data_t *
ipc_data_type_from_hostname (const char *source, size_t source_len,
                             const char *hostname, size_t hostname_len);

ipc_data_t *
ipc_data_type_from_user_agent (const char *user_agent, size_t user_agent_len);

ipc_data_t *
ipc_data_type_from_lsc (gboolean data_ready);

void
ipc_data_destroy (ipc_data_t **data);

const char *
ipc_data_to_json (ipc_data_t *data);

ipc_data_t *
ipc_data_from_json (const char *json, size_t len);

#endif
