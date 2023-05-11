/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file scanneraux.h
 * @brief Auxiliary structures for scanner.
 */

#ifndef MISC_SCANNERAUX_H
#define MISC_SCANNERAUX_H

#include <glib.h>
#include <gvm/base/nvti.h>
#include <gvm/util/kb.h>

struct scan_globals
{
  GHashTable *files_translation;
  GHashTable *files_size_translation;
  char *scan_id;
  pid_t host_pid;
};

struct host_info;

struct script_infos
{
  struct scan_globals *globals;
  struct ipc_context *ipc_context;
  kb_t key; // nvt_kb
  nvti_t *nvti;
  char *oid;
  char *name;
  GHashTable *udp_data;
  struct in6_addr *ip;
  GSList *vhosts;
  int standalone;
  int denial_port;
  int alive;
};

void
destroy_scan_globals (struct scan_globals *);

#endif /* not MISC_SCANNERAUX_H */
