/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file plugs_req.h
 * @brief plugs_req.c header.
 */

#ifndef OPENVAS_PLUGS_REQ_H
#define OPENVAS_PLUGS_REQ_H

#include <gvm/util/kb.h> /* for struct kb_item */

char *
requirements_plugin (kb_t, nvti_t *);

int
mandatory_requirements_met (kb_t, nvti_t *);

#endif
