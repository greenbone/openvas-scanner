/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2007 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file bpf_share.h
 * @brief Header file for module bpf_share.
 */

#ifndef MISC_BPF_SHARE_H
#define MISC_BPF_SHARE_H

#include <sys/types.h>

int
bpf_open_live (char *, char *);

u_char *
bpf_next (int, int *);

u_char *
bpf_next_tv (int, int *, struct timeval *);

void
bpf_close (int);

int
bpf_datalink (int);

#endif
