/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_frame_forgery.h
 * @brief Header file for module nasl_frame_forgery.
 */

#ifndef NASL_NASL_FRAME_FORGERY_H
#define NASL_NASL_FRAME_FORGERY_H

#include "nasl_lex_ctxt.h"

tree_cell *
nasl_send_arp_request (lex_ctxt *);

tree_cell *
nasl_get_local_mac_address_from_ip (lex_ctxt *);

tree_cell *
nasl_forge_frame (lex_ctxt *);

tree_cell *
nasl_send_frame (lex_ctxt *);

tree_cell *
nasl_dump_frame (lex_ctxt *);

#endif // NASL_NASL_FRAME_FORGERY_H
