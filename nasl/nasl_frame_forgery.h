/* Copyright (C) 2021-2022 Greenbone Networks GmbH
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
 * @file nasl_frame_forgery.h
 * @brief Header file for module nasl_frame_forgery.
 */

#ifndef NASL_FRAME_FORGERY_H
#define NASL_FRAME_FORGERY_H

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

#endif // NASL_FRAME_FORGERY_H
