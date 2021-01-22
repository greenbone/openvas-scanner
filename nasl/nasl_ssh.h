/* Copyright (C) 2011-2021 Greenbone Networks GmbH
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
 * @file nasl_ssh.h
 * @brief Protos and data structures for SSH functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_ssh.c
 */

#ifndef NASL_SSH_H
#define NASL_SSH_H

#include "nasl_lex_ctxt.h"

#include <libssh/libssh.h>

tree_cell *
nasl_ssh_connect (lex_ctxt *lexic);
tree_cell *
nasl_ssh_disconnect (lex_ctxt *lexic);
tree_cell *
nasl_ssh_session_id_from_sock (lex_ctxt *lexic);
tree_cell *
nasl_ssh_get_sock (lex_ctxt *lexic);
tree_cell *
nasl_ssh_set_login (lex_ctxt *lexic);
tree_cell *
nasl_ssh_userauth (lex_ctxt *lexic);
tree_cell *
nasl_ssh_request_exec (lex_ctxt *lexic);
tree_cell *
nasl_ssh_shell_open (lex_ctxt *lexic);
tree_cell *
nasl_ssh_shell_read (lex_ctxt *lexic);
tree_cell *
nasl_ssh_shell_write (lex_ctxt *lexic);
tree_cell *
nasl_ssh_shell_close (lex_ctxt *lexic);
tree_cell *
nasl_ssh_login_interactive (lex_ctxt *lexic);
tree_cell *
nasl_ssh_login_interactive_pass (lex_ctxt *lexic);

tree_cell *
nasl_ssh_exec (lex_ctxt *);

tree_cell *
nasl_ssh_get_issue_banner (lex_ctxt *lexic);
tree_cell *
nasl_ssh_get_server_banner (lex_ctxt *lexic);
tree_cell *
nasl_ssh_get_auth_methods (lex_ctxt *lexic);
tree_cell *
nasl_ssh_get_host_key (lex_ctxt *lexic);

#endif /*NASL_SSH_H*/
