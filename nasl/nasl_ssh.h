/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_ssh.h
 * @brief Protos and data structures for SSH functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_ssh.c
 */

#ifndef NASL_NASL_SSH_H
#define NASL_NASL_SSH_H

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

/*
 * NASL SFTP
 */

tree_cell *
nasl_sftp_enabled_check (lex_ctxt *);

/*
 * NASL NETCONF
 */
tree_cell *
nasl_ssh_execute_netconf_subsystem (lex_ctxt *);

#endif /*NASL_NASL_SSH_H*/
