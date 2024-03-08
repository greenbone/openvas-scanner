/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file nasl_ssh.c
 * @brief Implementation of an API for SSH functions.
 *
 * This file contains the implementation of the Secure Shell related
 * NASL builtin functions.  They are only available if build with
 * libssh support.
 */

#include "nasl_ssh.h"

#include "../misc/network.h" /* for openvas_get_socket_from_connection */
#include "../misc/plugutils.h"
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gvm/base/logging.h>
#include <gvm/base/networking.h>
#include <gvm/base/prefs.h> /* for prefs_get() */
#include <gvm/util/kb.h>
#include <libssh/sftp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef DIM
#define DIM(v) (sizeof (v) / sizeof ((v)[0]))
#define DIMof(type, member) DIM (((type *) 0)->member)
#endif

#if SSH_OK != 0
#error Oops, libssh ABI changed
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/* This object is used to keep track of libssh contexts.  Because they
   are pointers they can't be mapped easily to the NASL type system.
   We would need to define a new type featuring a callback which would
   be called when that variable will be freed.  This is not easy and
   has several implications.  A clean solution requires a decent
   garbage collector system with an interface to flange arbitrary C
   subsystems to it.  After all we would end up with a complete VM
   and FFI.  We don't want to do that now.

   Our solution is to track those contexts here and clean up any left
   over context at the end of a script run.  We could use undocumented
   "on_exit" feature but that one is not well implemented; thus we use
   explicit code in the interpreter for the cleanup.  The scripts are
   expected to close the sessions, but as long as they don't open too
   many of them, the system will take care of it at script termination
   time.

   We associate each context with a session id, which is a global
   counter of this process.  The simpler version of using slot numbers
   won't allow for better consistency checks.  A session id of 0 marks
   an unused table entry.

   Note that we can't reuse a session for another connection. To use a
   session is always an active or meanwhile broken connection to the
   server.
 */
struct session_table_item_s
{
  int session_id;
  ssh_session session;
  ssh_channel channel;
  int sock;                           /* The associated socket. */
  int authmethods;                    /* Bit fields with available
                                         authentication methods.  */
  unsigned int authmethods_valid : 1; /* Indicating that methods is valid.  */
  unsigned int user_set : 1;          /* Set if a user has been set for
                                         the session.  */
  unsigned int verbose : 1;           /* Verbose diagnostics.  */
};

#define MAX_SSH_SESSIONS 10
static struct session_table_item_s session_table[MAX_SSH_SESSIONS];

/* Local prototypes.  */
static int
nasl_ssh_close_hook (int);

static void
g_string_comma_str (GString *gstr, const char *str)
{
  if (gstr->len)
    g_string_append (gstr, ",");
  g_string_append (gstr, str);
}

/* Return the next session id.  Note that the first session ID we will
   hand out is an arbitrary high number, this is only to help
   debugging.  This function is also used to setup a hook to the
   network layer. */
static int
next_session_id (void)
{
  static int initialized;
  static int last = 9000;
  unsigned int i;

  if (!initialized)
    {
      add_close_stream_connection_hook (nasl_ssh_close_hook);
      initialized = 1;
    }

again:
  last++;
  /* Because we don't have an unsigned type, it is better to avoid
     negative values.  Thus if LAST turns negative we wrap around to
     1; this also avoids the verboten zero.  */
  if (last <= 0)
    last = 1;
  /* Now it may happen that after wrapping there is still a session id
     with that new value in use.  We can't allow that and check for
     it.  */
  for (i = 0; i < DIM (session_table); i++)
    if (session_table[i].session_id == last)
      goto again;

  return last;
}

/* Return the port for an SSH connection.  It first looks up the port
   in the preferences, then falls back to the KB, and finally resorts
   to the standard port. */
static unsigned short
get_ssh_port (lex_ctxt *lexic)
{
  const char *value;
  int type = KB_TYPE_INT;
  unsigned short port, *port_aux = NULL;

  value = prefs_get ("auth_port_ssh");
  if (value && (port = (unsigned short) strtoul (value, NULL, 10)) > 0)
    return port;

  port_aux = (unsigned short *) plug_get_key (lexic->script_infos,
                                              "Services/ssh", &type, NULL, 0);

  if (port_aux)
    {
      port = *port_aux;
      g_free (port_aux);
      if (type == KB_TYPE_INT && port > 0)
        return port;
    }

  return 22;
}

extern int lowest_socket;

/**
 * @brief Connect to the target host via TCP and setup an ssh
 *        connection.
 * @naslfn{ssh_connect}
 *
 * If the named argument "socket" is given, that socket will be used
 * instead of a creating a new TCP connection.  If socket is not given
 * or 0, the port is looked up in the preferences and the KB unless
 * overridden by the named parameter "port".
 *
 * On success an ssh session to the host has been established; the
 * caller may then run an authentication function.  If the connection
 * is no longer needed, ssh_disconnect may be used to disconnect and
 * close the socket.
 *
 * @naslnparam
 *
 * - @a socket If given, this socket will be used instead of creating
 *             a new connection.
 *
 * - @a port A non-standard port to connect to.  This is only used if
 *           @a socket is not given or 0.
 *
 * - @a keytype List of the preferred server host key types. Example:
 *              "ssh-rsa,ssh-dss"
 *
 * - @a csciphers SSH client-to-server ciphers.
 *
 * - @a scciphers SSH server-to-client ciphers.
 *
 * - @a timeout Set a timeout for the connection in seconds. Defaults to 10
 * seconds (defined by libssh internally) if not given.
 *
 * @naslret An integer to identify the ssh session. Zero on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with a non-zero
 *         integer identifying that ssh session; zero is returned on a
 *         connection error.  In case of an internal error NULL is
 *         returned.
 */
tree_cell *
nasl_ssh_connect (lex_ctxt *lexic)
{
  ssh_session session;
  tree_cell *retc;
  const char *key_type, *csciphers, *scciphers, *s;
  char ip_str[INET6_ADDRSTRLEN];
  int port, sock;
  unsigned int tbl_slot;
  int verbose = 0;
  int forced_sock = -1;
  long timeout; // in seconds

  sock = get_int_var_by_name (lexic, "socket", 0);
  if (sock)
    port = 0; /* The port is ignored if "socket" is given.  */
  else
    {
      port = get_int_var_by_name (lexic, "port", 0);
      if (port <= 0)
        port = get_ssh_port (lexic);
    }

  addr6_to_str (plug_get_host_ip (lexic->script_infos), ip_str);
  session = ssh_new ();
  if (!session)
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to allocate a new SSH session",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename ());
      return NULL;
    }

  timeout = get_int_var_by_name (lexic, "timeout", 0);
  if (timeout > 0)
    if (ssh_options_set (session, SSH_OPTIONS_TIMEOUT, &timeout))
      {
        g_message (
          "Function %s called from %s: "
          "Failed to set the SSH connection timeout to %ld seconds: %s",
          nasl_get_function_name (), nasl_get_plugin_filename (), timeout,
          ssh_get_error (session));
        ssh_free (session);
        return NULL;
      }

  if ((s = getenv ("OPENVAS_LIBSSH_DEBUG")))
    {
      verbose = 1;
      if (*s)
        {
          int intval = atoi (s);

          ssh_options_set (session, SSH_OPTIONS_LOG_VERBOSITY, &intval);
        }
    }

  if (ssh_options_set (session, SSH_OPTIONS_HOST, ip_str))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to set SSH hostname '%s': %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (), ip_str,
                 ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  if (ssh_options_set (session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null"))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to disable SSH known_hosts: %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (),
                 ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  key_type = get_str_var_by_name (lexic, "keytype");

  if (key_type && ssh_options_set (session, SSH_OPTIONS_HOSTKEYS, key_type))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to set SSH key type '%s': %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (), key_type,
                 ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  csciphers = get_str_var_by_name (lexic, "csciphers");
  if (csciphers
      && ssh_options_set (session, SSH_OPTIONS_CIPHERS_C_S, csciphers))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to set SSH client to server ciphers '%s': %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (), csciphers,
                 ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }
  scciphers = get_str_var_by_name (lexic, "scciphers");
  if (scciphers
      && ssh_options_set (session, SSH_OPTIONS_CIPHERS_S_C, scciphers))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "Failed to set SSH server to client ciphers '%s': %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (), scciphers,
                 ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  if (port)
    {
      unsigned int my_port = port;

      if (ssh_options_set (session, SSH_OPTIONS_PORT, &my_port))
        {
          g_message (
            "Function %s (calling internal function %s) called from %s: "
            "Failed to set SSH port for '%s' to %d: %s",
            nasl_get_function_name () ? nasl_get_function_name ()
                                      : "script_main_function",
            __func__, nasl_get_plugin_filename (), ip_str, port,
            ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
    }
  if (sock)
    {
      socket_t my_fd = openvas_get_socket_from_connection (sock);

      if (verbose)
        g_message ("Setting SSH fd for '%s' to %d (NASL sock=%d)", ip_str,
                   my_fd, sock);
      if (ssh_options_set (session, SSH_OPTIONS_FD, &my_fd))
        {
          g_message (
            "Function %s (calling internal function %s) called from %s: "
            "Failed to set SSH fd for '%s' to %d (NASL sock=%d): %s",
            nasl_get_function_name () ? nasl_get_function_name ()
                                      : "script_main_function",
            __func__, nasl_get_plugin_filename (), ip_str, my_fd, sock,
            ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
      /* Remember the NASL socket.  */
      forced_sock = sock;
    }

  /* Find a place in the table to save the session.  */
  for (tbl_slot = 0; tbl_slot < DIM (session_table); tbl_slot++)
    if (!session_table[tbl_slot].session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      if (verbose)
        g_message ("No space left in SSH session table");
      ssh_free (session);
      return NULL;
    }

  /* Prepare the session table entry.  */
  session_table[tbl_slot].session = session;
  session_table[tbl_slot].authmethods_valid = 0;
  session_table[tbl_slot].user_set = 0;
  session_table[tbl_slot].verbose = verbose;

  /* Connect to the host.  */
  if (verbose)
    g_message ("Connecting to SSH server '%s' (port %d, sock %d)", ip_str, port,
               sock);
  if (ssh_connect (session))
    {
      if (verbose)
        g_message ("Failed to connect to SSH server '%s'"
                   " (port %d, sock %d, f=%d): %s",
                   ip_str, port, sock, forced_sock, ssh_get_error (session));
      if (forced_sock != -1)
        {
          /* If the caller passed us a socket we can't call ssh_free
             on it because we expect the caller to close that socket
             himself.  Instead we need to setup a table entry so that
             it will then be close it via nasl_ssh_internal_close.  */
          session_table[tbl_slot].session_id = next_session_id ();
          session_table[tbl_slot].sock = forced_sock;
        }
      else
        ssh_free (session);

      /* return 0 to indicate the error.  */
      /* FIXME: Set the last error string.  */
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = 0;
      return retc;
    }

  /* How that we are connected, save the session.  */
  session_table[tbl_slot].session_id = next_session_id ();
  session_table[tbl_slot].sock =
    forced_sock != -1 ? forced_sock : ssh_get_fd (session);
  if (lowest_socket == 0 && session_table[tbl_slot].sock > 0)
    lowest_socket = session_table[tbl_slot].sock;

  /* Return the session id.  */
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}

/* Helper function to find and validate the session id.  On error 0 is
   returned, on success the session id and in this case the slot number
   from the table is stored at R_SLOT.  */
static int
verify_session_id (int session_id, const char *funcname, int *r_slot,
                   lex_ctxt *lexic)
{
  unsigned int tbl_slot;
  if (session_id <= 0)
    {
      if (funcname)
        nasl_perror (lexic, "Invalid SSH session id %d passed to %s",
                     session_id, funcname);
      return 0;
    }
  for (tbl_slot = 0; tbl_slot < DIM (session_table); tbl_slot++)
    if (session_table[tbl_slot].session_id == session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      if (funcname)
        nasl_perror (lexic, "Bad SSH session id %d passed to %s", session_id,
                     funcname);
      return 0;
    }

  *r_slot = tbl_slot;
  return session_id;
}

/* Helper for nasl_ssh_disconnect et al.  */
static void
do_nasl_ssh_disconnect (int tbl_slot)
{
  if (session_table[tbl_slot].channel)
    ssh_channel_free (session_table[tbl_slot].channel);
  ssh_disconnect (session_table[tbl_slot].session);
  ssh_free (session_table[tbl_slot].session);
  session_table[tbl_slot].session_id = 0;
  session_table[tbl_slot].session = NULL;
  session_table[tbl_slot].channel = NULL;
  session_table[tbl_slot].sock = -1;
}

/**
 * @brief Disconnect an ssh connection
 * @naslfn{ssh_disconnect}
 *
 * This function takes the ssh session id (as returned by ssh_connect)
 * as its only unnamed argument.  Passing 0 as session id is
 * explicitly allowed and does nothing.  If there are any open
 * channels they are closed as well and their ids will be marked as
 * invalid.
 *
 * @nasluparam
 *
 * - An SSH session id.  A value of 0 is allowed and acts as a NOP.
 *
 * @naslret Nothing
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Nothing.
 */
tree_cell *
nasl_ssh_disconnect (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, NULL, &tbl_slot, lexic))
    return FAKE_CELL;
  do_nasl_ssh_disconnect (tbl_slot);
  return FAKE_CELL;
}

/**
 * @brief Hook to close a socket associated with an ssh connection.
 *
 * NASL code may be using "ssh_connect" passing an open socket and
 * later closing this socket using "close" instead of calling
 * "ssh_disconnect".  Thus the close code needs to check whether the
 * socket refers to an ssh connection and call ssh_disconnect then
 * (libssh takes ownership of the socket if set via SSH_OPTIONS_FD).
 * This function implements the hook for checking and closing.
 *
 * @param[in] sock A socket
 *
 * @return Zero if the socket was closed (disconnected).
 */
static int
nasl_ssh_close_hook (int sock)
{
  int session_id;
  unsigned int tbl_slot;

  if (sock == -1)
    return -1;

  session_id = 0;
  for (tbl_slot = 0; tbl_slot < DIM (session_table); tbl_slot++)
    {
      if (session_table[tbl_slot].sock == sock
          && session_table[tbl_slot].session_id)
        {
          session_id = session_table[tbl_slot].session_id;
          break;
        }
    }
  if (!session_id || tbl_slot >= DIM (session_table))
    return -1;
  do_nasl_ssh_disconnect (tbl_slot);
  return 0;
}

/**
 * @brief Given a socket, return the corresponding session id.
 * @naslfn{ssh_session_id_from_sock}
 * @nasluparam
 * - A NASL socket value
 *
 * @naslret An integer with the corresponding ssh session id or 0 if
 *          no session id is known for the given socket.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The session id on success or 0 if not found.
 */
tree_cell *
nasl_ssh_session_id_from_sock (lex_ctxt *lexic)
{
  int sock, session_id;
  unsigned int tbl_slot;
  tree_cell *retc;

  session_id = 0;
  sock = get_int_var_by_num (lexic, 0, -1);
  if (sock != -1)
    {
      for (tbl_slot = 0; tbl_slot < DIM (session_table); tbl_slot++)
        if (session_table[tbl_slot].sock == sock
            && session_table[tbl_slot].session_id)
          {
            session_id = session_table[tbl_slot].session_id;
            break;
          }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_id;
  return retc;
}

/**
 * @brief Given a session id, return the corresponding socket
 * @naslfn{ssh_get_sock}
 *
 * The socket is either a native file descriptor or a NASL connection
 * socket (if a open socket was passed to ssh_connect).  The NASL
 * network code handles both of them.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret An integer representing the socket or -1 on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The socket or -1 on error.
 */
tree_cell *
nasl_ssh_get_sock (lex_ctxt *lexic)
{
  int tbl_slot, sock, session_id;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_sock", &tbl_slot, lexic))
    sock = -1;
  else
    sock = session_table[tbl_slot].sock;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = sock;
  return retc;
}

/* Get the list of supported authentication schemes.  Returns 0 if no
   authentication is required; otherwise non-zero.  */
static int
get_authmethods (int tbl_slot)
{
  int rc;
  int retc_val = -1;
  ssh_session session;
  int verbose;
  int methods;

  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  rc = ssh_userauth_none (session, NULL);
  if (rc == SSH_AUTH_SUCCESS)
    {
      g_message ("SSH authentication succeeded using the none method - "
                 "should not happen; very old server?");
      retc_val = 0;
      methods = 0;
      goto leave;
    }
  else if (rc == SSH_AUTH_DENIED)
    {
      methods = ssh_userauth_list (session, NULL);
    }
  else
    {
      if (verbose)
        g_message ("SSH server did not return a list of authentication methods"
                   " - trying all");
      methods = (SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PASSWORD
                 | SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_HOSTBASED
                 | SSH_AUTH_METHOD_INTERACTIVE);
    }

  if (verbose)
    {
      fputs ("SSH available authentication methods:", stderr);
      if ((methods & SSH_AUTH_METHOD_NONE))
        fputs (" none", stderr);
      if ((methods & SSH_AUTH_METHOD_PASSWORD))
        fputs (" password", stderr);
      if ((methods & SSH_AUTH_METHOD_PUBLICKEY))
        fputs (" publickey", stderr);
      if ((methods & SSH_AUTH_METHOD_HOSTBASED))
        fputs (" hostbased", stderr);
      if ((methods & SSH_AUTH_METHOD_INTERACTIVE))
        fputs (" keyboard-interactive", stderr);
      fputs ("\n", stderr);
    }

leave:
  session_table[tbl_slot].authmethods = methods;
  session_table[tbl_slot].authmethods_valid = 1;

  return retc_val;
}

/**
 * @brief Set the login name for the authentication.
 * @naslfn{ssh_set_login}
 *
 * This is an optional function and usuallay not required.  However,
 * if you want to get the banner before starting the authentication,
 * you need to tell libssh the user because it is often not possible
 * to change the user after the first call to an authentication
 * methods - getting the banner uses an authentication function.
 *
 * The named argument "login" is used for the login name; it defaults
 * the KB entry "Secret/SSH/login".  It should contain the user name
 * to login.  Given that many servers don't allow changing the login
 * for an established connection, the "login" parameter is silently
 * ignored on all further calls.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name (optional).
 *
 * @naslret None
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return none.
 */
tree_cell *
nasl_ssh_set_login (lex_ctxt *lexic)
{
  int tbl_slot, session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_set_login", &tbl_slot, lexic))
    return NULL; /* Ooops.  */
  if (!session_table[tbl_slot].user_set)
    {
      ssh_session session = session_table[tbl_slot].session;
      kb_t kb;
      char *username;

      username = g_strdup (get_str_var_by_name (lexic, "login"));
      if (!username)
        {
          kb = plug_get_kb (lexic->script_infos);
          username = kb_item_get_str (kb, "Secret/SSH/login");
        }
      if (username && *username
          && ssh_options_set (session, SSH_OPTIONS_USER, username))
        {
          g_message (
            "Function %s (calling internal function %s) called from %s: "
            "Failed to set SSH username '%s': %s",
            nasl_get_function_name () ? nasl_get_function_name ()
                                      : "script_main_function",
            __func__, nasl_get_plugin_filename (), username,
            ssh_get_error (session));
          g_free (username);
          return NULL; /* Ooops.  */
        }
      /* In any case mark the user has set.  */
      session_table[tbl_slot].user_set = 1;
      g_free (username);
    }
  return FAKE_CELL;
}

/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_userauth}
 *
 * The function expects the session id as its first unnamed argument.
 * The first time this function is called for a session id, the named
 * argument "login" is also expected; it defaults the KB entry
 * "Secret/SSH/login".  It should contain the user name to login.
 * Given that many servers don't allow changing the login for an
 * established connection, the "login" parameter is silently ignored
 * on all further calls.
 *
 * To perform a password based authentication, the named argument
 * "password" must contain a password.
 *
 * To perform a public key based authentication, the named argument
 * "privatekey" must contain a base64 encoded private key in ssh
 * native or in PKCS#8 format.
 *
 * If both, "password" and "privatekey" are given as named arguments
 * only "password" is used.  If neither are given the values are taken
 * from the KB ("Secret/SSH/password" and "Secret/SSH/privatekey") and
 * tried in the order {password, privatekey}.  Note well, that if one
 * of the named arguments are given, only those are used and the KB is
 * not consulted.
 *
 * If the private key is protected, its passphrase is taken from the
 * named argument "passphrase" or, if not given, taken from the KB
 * ("Secret/SSH/passphrase").
 *
 * Note that the named argument "publickey" and the KB item
 * ("Secret/SSH/publickey") are ignored - they are not longer required
 * because they can be derived from the private key.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name.
 *
 * - @a password A string with the password.
 *
 * - @a privatekey A base64 encoded private key in ssh native or in
 *      pkcs#8 format.  This parameter is ignored if @a password is given.
 *
 * - @a passphrase A string with the passphrase used to unprotect @a
 *      privatekey.
 *
 * @naslret An integer as status value; 0 indicates success.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return 0 is returned on success.  Any other value indicates an
 *         error.
 */
tree_cell *
nasl_ssh_userauth (lex_ctxt *lexic)
{
  int rc, retc_val = -1, methods, verbose, tbl_slot, session_id;
  ssh_session session;
  char *password = NULL;
  char *privkeystr = NULL;
  char *privkeypass = NULL;
  kb_t kb;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_userauth", &tbl_slot, lexic))
    return NULL; /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* Check if we need to set the user.  This is done only once per
     session.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;

  kb = plug_get_kb (lexic->script_infos);
  password = g_strdup (get_str_var_by_name (lexic, "password"));
  privkeystr = g_strdup (get_str_var_by_name (lexic, "privatekey"));
  privkeypass = g_strdup (get_str_var_by_name (lexic, "passphrase"));
  if (!password && !privkeystr && !privkeypass)
    {
      password = kb_item_get_str (kb, "Secret/SSH/password");
      privkeystr = kb_item_get_str (kb, "Secret/SSH/privatekey");
      privkeypass = kb_item_get_str (kb, "Secret/SSH/passphrase");
    }

  /* Get the authentication methods only once per session.  */
  if (!session_table[tbl_slot].authmethods_valid)
    {
      if (!get_authmethods (tbl_slot))
        {
          retc_val = 0;
          goto leave;
        }
    }
  methods = session_table[tbl_slot].authmethods;

  /* Check whether a password has been given.  If so, try to
     authenticate using that password.  Note that the OpenSSH client
     uses a different order it first tries the public key and then the
     password.  However, the old NASL SSH protocol implementation tries
     the password before the public key authentication.  Because we
     want to be compatible, we do it in that order. */
  if (password && (methods & SSH_AUTH_METHOD_PASSWORD))
    {
      rc = ssh_userauth_password (session, NULL, password);
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }

      if (verbose)
        g_message ("SSH password authentication failed for session"
                   " %d: %s",
                   session_id, ssh_get_error (session));
      /* Keep on trying.  */
    }

  if (password && (methods & SSH_AUTH_METHOD_INTERACTIVE))
    {
      /* Our strategy for kbint is to send the password to the first
         prompt marked as non-echo.  */
      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          const char *s;
          int n, nprompt;
          char echoflag;
          int found_prompt = 0;

          if (verbose)
            {
              s = ssh_userauth_kbdint_getname (session);
              if (s && *s)
                g_message ("SSH kbdint name='%s'", s);
              s = ssh_userauth_kbdint_getinstruction (session);
              if (s && *s)
                g_message ("SSH kbdint instruction='%s'", s);
            }
          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n = 0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s && verbose)
                g_message ("SSH kbdint prompt='%s'%s", s,
                           echoflag ? "" : " [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                {
                  found_prompt = 1;
                  rc = ssh_userauth_kbdint_setanswer (session, n, password);
                  if (rc != SSH_AUTH_SUCCESS)
                    {
                      if (verbose)
                        g_message ("SSH keyboard-interactive authentication "
                                   "failed at prompt %d for session %d: %s",
                                   n, session_id, ssh_get_error (session));
                    }
                }
            }
        }

      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }

      if (verbose)
        g_message (
          "SSH keyboard-interactive authentication failed for session %d"
          ": %s",
          session_id, ssh_get_error (session));
      /* Keep on trying.  */
    }

  /* If we have a private key, try public key authentication.  */
  if (privkeystr && *privkeystr && (methods & SSH_AUTH_METHOD_PUBLICKEY))
    {
      ssh_key key = NULL;

      if (ssh_pki_import_privkey_base64 (privkeystr, privkeypass, NULL, NULL,
                                         &key))
        {
          if (verbose)
            g_message ("SSH public key authentication failed for "
                       "session %d: %s",
                       session_id, "Error converting provided key");
        }
      else if (ssh_userauth_try_publickey (session, NULL, key)
               != SSH_AUTH_SUCCESS)
        {
          if (verbose)
            g_message ("SSH public key authentication failed for "
                       "session %d: %s",
                       session_id, "Server does not want our key");
        }
      else if (ssh_userauth_publickey (session, NULL, key) == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          ssh_key_free (key);
          goto leave;
        }
      ssh_key_free (key);
      /* Keep on trying.  */
    }

  if (verbose)
    g_message ("SSH authentication failed for session %d: %s", session_id,
               "No more authentication methods to try");

leave:
  g_free (password);
  g_free (privkeystr);
  g_free (privkeypass);
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = retc_val;
  return retc;
}

/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_login_intenteractive}
 *
 * The function starts the authentication process and pauses it when
 * it finds the first non-echo prompt. The function expects the session
 * id as its first unnamed argument.
 * The first time this function is called for a session id, the named
 * argument "login" is also expected.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string containing the prompt is returned on success.
 *         NULL indicates that the error.
 */
tree_cell *
nasl_ssh_login_interactive (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  const char *s = NULL;
  int methods;
  int verbose;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_login_interactive", &tbl_slot,
                          lexic))
    return NULL; /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* Check if we need to set the user.  This is done only once per
     session.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;

  /* Get the authentication methods only once per session.  */
  if (!session_table[tbl_slot].authmethods_valid)
    {
      if (!get_authmethods (tbl_slot))
        {
          s = g_strdup ("");
          goto leave;
        }
    }
  methods = session_table[tbl_slot].authmethods;

  if (methods & SSH_AUTH_METHOD_INTERACTIVE)
    {
      /* Our strategy for kbint is to send the password to the first
         prompt marked as non-echo.  */

      while (ssh_userauth_kbdint (session, NULL, NULL) == SSH_AUTH_INFO)
        {
          int n, nprompt;
          char echoflag;
          int found_prompt = 0;

          if (verbose)
            {
              s = ssh_userauth_kbdint_getname (session);
              if (s && *s)
                g_message ("SSH kbdint name='%s'", s);
              s = ssh_userauth_kbdint_getinstruction (session);
              if (s && *s)
                g_message ("SSH kbdint instruction='%s'", s);
            }

          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n = 0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s && verbose)
                g_message ("SSH kbdint prompt='%s'%s", s,
                           echoflag ? "" : " [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                goto leave;
            }
        }
      if (verbose)
        g_message (
          "SSH keyboard-interactive authentication failed for session %d"
          ": %s",
          session_id, ssh_get_error (session));
    }

  if (!s)
    return NULL;

leave:
  {
    tree_cell *retc;

    retc = alloc_typed_cell (CONST_DATA);
    retc->x.str_val = g_strdup (s);
    retc->size = strlen (s);
    return retc;
  }
}

/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_login_intenteractive_pass}
 *
 * The function finishes the authentication process started by
 * ssh_login_interactive. The function expects the session id as its first
 * unnamed argument.
 *
 * To finish the password, the named argument "password" must contain
 * a password.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a password A string with the password.
 *
 * @naslret An integer as status value; 0 indicates success.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return An integer is returned on success. -1 indicates an
 *         error.
 */
tree_cell *
nasl_ssh_login_interactive_pass (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  const char *password = NULL;
  int rc;
  int retc_val = -1;
  int verbose;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_login_interactive_pass", &tbl_slot,
                          lexic))
    return NULL; /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* A prompt is waiting for the password. */
  if ((password = get_str_var_by_name (lexic, "password")) == NULL)
    return NULL;

  rc = ssh_userauth_kbdint_setanswer (session, 0, password);

  if (rc < 0)
    {
      if (verbose)
        g_message ("SSH keyboard-interactive authentication "
                   "failed at prompt %d for session %d: %s",
                   0, session_id, ssh_get_error (session));
      retc_val = -1;
      goto leave;
    }

  if (rc == 0)
    {
      /* I need to do that to finish the auth process. */
      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          ssh_userauth_kbdint_getnprompts (session);
        }
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }
      if (rc != SSH_AUTH_SUCCESS)
        {
          retc_val = -1;
          goto leave;
        }
    }

leave:
  {
    tree_cell *retc;

    retc = alloc_typed_cell (CONST_INT);
    retc->x.i_val = retc_val;
    return retc;
  }
}

static void
exec_ssh_cmd_alarm (int signal)
{
  (void) signal;
  g_message ("exec_ssh_cmd: Timeout");
}

/**
 * @brief Execute an ssh command.
 *
 * @param[in]   session     SSH session.
 * @param[in]   cmd         Command to execute.
 * @param[in]   verbose     1 for verbose mode, 0 otherwise.
 * @param[in]   compat_mode 1 for compatibility mode, 0 otherwise.
 * @param[in]   to_stdout   1 to return command output to stdout.
 * @param[in]   to_stderr   1 to return command output to stderr.
 * @param[out]  response    Response buffer.
 * @param[out]  compat_buf  Compatibility buffer.
 *
 *
 * @return SSH_OK if success, SSH_ERROR otherwise.
 */
static int
exec_ssh_cmd (ssh_session session, char *cmd, int verbose, int compat_mode,
              int to_stdout, int to_stderr, GString *response,
              GString *compat_buf)
{
  int rc = 1;
  ssh_channel channel;
  char buffer[4096];

  /* Work-around for LibSSH calling poll() with an infinite timeout. */
  signal (SIGALRM, exec_ssh_cmd_alarm);
  alarm (30);
  if ((channel = ssh_channel_new (session)) == NULL)
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "ssh_channel_new failed: %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (),
                 ssh_get_error (session));
      return SSH_ERROR;
    }

  if (ssh_channel_open_session (channel))
    {
      /* FIXME: Handle SSH_AGAIN.  */
      if (verbose)
        g_message ("ssh_channel_open_session failed: %s",
                   ssh_get_error (session));
      ssh_channel_free (channel);
      return SSH_ERROR;
    }

  if (ssh_channel_request_pty (channel) && verbose)
    g_message ("ssh_channel_request_pty failed: %s", ssh_get_error (session));

  if (ssh_channel_request_exec (channel, cmd))
    {
      /* FIXME: Handle SSH_AGAIN.  */
      if (verbose)
        g_message ("ssh_channel_request_exec failed for '%s': %s", cmd,
                   ssh_get_error (session));
      ssh_channel_free (channel);
      return SSH_ERROR;
    }
  alarm (0);
  signal (SIGALRM, _exit);
  while (rc > 0)
    {
      if ((rc = ssh_channel_read_timeout (channel, buffer, sizeof (buffer), 1,
                                          15000))
          > 0)
        {
          if (to_stderr)
            g_string_append_len (response, buffer, rc);
          if (compat_mode)
            g_string_append_len (compat_buf, buffer, rc);
        }
      if (rc == SSH_ERROR)
        goto exec_err;
    }
  rc = 1;
  while (rc > 0)
    {
      if ((rc = ssh_channel_read_timeout (channel, buffer, sizeof (buffer), 0,
                                          15000))
          > 0)
        {
          if (to_stdout)
            g_string_append_len (response, buffer, rc);
        }
      if (rc == SSH_ERROR)
        goto exec_err;
    }
  rc = SSH_OK;

exec_err:
  ssh_channel_free (channel);
  return rc;
}

/**
 * @brief Run a command via ssh.
 * @naslfn{ssh_request_exec}
 *
 * The function opens a channel to the remote end and ask it to
 * execute a command.  The output of the command is then returned as a
 * data block.  The first unnamed argument is the session id. The
 * command itself is expected as string in the named argument "cmd".
 *
 * Regarding the handling of the stderr and stdout stream, this
 * function may be used in different modes.
 *
 * If either the named arguments @a stdout or @a stderr are given and
 * that one is set to 1, only the output of the specified stream is
 * returned.
 *
 * If @a stdout and @a stderr are both given and set to 1, the output
 * of both is returned interleaved.  NOTE: The following feature has
 * not yet been implemented: The output is guaranteed not to switch
 * between stderr and stdout within a line.
 *
 * If @a stdout and @a stderr are both given but set to 0, a special
 * backward compatibility mode is used: First all output to stderr is
 * collected up until any output to stdout is received.  Then all
 * output to stdout is returned while ignoring all further stderr
 * output; at EOF the initial collected data from stderr is returned.
 *
 * If the named parameters @a stdout and @a stderr are not given, the
 * function acts exactly as if only @a stdout has been set to 1.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a cmd A string with the command to execute.
 *
 * - @a stdout An integer with value 0 or 1; see above for a full
 *    description.
 *
 * - @a stderr An integer with value 0 or 1; see above for a full
 *    description.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A data/string is returned on success.  NULL indicates an
 *         error.
 */
tree_cell *
nasl_ssh_request_exec (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  int verbose;
  char *cmd;
  int rc;
  GString *response;
  GString *compat_buf = NULL;
  size_t len = 0;
  tree_cell *retc;
  char *p;
  int to_stdout, to_stderr, compat_mode, compat_buf_inuse;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_request_exec", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  verbose = session_table[tbl_slot].verbose;

  cmd = get_str_var_by_name (lexic, "cmd");
  if (!cmd || !*cmd)
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "No command passed",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename ());
      return NULL;
    }

  to_stdout = get_int_var_by_name (lexic, "stdout", -1);
  to_stderr = get_int_var_by_name (lexic, "stderr", -1);
  compat_mode = 0;
  if (to_stdout == -1 && to_stderr == -1)
    {
      /* None of the two named args are given.  */
      to_stdout = 1;
    }
  else if (to_stdout == 0 && to_stderr == 0)
    {
      /* Compatibility mode.  */
      to_stdout = 1;
      compat_mode = 1;
    }

  if (to_stdout < 0)
    to_stdout = 0;
  if (to_stderr < 0)
    to_stderr = 0;

  /* Allocate some space in advance.  Most commands won't output too
     much and thus 512 bytes (6 standard terminal lines) should often
     be sufficient.  */
  response = g_string_sized_new (512);
  if (compat_mode)
    {
      compat_buf = g_string_sized_new (512);
      compat_buf_inuse = 1;
    }
  else
    compat_buf_inuse = 0;

  rc = exec_ssh_cmd (session, cmd, verbose, compat_mode, to_stdout, to_stderr,
                     response, compat_buf);
  if (rc == SSH_ERROR)
    {
      if (compat_buf_inuse)
        g_string_free (compat_buf, TRUE);
      g_string_free (response, TRUE);
      return NULL;
    }

  /* Append the compatibility buffer to the output.  */
  if (compat_buf_inuse)
    {
      len = compat_buf->len;
      p = g_string_free (compat_buf, FALSE);
      if (p)
        {
          g_string_append_len (response, p, len);
          g_free (p);
        }
    }

  /* Return the the output.  */
  len = response->len;
  p = g_string_free (response, FALSE);
  if (!p)
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "memory problem: %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (), strerror (-1));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = p;
  return retc;
}

/**
 * @brief Get the issue banner
 * @naslfn{ssh_get_issue_banner}
 *
 * The function returns a string with the issue banner.  This is
 * usually displayed before authentication.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         server did not send a banner or that the connection has not
 *         yet been established.
 */
tree_cell *
nasl_ssh_get_issue_banner (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  char *banner;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_issue_banner", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  /* We need to make sure that we got the auth methods so that libssh
     has the banner.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;
  if (!session_table[tbl_slot].authmethods_valid)
    get_authmethods (tbl_slot);

  banner = ssh_get_issue_banner (session);
  if (!banner)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_strdup (banner);
  retc->size = strlen (banner);
  ssh_string_free_char (banner);
  return retc;
}

/**
 * @brief Get the server banner
 * @naslfn{ssh_get_server_banner}
 *
 * The function returns a string with the server banner.  This is
 * usually the first data sent by the server.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_server_banner (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  const char *banner;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_server_banner", &tbl_slot,
                          lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  banner = ssh_get_serverbanner (session);
  if (!banner)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_strdup (banner);
  retc->size = strlen (banner);
  return retc;
}

/**
 * @brief Get the host key
 * @naslfn{ssh_get_host_key}
 *
 * The function returns a string with the MD5 host key. *
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_host_key (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  ssh_string sstring;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_host_key", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  sstring = ssh_get_pubkey (session);
  if (!sstring)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = ssh_string_to_char (sstring);
  retc->size = ssh_string_len (sstring);
  ssh_string_free (sstring);
  return retc;
}

/**
 * @brief Get the list of authmethods
 * @naslfn{ssh_get_auth_methods}
 *
 * The function returns a string with comma separated authentication
 * methods.  This is basically the same as returned by
 * SSH_MSG_USERAUTH_FAILURE protocol element; however, it has been
 * screened and put into a definitive order.
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret A string on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_auth_methods (lex_ctxt *lexic)
{
  int tbl_slot, methods, session_id;
  GString *buffer;
  char *p;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_auth_methods", &tbl_slot, lexic))
    return NULL;

  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;
  if (!session_table[tbl_slot].authmethods_valid)
    get_authmethods (tbl_slot);

  methods = session_table[tbl_slot].authmethods;

  buffer = g_string_sized_new (128);
  if ((methods & SSH_AUTH_METHOD_NONE))
    g_string_comma_str (buffer, "none");
  if ((methods & SSH_AUTH_METHOD_PASSWORD))
    g_string_comma_str (buffer, "password");
  if ((methods & SSH_AUTH_METHOD_PUBLICKEY))
    g_string_comma_str (buffer, "publickey");
  if ((methods & SSH_AUTH_METHOD_HOSTBASED))
    g_string_comma_str (buffer, "hostbased");
  if ((methods & SSH_AUTH_METHOD_INTERACTIVE))
    g_string_comma_str (buffer, "keyboard-interactive");
  g_string_append_c (buffer, 0x00);
  p = g_string_free (buffer, FALSE);
  if (!p)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = p;
  retc->size = strlen (p);
  return retc;
}

static void
request_ssh_shell_alarm (int signal)
{
  (void) signal;
  g_message ("request_ssh_shell: Timeout");
}

/**
 * @brief Open a shell on an ssh channel.
 *
 * @param[in]   channel     SSH Channel.
 * @param[in]   pty         1 interactive shell, 0 non-intercative shell
 *
 * @return 0 if success, -1 if error.
 */
static int
request_ssh_shell (ssh_channel channel, int pty)
{
  assert (channel);

  /* Work-around for LibSSH calling poll() with an infinite timeout. */
  signal (SIGALRM, request_ssh_shell_alarm);
  alarm (30);

  if (pty == 1)
    {
      if (ssh_channel_request_pty (channel))
        return -1;

      if (ssh_channel_change_pty_size (channel, 80, 24))
        return -1;
    }
  if (ssh_channel_request_shell (channel))
    return -1;

  alarm (0);
  signal (SIGALRM, _exit);

  return 0;
}

/**
 * @brief Request an ssh shell.
 * @naslfn{ssh_shell_open}
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a pty To enable/disable the interactive shell. Default is 1 (interactive).
 *
 * @naslret An int on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Session ID on success, NULL on failure.
 */
tree_cell *
nasl_ssh_shell_open (lex_ctxt *lexic)
{
  int tbl_slot, session_id, pty;
  ssh_channel channel;
  ssh_session session;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  pty = get_int_var_by_name (lexic, "pty", 1);

  if (!verify_session_id (session_id, "ssh_shell_open", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;
  channel = ssh_channel_new (session);
  if (!channel)
    return NULL;
  if (ssh_channel_open_session (channel))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "ssh_channel_open_session: %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (),
                 ssh_get_error (session));
      ssh_channel_free (channel);
      return NULL;
    }

  if (request_ssh_shell (channel, pty))
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "request_ssh_shell: %s",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename (),
                 ssh_get_error (session));
      ssh_channel_free (channel);
      return NULL;
    }
  if (session_table[tbl_slot].channel)
    ssh_channel_free (session_table[tbl_slot].channel);
  session_table[tbl_slot].channel = channel;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}

/**
 * @brief read from an ssh channel until timeouts or there is no bytes left to
 * read.
 *
 * @param[in]   channel     SSH Channel.
 * @param[out]  response    Buffer to store response in.
 * @param[in]   timeout     Timeout in milliseconds.
 *
 * @return 0 if success, -1 if error.
 */
static int
read_ssh_blocking (ssh_channel channel, GString *response, int timeout)
{
  int rc;
  char buffer[4096];

  /* Read stderr */
  do
    {
      if ((rc = ssh_channel_read_timeout (channel, buffer, sizeof (buffer), 1,
                                          timeout))
          > 0)
        g_string_append_len (response, buffer, rc);

      else if (rc == SSH_ERROR)
        goto exec_err;
    }
  while (rc > 0 || rc == SSH_AGAIN);

  /* Read stdout */
  do
    {
      if ((rc = ssh_channel_read_timeout (channel, buffer, sizeof (buffer), 0,
                                          timeout))
          > 0)
        g_string_append_len (response, buffer, rc);

      else if (rc == SSH_ERROR)
        goto exec_err;
    }
  while (rc > 0 || rc == SSH_AGAIN);
  rc = SSH_OK;

exec_err:
  return rc;
}

/**
 * @brief read from an ssh channel without blocking.
 *
 * @param[in]   channel     SSH Channel.
 * @param[out]  response    Buffer to store response in.
 *
 * @return 0 if success, -1 if error.
 */
static int
read_ssh_nonblocking (ssh_channel channel, GString *response)
{
  int rc;
  char buffer[4096];

  if (!ssh_channel_is_open (channel) || ssh_channel_is_eof (channel))
    return -1;

  if ((rc = ssh_channel_read_nonblocking (channel, buffer, sizeof (buffer), 1))
      > 0)
    g_string_append_len (response, buffer, rc);
  if (rc == SSH_ERROR)
    return -1;
  if ((rc = ssh_channel_read_nonblocking (channel, buffer, sizeof (buffer), 0))
      > 0)
    g_string_append_len (response, buffer, rc);
  if (rc == SSH_ERROR)
    return -1;
  return 0;
}

/**
 * @brief Read the output of an ssh shell.
 * @naslfn{ssh_shell_read}
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslparam timeout
 *
 * - Enable the blocking ssh read until it gives the timeout or there is no
 * bytes left to read.
 *
 * @naslret A string on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Data read from shell on success, NULL on failure.
 */
tree_cell *
nasl_ssh_shell_read (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_channel channel;
  tree_cell *retc;
  GString *response;
  int timeout;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_read", &tbl_slot, lexic))
    return NULL;
  channel = session_table[tbl_slot].channel;

  response = g_string_new (NULL);

  timeout = get_int_var_by_name (lexic, "timeout", 0);

  if (timeout > 0)
    {
      if (read_ssh_blocking (channel, response, timeout))
        return NULL;
    }
  else
    {
      if (read_ssh_nonblocking (channel, response))
        return NULL;
    }
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = response->len;
  retc->x.str_val = g_string_free (response, FALSE);
  return retc;
}

/**
 * @brief Write string to ssh shell.
 * @naslfn{ssh_shell_write}
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslnparam
 *
 * - @a cmd A string to write to shell.
 *
 * @naslret An integer: 0 on success, -1 on failure.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return 0 on success, -1 on failure.
 */
tree_cell *
nasl_ssh_shell_write (lex_ctxt *lexic)
{
  int tbl_slot, rc = -1, len, session_id;
  ssh_channel channel;
  tree_cell *retc;
  char *cmd;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_write", &tbl_slot, lexic))
    goto write_ret;
  if (!(channel = session_table[tbl_slot].channel))
    {
      g_message ("ssh_shell_write: No shell channel found");
      goto write_ret;
    }

  cmd = get_str_var_by_name (lexic, "cmd");
  if (!cmd || !*cmd)
    {
      g_message ("Function %s (calling internal function %s) called from %s: "
                 "No command passed",
                 nasl_get_function_name () ? nasl_get_function_name ()
                                           : "script_main_function",
                 __func__, nasl_get_plugin_filename ());
      goto write_ret;
    }
  len = strlen (cmd);
  if (ssh_channel_write (channel, cmd, len) != len)
    {
      g_message (
        "Function %s (calling internal function %s) called from %s: %s",
        nasl_get_function_name () ? nasl_get_function_name ()
                                  : "script_main_function",
        __func__, nasl_get_plugin_filename (),
        ssh_get_error (session_table[tbl_slot].session));
      goto write_ret;
    }
  rc = 0;

write_ret:
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = rc;
  return retc;
}

/**
 * @brief Close an ssh shell.
 * @naslfn{ssh_shell_close}
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_ssh_shell_close (lex_ctxt *lexic)
{
  int tbl_slot, session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_close", &tbl_slot, lexic))
    return NULL;
  if (session_table[tbl_slot].channel)
    {
      ssh_channel_free (session_table[tbl_slot].channel);
      session_table[tbl_slot].channel = NULL;
    }

  return NULL;
}

/*
 * NASL SFTP
 */

/**
 * @brief Check if the SFTP subsystem is enabled on the remote SSH server.
 * @naslfn{sftp_enabled_check}
 *
 * @nasluparam
 *
 * - An SSH session id.
 *
 * @naslret An integer: 0 on success, -1 (SSH_ERROR) on Channel request
 * subsystem failure. Greater than 0 means an error during SFTP init. NULL
 * indicates a failure during session id verification.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_sftp_enabled_check (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  tree_cell *retc;
  sftp_session sftp;
  ssh_session session;
  int rc, verbose = 0;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "sftp_enabled_check", &tbl_slot, lexic))
    return NULL;

  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  sftp = sftp_new (session);
  if (sftp == NULL)
    {
      if (verbose)
        g_message (
          "Function %s (calling internal function %s) called from %s: %s",
          nasl_get_function_name () ? nasl_get_function_name ()
                                    : "script_main_function",
          __func__, nasl_get_plugin_filename (),
          ssh_get_error (session_table[tbl_slot].session));
      rc = SSH_ERROR;
      goto write_ret;
    }

  rc = sftp_init (sftp);
  if (rc != SSH_OK)
    {
      if (verbose)
        {
          g_message ("Function %s (calling internal function %s) called from "
                     "%s: %s. Code %d",
                     nasl_get_function_name () ? nasl_get_function_name ()
                                               : "script_main_function",
                     __func__, nasl_get_plugin_filename (),
                     ssh_get_error (session_table[tbl_slot].session),
                     sftp_get_error (sftp));
        }
    }
  sftp_free (sftp);

write_ret:

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = rc;
  return retc;
}

/*
 * NASL NETCONF
 */
/**
 * @brief Excecute the NETCONF subsystem on the the ssh channel
 *
 * @naslfn{ssh_execute_netconf_subsystem}
 * @nasluparam
 * - An SSH session id.
 * @naslret An int on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 * @return Session ID on success, NULL on failure.
 */
tree_cell *
nasl_ssh_execute_netconf_subsystem (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_channel channel;
  ssh_session session;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);

  if (!verify_session_id (session_id, "ssh_execute_netconf_subsystem",
                          &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;
  channel = ssh_channel_new (session);
  if (!channel)
    return NULL;

  if (ssh_channel_open_session (channel))
    {
      /* FIXME: Handle SSH_AGAIN.  */
      g_message ("ssh_channel_open_session failed: %s",
                 ssh_get_error (session));
      ssh_channel_free (channel);
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = SSH_ERROR;
      return retc;
    }

  int err;
  if ((err = ssh_channel_request_subsystem (channel, "netconf")) < 0)
    {
      g_message ("%s Could not execute netconf subsystem", __func__);
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = err;
      return retc;
    }

  if (session_table[tbl_slot].channel)
    ssh_channel_free (session_table[tbl_slot].channel);
  session_table[tbl_slot].channel = channel;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}
