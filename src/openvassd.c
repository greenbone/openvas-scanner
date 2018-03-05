/* OpenVAS
* $Id$
* Description: Runs the OpenVAS-scanner.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
* as published by the Free Software Foundation
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
 * @mainpage
 *
 * @section Introduction
 * @verbinclude README
 *
 * @section license License Information
 * @verbinclude COPYING
 */

/**
 * @file
 * OpenVAS Scanner main module, runs the scanner.
 */

#include <stdlib.h>    /* for atoi() */
#include <unistd.h>    /* for close() */
#include <errno.h>     /* for errno() */
#include <fcntl.h>     /* for open() */
#include <signal.h>    /* for SIGTERM */
#include <netdb.h>     /* for addrinfo */
#include <sys/wait.h>     /* for waitpid */
#include <sys/un.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#include <openvas/misc/openvas_proctitle.h> /* for proctitle_set */
#include <openvas/misc/openvas_logging.h>  /* for setup_legacy_log_handler */
#include <openvas/base/pidfile.h>    /* for pidfile_create */
#include <openvas/base/nvticache.h> /* nvticache_free */
#include <openvas/base/kb.h>         /* for KB_PATH_DEFAULT */
#include <openvas/base/gpgme_util.h>
#include <openvas/misc/prefs.h>      /* for prefs_get() */
#include <openvas/misc/vendorversion.h>      /* for prefs_get() */

#include <gcrypt.h> /* for gcry_control */

#include "comm.h"         /* for comm_loading */
#include "attack.h"       /* for attack_network */
#include "sighand.h"      /* for openvas_signal */
#include "log.h"          /* for log_write */
#include "processes.h"    /* for create_process */
#include "ntp.h"          /* for ntp_timestamp_scan_starts */
#include "utils.h"        /* for wait_for_children1 */
#include "pluginlaunch.h" /* for init_loading_shm */

#if GNUTLS_VERSION_NUMBER < 0x030300
#include <openvas/misc/network.h>     /* openvas_SSL_init */
#endif

#ifdef SVN_REV_AVAILABLE
#include "svnrevision.h"
#endif

/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

static int global_iana_socket = -1;

static volatile int loading_stop_signal = 0;
static volatile int reload_signal = 0;
static volatile int termination_signal = 0;

typedef struct
{
  char *option;
  char *value;
} openvassd_option;

/**
 * @brief Default values for scanner options. Must be NULL terminated.
 */
static openvassd_option openvassd_defaults[] = {
  {"plugins_folder", OPENVAS_NVT_DIR},
  {"cache_folder", OPENVAS_CACHE_DIR},
  {"include_folders", OPENVAS_NVT_DIR},
  {"max_hosts", "30"},
  {"max_checks", "10"},
  {"be_nice", "no"},
  {"logfile", OPENVASSD_MESSAGES},
  {"log_whole_attack", "no"},
  {"log_plugins_name_at_load", "no"},
  {"dumpfile", OPENVASSD_DEBUGMSG},
  {"cgi_path", "/cgi-bin:/scripts"},
  {"optimize_test", "yes"},
  {"checks_read_timeout", "5"},
  {"network_scan", "no"},
  {"non_simult_ports", "139, 445"},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"scanner_plugins_timeout", G_STRINGIFY (SCANNER_NVT_TIMEOUT)},
  {"safe_checks", "yes"},
  {"auto_enable_dependencies", "yes"},
  {"use_mac_addr", "no"},
  {"nasl_no_signature_check", "yes"},
  {"drop_privileges", "no"},
  {"unscanned_closed", "yes"},
  {"unscanned_closed_udp", "yes"},
  // Empty options must be "\0", not NULL, to match the behavior of
  {"vhosts", "\0"},
  {"vhosts_ip", "\0"},
  {"report_host_details", "yes"},
  {"kb_location", KB_PATH_DEFAULT},
  {"timeout_retry", "3"},
  {NULL, NULL}
};

gchar *unix_socket_path = NULL;

static void
start_daemon_mode (void)
{
  const char *s;
  int fd;

  /* do not block the listener port for subsequent scanners */
  close (global_iana_socket);

  /* become process group leader */
  if (setsid () < 0)
    {
      log_write ("Warning: Cannot set process group leader (%s)",
                 strerror (errno));
    }

  if ((fd = open ("/dev/tty", O_RDWR)) >= 0)
    close (fd);

  /* no input, anymore: provide an empty-file substitute */
  if ((fd = open ("/dev/null", O_RDONLY)) < 0)
    {
      log_write ("Cannot open /dev/null (%s) -- aborting", strerror (errno));
      exit (0);
    }

  dup2 (fd, 0);
  close (fd);

  /* provide a dump file to collect stdout and stderr */
  if ((s = prefs_get ("dumpfile")) == 0)
    s = OPENVASSD_DEBUGMSG;
  /* setting "-" denotes terminal mode */
  if (strcmp (s, "-") == 0)
    return;

  fflush (stdout);
  fflush (stderr);

  if ((fd = open (s, O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0)
    {
      log_write ("Cannot create a new dumpfile %s (%s)-- aborting", s,
                 strerror (errno));
      exit (2);
    }

  dup2 (fd, 1);
  dup2 (fd, 2);
  close (fd);
  setlinebuf (stdout);
  setlinebuf (stderr);
}


static void
end_daemon_mode (void)
{
  /* clean up all processes the process group */
  make_em_die (SIGTERM);
}

static void
set_globals_from_preferences (void)
{
  const char *str;

  if ((str = prefs_get ("max_hosts")) != NULL)
    {
      global_max_hosts = atoi (str);
      if (global_max_hosts <= 0)
        global_max_hosts = 15;
    }

  if ((str = prefs_get ("max_checks")) != NULL)
    {
      global_max_checks = atoi (str);
      if (global_max_checks <= 0)
        global_max_checks = 10;
    }
}

static void
handle_reload_signal (int sig)
{
  reload_signal = sig;
}

static void
handle_termination_signal (int sig)
{
  termination_signal = sig;
}

/*
 * @brief Handles a client request when the scanner is still loading.
 *
 * @param[in]   soc Client socket to send and receive from.
 */
static void
loading_client_handle (int soc)
{
  int opt = 1;
  if (soc <= 0)
    return;

  setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt));
  comm_loading (soc);
  shutdown (soc, 2);
  close (soc);
}

/*
 * @brief Handles term signal received by loading handler child process.
 */
static void
handle_loading_stop_signal (int sig)
{
  loading_stop_signal = sig;
}

static void
remove_pidfile ()
{
  pidfile_remove ("openvassd");
}

/*
 * @brief Starts a process to handle client requests while the scanner is
 * loading.
 *
 * @return process id of loading handler.
 */
static pid_t
loading_handler_start ()
{
  pid_t child_pid, parent_pid;
  int opts;

  init_loading_shm ();
  parent_pid = getpid ();
  child_pid = fork ();
  if (child_pid != 0)
    return child_pid;

  proctitle_set ("openvassd (Loading Handler)");
  openvas_signal (SIGTERM, handle_loading_stop_signal);
  if ((opts = fcntl (global_iana_socket, F_GETFL, 0)) < 0)
    {
      log_write ("fcntl: %s", strerror (errno));
      exit (0);
    }

  if (fcntl (global_iana_socket, F_SETFL, opts | O_NONBLOCK) < 0)
    {
      log_write ("fcntl: %s", strerror (errno));
      exit (0);
    }

  /*
   * Forked process will handle client requests until parent dies or stops it
   * with loading_handler_stop ().
   */
  while (1)
    {
      unsigned int lg_address;
      struct sockaddr_un address;
      int soc;

      if (loading_stop_signal || kill (parent_pid, 0) < 0)
        break;
      lg_address = sizeof (struct sockaddr_un);
      soc = accept (global_iana_socket, (struct sockaddr *) (&address),
                    &lg_address);
      loading_client_handle (soc);
      sleep (1);
    }
  if (fcntl (global_iana_socket, F_SETFL, opts) < 0)
    log_write ("fcntl: %s", strerror (errno));

  exit (0);
}

/*
 * @brief Stops the loading handler process.
 *
 * @param[in]   handler_pid Pid of loading handler.
 */
void
loading_handler_stop (pid_t handler_pid)
{
  terminate_process (handler_pid);
  destroy_loading_shm ();
}

/**
 * @brief Initializes main scanner process' signal handlers.
 */
static void
init_signal_handlers ()
{
  openvas_signal (SIGTERM, handle_termination_signal);
  openvas_signal (SIGINT, handle_termination_signal);
  openvas_signal (SIGQUIT, handle_termination_signal);
  openvas_signal (SIGHUP, handle_reload_signal);
  openvas_signal (SIGCHLD, sighand_chld);
}

/* Restarts the scanner by reloading the configuration. */
static void
reload_openvassd ()
{
  const char *config_file;
  pid_t handler_pid;
  int i, ret;

  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);

  /* Reinitialize logging before writing to it. */
  log_init (prefs_get ("logfile"));
  log_write ("Reloading the scanner.");

  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return;
  /* Reload config file. */
  config_file = prefs_get ("config_file");
  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  /* Reload the plugins */
  ret = plugins_init ();
  set_globals_from_preferences ();
  loading_handler_stop (handler_pid);

  log_write ("Finished reloading the scanner.");
  reload_signal = 0;
  openvas_signal (SIGHUP, handle_reload_signal);
  if (ret)
    exit (1);
}

static void
handle_client (struct arglist *globals)
{
  kb_t net_kb = NULL;
  int soc = arg_get_value_int (globals, "global_socket");

  /* Become process group leader and the like ... */
  start_daemon_mode ();
  if (comm_wait_order (globals))
    return;
  ntp_timestamp_scan_starts (soc);
  attack_network (globals, &net_kb);
  if (net_kb != NULL)
    {
      kb_delete (net_kb);
      net_kb = NULL;
    }
  ntp_timestamp_scan_ends (soc);
  comm_terminate (soc);
}

static void
scanner_thread (struct arglist *globals)
{
  int opt = 1, soc;

  nvticache_reset ();
  soc = arg_get_value_int (globals, "global_socket");
  proctitle_set ("openvassd: Serving %s", unix_socket_path);

  /* Everyone runs with a nicelevel of 10 */
  if (prefs_get_bool ("be_nice"))
    {
      errno = 0;
      if (nice(10) == -1 && errno != 0)
        {
          log_write ("Unable to renice process: %d", errno);
        }
    }

  /* Close the scanner thread - it is useless for us now */
  close (global_iana_socket);

  if (soc < 0)
    goto shutdown_and_exit;

  setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt));
  /* arg_set_value *replaces* an existing value, but it shouldn't fail here */
  arg_add_value (globals, "parent_socket", ARG_INT, GSIZE_TO_POINTER (soc));
  arg_set_value (globals, "global_socket", GSIZE_TO_POINTER (soc));

  if (comm_init (soc) < 0)
    exit (0);
  handle_client (globals);

shutdown_and_exit:
  shutdown (soc, 2);
  close (soc);

  /* Kill left overs */
  end_daemon_mode ();
  exit (0);
}

/*
 * @brief Terminates the scanner if a termination signal was received.
 */
static void
check_termination ()
{
  if (termination_signal)
    {
      log_write ("Received the %s signal", strsignal (termination_signal));
      remove_pidfile ();
      make_em_die (SIGTERM);
      log_close ();
      _exit (0);
    }
}

/*
 * @brief Reloads the scanner if a reload was requested.
 */
static void
check_reload ()
{
  if (reload_signal)
    {
      proctitle_set ("openvassd: Reloading");
      reload_openvassd ();
      proctitle_set ("openvassd: Waiting for incoming connections");
    }
}


/**
 * @brief Get the pid and ppid from /proc to find the running scan pids.
 *        Send SIGUSR2 kill signal to all running scans to stop them.
 */
static void
stop_all_scans (void)
{
  int i, ispid;
  GDir *proc = NULL;
  const gchar *piddir = NULL;
  gchar *pidstatfn = NULL;
  gchar **contents_split = NULL;
  gchar *contents = NULL;
  GError *error = NULL;
  gchar *parentID = NULL;
  gchar *processID = NULL;

  proc = g_dir_open ("/proc", 0, &error);
  if (error != NULL)
  {
    log_write ("Unable to open directory: %s\n", error->message);
    g_error_free (error);
    return;
  }
  while ((piddir = g_dir_read_name (proc)) != NULL)
    {
      ispid = 1;
      for (i = 0; i < (int)strlen (piddir); i++)
        if (!g_ascii_isdigit (piddir[i]))
          {
            ispid = 0;
            break;
          }
      if (!ispid)
        continue;

      pidstatfn = g_strconcat ("/proc/", piddir, "/stat", NULL);
      if (g_file_get_contents (pidstatfn, &contents, NULL, NULL))
        {
          contents_split = g_strsplit (contents," ", 6);
          parentID = g_strdup (contents_split[3]);
          processID = g_strdup (contents_split[0]);

          g_free (pidstatfn);
          pidstatfn = NULL;
          g_free (contents);
          contents  = NULL;
          g_strfreev (contents_split);
          contents_split  = NULL;

          if (atoi(parentID) == (int)getpid())
            {
              log_write ("Stopping running scan with PID: %s", processID);
              kill (atoi(processID), SIGUSR2);
            }
          g_free (parentID);
          parentID = NULL;
          g_free (processID);
          processID = NULL;
        }
      else
        {
          g_free (pidstatfn);
          pidstatfn = NULL;
          continue;
        }
    }

  if (proc)
    g_dir_close (proc);
}

/**
 * @brief Check if Redis Server is up and if the KB exists. If KB does not
 * exist,force a reload and stop all the running scans.
 */
void
check_kb_status ()
{
  int  waitredis = 5, waitkb = 5, ret = 0;
  kb_t kb_access_aux;

  while (waitredis != 0)
    {
      ret = kb_new (&kb_access_aux, prefs_get ("kb_location"));
      if (ret)
        {
          log_write ("Redis connection lost. Trying to reconnect.");
          waitredis--;
          sleep (5);
          continue;
        }
      else
        {
          kb_delete (kb_access_aux);
          break;
        }
    }

  if (waitredis == 0)
    {
      log_write ("Critical Redis connection error.");
      exit (1);
    }

  while (waitkb != 0)
    {
      kb_access_aux = kb_find (prefs_get ("kb_location"), "nvticache");
      if (!kb_access_aux)
        {
          log_write ("Redis kb not found. Trying again in 2 seconds.");
          waitkb--;
          sleep (2);
          continue;
        }
      else
        {
          kb_lnk_reset (kb_access_aux);
          g_free (kb_access_aux);
          break;
        }
    }

  if (waitredis != 5 || waitkb == 0)
    {
      log_write ("Redis connection error. Stopping all the running scans.");
      stop_all_scans ();
      reload_openvassd ();
    }
}

static void
main_loop ()
{
#ifdef OPENVASSD_SVN_REVISION
  log_write ("openvassd %s (SVN revision %i) started",
             OPENVASSD_VERSION,
             OPENVASSD_SVN_REVISION);
#else
  log_write ("openvassd %s started", OPENVASSD_VERSION);
#endif
  proctitle_set ("openvassd: Waiting for incoming connections");
  for (;;)
    {
      int soc, opts;
      unsigned int lg_address;
      struct sockaddr_un address;
      struct arglist *globals;
      fd_set set;
      struct timeval timeout;
      int rv;

      check_termination ();
      check_reload ();
      check_kb_status ();
      wait_for_children1 ();
      lg_address = sizeof (struct sockaddr_un);

      /* Setting the socket to non-blocking and the use of select() for
       * listen() before accept() is done only for openvas-9. It allows to
       * go through the loop every 0.5sec without stuck in the accept() call.
       * In the trunk version the manager ask the the scanner for new NVTs
       * every 10sec, so the loop is not stuck in accept().
       */
      if ((opts = fcntl (global_iana_socket, F_GETFL, 0)) < 0)
        {
          log_write ("fcntl: %s", strerror (errno));
          exit (0);
        }
      if (fcntl (global_iana_socket, F_SETFL, opts | O_NONBLOCK) < 0)
        {
          log_write ("fcntl: %s", strerror (errno));
          exit (0);
        }

      if (listen (global_iana_socket, 5) < 0)
        continue;

      FD_ZERO(&set);
      FD_SET(global_iana_socket, &set);

      timeout.tv_sec = 0;
      timeout.tv_usec = 500000;

      rv = select(global_iana_socket + 1, &set, NULL, NULL, &timeout);
      if(rv == -1) /* Select error. */
        continue;
      else if(rv == 0) /* Timeout. */
        continue;
      else
        soc = accept (global_iana_socket, (struct sockaddr *) (&address),
                    &lg_address);
      if (soc == -1)
        continue;

      /* Set the socket to blocking again. */
      if (fcntl (global_iana_socket, F_SETFL, opts) < 0)
        log_write ("fcntl: %s", strerror (errno));

      globals = g_malloc0 (sizeof (struct arglist));
      arg_add_value (globals, "global_socket", ARG_INT, GSIZE_TO_POINTER (soc));

      /* we do not want to create an io thread, yet so the last argument is -1 */
      if (create_process ((process_func_t) scanner_thread, globals) < 0)
        {
          log_write ("Could not fork - client won't be served");
          sleep (2);
        }
      close (soc);
      arg_free (globals);
    }
}

/**
 * Initialization of the network in unix socket case:
 * we setup the socket that will listen for incoming connections on
 * unix_socket_path.
 *
 * @param[out] sock Socket to be initialized.
 * @param unix_socket_path Path to unix socket to listen on.
 *
 * @return 0 on success. -1 on failure.
 */
static int
init_unix_network (int *sock, const char *owner, const char *group,
                   const char *mode)
{
  struct sockaddr_un addr;
  struct stat ustat;
  int unix_socket;
  mode_t omode;

  unix_socket = socket (AF_UNIX, SOCK_STREAM, 0);
  if (unix_socket == -1)
    {
      log_write ("%s: Couldn't create UNIX socket", __FUNCTION__);
      return -1;
    }
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, unix_socket_path, sizeof (addr.sun_path));
  if (!stat (addr.sun_path, &ustat))
    {
      /* Remove socket so we can bind(). */
      unlink (addr.sun_path);
    }
  if (bind (unix_socket, (struct sockaddr *) &addr, sizeof (struct sockaddr_un))
      == -1)
    {
      log_write ("%s: Error on bind(%s): %s", __FUNCTION__,
                 unix_socket_path, strerror (errno));
      return -1;
    }

  if (owner)
    {
      struct passwd *pwd = getpwnam (owner);
      if (!pwd)
        {
          log_write ("%s: User %s not found.", __FUNCTION__, owner);
          return -1;
        }
      if (chown (unix_socket_path, pwd->pw_uid, -1) == -1)
        {
          log_write ("%s: chown: %s", __FUNCTION__, strerror (errno));
          return -1;
        }
    }

  if (group)
    {
      struct group *grp = getgrnam (group);
      if (!grp)
        {
          log_write ("%s: Group %s not found.", __FUNCTION__, group);
          return -1;
        }
      if (chown (unix_socket_path, -1, grp->gr_gid) == -1)
        {
          log_write ("%s: chown: %s", __FUNCTION__, strerror (errno));
          return -1;
        }
    }

  if (!mode)
    mode = "660";
 omode = strtol (mode, 0, 8);
 if (omode <= 0 || omode > 4095)
   {
     log_write ("%s: Erroneous liste-mode value", __FUNCTION__);
     return -1;
   }
 if (chmod (unix_socket_path, strtol (mode, 0, 8)) == -1)
   {
     log_write ("%s: chmod: %s", __FUNCTION__, strerror (errno));
     return -1;
   }

  if (listen (unix_socket, 128) == -1)
    {
      log_write ("%s: Error on listen(): %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  *sock = unix_socket;
  return 0;
}

/**
 * @brief Initialize everything.
 *
 * @param stop_early 0: do some initialization, 1: no initialization.
 */
static int
init_openvassd (int dont_fork, const char *config_file)
{
  int i;

  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  log_init (prefs_get ("logfile"));
  if (dont_fork == FALSE)
    setup_legacy_log_handler (log_vwrite);

  set_globals_from_preferences ();

  return 0;
}

static void
set_daemon_mode ()
{
  /* Close stdin, stdout and stderr */
  int i = open ("/dev/null", O_RDONLY, 0640);
  if (dup2 (i, STDIN_FILENO) != STDIN_FILENO)
    log_write ("Could not redirect stdin to /dev/null: %s\n", strerror (errno));
  if (dup2 (i, STDOUT_FILENO) != STDOUT_FILENO)
    log_write ("Could not redirect stdout to /dev/null: %s\n",
               strerror (errno));
  if (dup2 (i, STDERR_FILENO) != STDERR_FILENO)
    log_write ("Could not redirect stderr to /dev/null: %s\n",
               strerror (errno));
  close (i);
  if (fork ())
    exit (0);
  setsid ();
}

static int
flush_all_kbs ()
{
  kb_t kb;
  int rc;

  rc = kb_new (&kb, prefs_get ("kb_location"));
  if (rc)
    return rc;

  rc = kb_flush (kb, "nvticache");
  return rc;
}

static void
gcrypt_init ()
{
  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P))
    return;
  gcry_check_version (NULL);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED);
}

/**
 * @brief openvassd.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
int
main (int argc, char *argv[])
{
  int ret;
  pid_t handler_pid;

  proctitle_init (argc, argv);
  gcrypt_init ();

  static gboolean display_version = FALSE;
  static gboolean dont_fork = FALSE;
  static gchar *config_file = NULL;
  static gchar *vendor_version_string = NULL;
  static gchar *listen_owner = NULL;
  static gchar *listen_group = NULL;
  static gchar *listen_mode = NULL;
  static gchar *gnupg_dir = NULL;
  static gboolean print_specs = FALSE;
  static gboolean print_sysconfdir = FALSE;
  static gboolean only_cache = FALSE;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"foreground", 'f', 0, G_OPTION_ARG_NONE, &dont_fork,
     "Do not run in daemon mode but stay in foreground", NULL},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"vendor-version", '\0', 0, G_OPTION_ARG_STRING, &vendor_version_string,
     "Use <string> as vendor version.", "<string>"},
    {"cfg-specs", 's', 0, G_OPTION_ARG_NONE, &print_specs,
     "Print configuration settings", NULL},
    {"sysconfdir", 'y', 0, G_OPTION_ARG_NONE, &print_sysconfdir,
     "Print system configuration directory (set at compile time)", NULL},
    {"only-cache", 'C', 0, G_OPTION_ARG_NONE, &only_cache,
     "Exit once the NVT cache has been initialized or updated", NULL},
    {"unix-socket", 'c', 0, G_OPTION_ARG_FILENAME, &unix_socket_path,
     "Path of unix socket to listen on", "<filename>"},
    {"listen-owner", '\0', 0, G_OPTION_ARG_STRING, &listen_owner,
     "Owner of the unix socket", "<string>"},
    {"listen-group", '\0', 0, G_OPTION_ARG_STRING, &listen_group,
     "Group of the unix socket", "<string>"},
    {"listen-mode", '\0', 0, G_OPTION_ARG_STRING, &listen_mode,
     "File mode of the unix socket", "<string>"},
    {"gnupg-home", 'c', 0, G_OPTION_ARG_STRING, &gnupg_dir,
     "Gnupg home directory", "<directory>"},
    {NULL, 0, 0, 0, NULL, NULL, NULL}
  };

  option_context =
    g_option_context_new ("- Scanner of the Open Vulnerability Assessment System");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      exit (0);
    }
  g_option_context_free (option_context);

  if (print_sysconfdir)
    {
      g_print ("%s\n", SYSCONFDIR);
      exit (0);
    }

  /* Switch to UTC so that OTP times are always in UTC. */
  if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_print ("%s\n\n", strerror (errno));
      exit (0);
    }
  tzset ();

  if (!unix_socket_path)
    unix_socket_path = g_build_filename (OPENVAS_RUN_DIR, "openvassd.sock", NULL);

  if (display_version)
    {
      printf ("OpenVAS Scanner %s\n", OPENVASSD_VERSION);
#ifdef OPENVASSD_SVN_REVISION
      printf ("SVN revision %i\n", OPENVASSD_SVN_REVISION);
#endif
      printf
        ("Most new code since 2005: (C) 2016 Greenbone Networks GmbH\n");
      printf
        ("Nessus origin: (C) 2004 Renaud Deraison <deraison@nessus.org>\n");
      printf ("License GPLv2: GNU GPL version 2\n");
      printf
        ("This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n\n");
      exit (0);
    }

  if (gnupg_dir)
    set_gpghome (gnupg_dir);

  if (vendor_version_string)
    vendor_version_set (vendor_version_string);

  if (!config_file)
    config_file = OPENVASSD_CONF;
  if (only_cache)
    {
      if (init_openvassd (dont_fork, config_file))
        return 1;
      if (plugins_init ())
        return 1;
      return 0;
    }

  if (init_openvassd (dont_fork, config_file))
    return 1;
  if (!print_specs)
    {
      if (init_unix_network (&global_iana_socket, listen_owner, listen_group,
                             listen_mode))
        return 1;
    }

  /* special treatment */
  if (print_specs)
    {
      prefs_dump ();
      exit (0);
    }
  flush_all_kbs ();

#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    log_write ("Could not initialize openvas SSL!");
#endif

  // Daemon mode:
  if (dont_fork == FALSE)
    set_daemon_mode ();
  pidfile_create ("openvassd");

  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);
  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return 1;
  ret = plugins_init ();
  loading_handler_stop (handler_pid);
  if (ret)
    return 1;
  init_signal_handlers ();
  main_loop ();
  exit (0);
}
