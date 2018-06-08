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
 * @verbinclude README.md
 *
 * @section license License Information
 * @verbinclude COPYING
 */

/**
 * @file
 * OpenVAS Scanner main module, runs the scanner.
 */

#include <stdlib.h>    /* for atoi() */
#include <stdio.h>     /* for fflush() */
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
#include <glib.h>

#include <gvm/base/pidfile.h>    /* for pidfile_create */
#include <gvm/base/logging.h>    /* for setup_log_handler, load_log_configuration, free_log_configuration*/
#include <gvm/base/proctitle.h>  /* for proctitle_set */
#include <gvm/base/prefs.h>      /* for prefs_get() */
#include <gvm/base/nvti.h>       /* for prefs_get() */
#include <gvm/util/kb.h>         /* for KB_PATH_DEFAULT */
#include <gvm/util/nvticache.h>  /* nvticache_free */
#include <gvm/util/uuidutils.h>  /* gvm_uuid_make */
#include "../misc/plugutils.h"   /* nvticache_free */
#include "../misc/vendorversion.h" /* for vendor_version_set */

#include <gcrypt.h> /* for gcry_control */

#include "comm.h"         /* for comm_loading */
#include "attack.h"       /* for attack_network */
#include "sighand.h"      /* for openvas_signal */
#include "processes.h"    /* for create_process */
#include "ntp.h"          /* for ntp_timestamp_scan_starts */
#include "utils.h"        /* for wait_for_children1 */
#include "pluginlaunch.h" /* for init_loading_shm */

#ifdef GIT_REV_AVAILABLE
#include "gitrevision.h"
#endif

#if GNUTLS_VERSION_NUMBER < 0x030300
#include "../misc/network.h"     /* openvas_SSL_init */
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"


/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;


static int global_iana_socket = -1;

static volatile int loading_stop_signal = 0;
static volatile int reload_signal = 0;
static volatile int termination_signal = 0;
static char *global_scan_id = NULL;

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
  {"include_folders", OPENVAS_NVT_DIR},
  {"max_hosts", "30"},
  {"max_checks", "10"},
  {"be_nice", "no"},
  {"log_whole_attack", "no"},
  {"log_plugins_name_at_load", "no"},
  {"cgi_path", "/cgi-bin:/scripts"},
  {"optimize_test", "yes"},
  {"checks_read_timeout", "5"},
  {"network_scan", "no"},
  {"non_simult_ports", "139, 445, 3389, Services/irc"},
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
  // prefs_init.
  {"report_host_details", "yes"},
  {"kb_location", KB_PATH_DEFAULT},
  {"timeout_retry", "3"},
  {"open_sock_max_attempts", "5"},
  {"time_between_request", "0"},
  {NULL, NULL}
};

gchar *unix_socket_path = NULL;

static void
start_daemon_mode (void)
{
  /* do not block the listener port for subsequent scanners */
  close (global_iana_socket);

  /* become process group leader */
  if (setsid () < 0)
    {
      g_warning ("Cannot set process group leader (%s)\n",
                 strerror (errno));
    }
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

  if (setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt)) < 0)
    g_warning ("setsockopt: %s", strerror (errno));
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

  init_loading_shm ();
  parent_pid = getpid ();
  child_pid = fork ();
  if (child_pid != 0)
    return child_pid;

  proctitle_set ("openvassd (Loading Handler)");
  openvas_signal (SIGTERM, handle_loading_stop_signal);

  /*
   * Forked process will handle client requests until parent dies or stops it
   * with loading_handler_stop ().
   */
  while (1)
    {
      unsigned int lg_address;
      struct sockaddr_un address;
      int soc;
      fd_set set;
      struct timeval timeout;
      int rv, ret;
      pid_t child_pid1;

      if (loading_stop_signal || kill (parent_pid, 0) < 0)
        break;
      lg_address = sizeof (struct sockaddr_un);

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

      child_pid1 = fork ();
      if (child_pid1 == 0)
        {
          loading_client_handle (soc);
          close (soc);
          exit (0);
        }
      waitpid (child_pid1, &ret, WNOHANG);

    }
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
  static gchar *rc_name = NULL;
  const char *config_file;
  pid_t handler_pid;
  int i, ret;

  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);

  /* Setup logging. */
  rc_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvassd_log.conf",
                              NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  g_message ("Reloading the scanner.\n");

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

  g_message ("Finished reloading the scanner.");
  reload_signal = 0;
  openvas_signal (SIGHUP, handle_reload_signal);
  if (ret)
    exit (1);
}


/**
 * @brief Read the scan preferences from redis
 * @input scan_id Scan ID used as key to find the corresponding KB where
 *                to take the preferences from.
 * @return 0 on success, -1 if the kb is not found or no prefs are found in
 *         the kb.
 */
static int
load_scan_preferences (const char *scan_id)
{
  char key[1024];
  kb_t kb;
  struct kb_item *res = NULL;

  g_debug ("Start loading scan preferences.");
  if (!scan_id)
    return -1;

  snprintf (key, sizeof (key), "internal/%s/scanprefs", scan_id);
  kb = kb_find (prefs_get ("kb_location"), key);
  if (!kb)
    return -1;

  res = kb_item_get_all (kb, key);
  if (!res)
    return -1;

  while (res)
    {
      gchar **pref = g_strsplit (res->v_str, "|||", 2);
      if (pref[0])
        prefs_set (pref[0], pref[1] ?: "");
      g_strfreev (pref);
      res = res->next;
    }
  g_debug ("End loading scan preferences.");

  kb_item_free (res);
  return 0;
}

static void
handle_client (struct scan_globals *globals)
{
  kb_t net_kb = NULL;
  int soc = globals->global_socket;

  /* Become process group leader and the like ... */
  if (is_otp_scan ())
    {
      start_daemon_mode ();
      if (comm_wait_order (globals))
        return;
      ntp_timestamp_scan_starts (soc);
    }
  else
    {
      /* Load preferences from Redis. Scan started with a scan_id. */
      if (load_scan_preferences (globals->scan_id))
        {
          g_warning ("No preferences found for the scan %s", globals->scan_id);
          exit (0);
        }
    }
  attack_network (globals, &net_kb);
  if (net_kb != NULL)
    {
      kb_delete (net_kb);
      net_kb = NULL;
    }
  if (is_otp_scan ())
    {
      ntp_timestamp_scan_ends (soc);
      comm_terminate (soc);
    }
}

static void
scanner_thread (struct scan_globals *globals)
{
  int opt = 1, soc;

  nvticache_reset ();

  if (is_otp_scan () && !global_scan_id)
    {
      globals->scan_id = (char *) gvm_uuid_make ();
      soc = globals->global_socket;
      proctitle_set ("openvassd: Serving %s", unix_socket_path);

      /* Close the scanner thread - it is useless for us now */
      close (global_iana_socket);

      if (soc < 0)
        goto shutdown_and_exit;

      if (setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt)) < 0)
        goto shutdown_and_exit;

      globals->global_socket = soc;

      if (comm_init (soc) < 0)
        exit (0);
    }
  else
    globals->scan_id = g_strdup (global_scan_id);

  /* Everyone runs with a nicelevel of 10 */
  if (prefs_get_bool ("be_nice"))
    {
      errno = 0;
      if (nice(10) == -1 && errno != 0)
        {
          g_warning ("Unable to renice process: %d", errno);
        }
    }

  handle_client (globals);

shutdown_and_exit:
  if (is_otp_scan () && !global_scan_id)
    {
      shutdown (soc, 2);
      close (soc);
      /* Kill left overs */
      end_daemon_mode ();
    }
  exit (0);
}

/**
 * @brief Free logging configuration.
 */
static void
log_config_free ()
{
  free_log_configuration (log_config);
  log_config = NULL;
}


/*
 * @brief Terminates the scanner if a termination signal was received.
 */
static void
check_termination ()
{
  if (termination_signal)
    {
      g_debug ("Received the %s signal", strsignal (termination_signal));
      if (log_config) log_config_free ();
      remove_pidfile ();
      make_em_die (SIGTERM);
      _exit (0);
    }
}

/*
 * @brief Reloads the scanner if a reload was requested or the feed was updated.
 */
static void
check_reload ()
{
  if (reload_signal || nvticache_check_feed ())
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
    g_message ("Unable to open directory: %s\n", error->message);
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
              g_message ("Stopping running scan with PID: %s", processID);
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
          g_message ("Redis connection lost. Trying to reconnect.");
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
      g_message ("Critical Redis connection error.");
      exit (1);
    }
  while (waitkb != 0)
    {
      kb_access_aux = kb_find (prefs_get ("kb_location"), NVTICACHE_STR);
      if (!kb_access_aux)
        {
          g_message ("Redis kb not found. Trying again in 2 seconds.");
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
      g_message ("Redis connection error. Stopping all the running scans.");
      stop_all_scans ();
      reload_openvassd ();
    }
}


static void
main_loop ()
{
#ifdef OPENVASSD_GIT_REVISION
  g_message ("openvassd %s (GIT revision %s) started",
             OPENVASSD_VERSION,
             OPENVASSD_GIT_REVISION);
#else
  g_message ("openvassd %s started", OPENVASSD_VERSION);
#endif
  proctitle_set ("openvassd: Waiting for incoming connections");
  for (;;)
    {
      int soc;
      unsigned int lg_address;
      struct sockaddr_un address;
      struct scan_globals *globals;

      check_termination ();
      check_kb_status ();
      wait_for_children1 ();
      lg_address = sizeof (struct sockaddr_un);
      soc = accept (global_iana_socket, (struct sockaddr *) (&address),
                    &lg_address);
      if (soc == -1)
        continue;

      globals = g_malloc0 (sizeof (struct scan_globals));
      globals->global_socket = soc;
      /* Set scan type 1:OTP, 0:OSP */
      set_scan_type (1);

      /* Check for reload after accept() but before we fork, to ensure that
       * Manager gets full updated feed in case of NVT update connection.
       */
      check_reload ();
      if (create_process ((process_func_t) scanner_thread, globals) < 0)
        {
          g_debug ("Could not fork - client won't be served");
          sleep (2);
        }
      close (soc);
      g_free (globals);
    }
}

/**
 * Initialization of the network in unix socket case:
 * we setup the socket that will listen for incoming connections on
 * unix_socket_path.
 *
 * @param[out] sock Socket to be initialized.
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
      g_debug ("%s: Couldn't create UNIX socket", __FUNCTION__);
      close (unix_socket);
      return -1;
    }
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, unix_socket_path, sizeof (addr.sun_path) - 1);
  if (!stat (addr.sun_path, &ustat))
    {
      /* Remove socket so we can bind(). */
      unlink (addr.sun_path);
    }
  if (bind (unix_socket, (struct sockaddr *) &addr, sizeof (struct sockaddr_un))
      == -1)
    {
      g_debug ("%s: Error on bind(%s): %s", __FUNCTION__,
                 unix_socket_path, strerror (errno));
      return -1;
    }

  if (owner)
    {
      struct passwd *pwd = getpwnam (owner);
      if (!pwd)
        {
          g_debug ("%s: User %s not found.", __FUNCTION__, owner);
          return -1;
        }
      if (chown (unix_socket_path, pwd->pw_uid, -1) == -1)
        {
          g_debug ("%s: chown: %s", __FUNCTION__, strerror (errno));
          return -1;
        }
    }

  if (group)
    {
      struct group *grp = getgrnam (group);
      if (!grp)
        {
          g_debug ("%s: Group %s not found.", __FUNCTION__, group);
          return -1;
        }
      if (chown (unix_socket_path, -1, grp->gr_gid) == -1)
        {
          g_debug ("%s: chown: %s", __FUNCTION__, strerror (errno));
          return -1;
        }
    }

  if (!mode)
    mode = "660";
 omode = strtol (mode, 0, 8);
 if (omode <= 0 || omode > 4095)
   {
     g_debug ("%s: Erroneous liste-mode value", __FUNCTION__);
     return -1;
   }
 if (chmod (unix_socket_path, strtol (mode, 0, 8)) == -1)
   {
     g_debug ("%s: chmod: %s", __FUNCTION__, strerror (errno));
     return -1;
   }

  if (listen (unix_socket, 128) == -1)
    {
      g_debug ("%s: Error on listen(): %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  *sock = unix_socket;
  return 0;
}

/**
 * @brief Initialize everything.
 *
 * @param config_file Path to config file for initialization
 */
static int
init_openvassd (const char *config_file)
{
  static gchar *rc_name = NULL;
  int i;

  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);



  /* Setup logging. */
  rc_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvassd_log.conf",
                              NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  set_globals_from_preferences ();

  return 0;
}

static void
set_daemon_mode ()
{
  if (fork ())
    { /* Parent. */
      log_config_free ();
      exit (0);
    }
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

  rc = kb_flush (kb, NVTICACHE_STR);
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

void
start_single_task_scan ()
{
  struct scan_globals *globals;
  int ret = 0;

#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
#endif

#ifdef OPENVASSD_GIT_REVISION
  g_message ("openvassd %s (GIT revision %s) started",
             OPENVASSD_VERSION,
             OPENVASSD_GIT_REVISION);
#else
  g_message ("openvassd %s started", OPENVASSD_VERSION);
#endif

  pidfile_create ("openvassd");
  openvas_signal (SIGHUP, SIG_IGN);
  ret = plugins_init ();
  if (ret)
    exit (0);
  init_signal_handlers ();

  globals = g_malloc0 (sizeof (struct scan_globals));

  /* Set scan type 1:OTP, 0:OSP */
  set_scan_type (0);
  scanner_thread (globals);
  exit (0);
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
  static gchar *scan_id = NULL;
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
    {"scan-start", '\0', 0, G_OPTION_ARG_STRING, &scan_id,
     "ID for this scan taks", "<string>"},
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
#ifdef OPENVASSD_GIT_REVISION
      printf ("GIT revision %s\n", OPENVASSD_GIT_REVISION);
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

  if (vendor_version_string)
    vendor_version_set (vendor_version_string);

  if (!config_file)
    config_file = OPENVASSD_CONF;
  if (only_cache)
    {
      if (init_openvassd (config_file))
        return 1;
      if (plugins_init ())
        return 1;
      return 0;
    }

  if (init_openvassd (config_file))
    return 1;

  if (scan_id)
    {
      global_scan_id = g_strdup (scan_id);
      start_single_task_scan ();
      exit (0);
    }

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
  if (flush_all_kbs ())
    exit (1);


#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
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
