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

#include <openvas/misc/network.h>    /* for ovas_scanner_context_t */
#include <openvas/misc/openvas_proctitle.h> /* for proctitle_set */
#include <openvas/misc/openvas_logging.h>  /* for setup_legacy_log_handler */
#include <openvas/base/pidfile.h>    /* for pidfile_create */
#include <openvas/base/nvticache.h> /* nvticache_free */
#include <openvas/misc/kb.h>         /* for KB_PATH_DEFAULT */
#include <openvas/misc/prefs.h>      /* for prefs_get() */

#include <gcrypt.h> /* for gcry_control */

#include "comm.h"         /* for comm_loading */
#include "attack.h"       /* for attack_network */
#include "sighand.h"      /* for openvas_signal */
#include "log.h"          /* for log_write */
#include "processes.h"    /* for create_process */
#include "ntp.h"          /* for ntp_timestamp_scan_starts */
#include "utils.h"        /* for wait_for_children1 */
#include "pluginlaunch.h" /* for init_loading_shm */

/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

static int global_iana_socket;
struct arglist *global_plugins;

static GHashTable *global_options;

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
  {"safe_checks", "yes"},
  {"auto_enable_dependencies", "yes"},
  {"use_mac_addr", "no"},
  {"nasl_no_signature_check", "yes"},
  {"drop_privileges", "no"},
  {"unscanned_closed", "yes"},
  {"unscanned_closed_udp", "yes"},
  // Empty options must be "\0", not NULL, to match the behavior of
  // prefs_init.
  {"vhosts", "\0"},
  {"vhosts_ip", "\0"},
  {"report_host_details", "yes"},
  {"cert_file", SCANNERCERT},
  {"key_file", SCANNERKEY},
  {"ca_file", CACERT},
  {"kb_location", KB_PATH_DEFAULT},
  {NULL, NULL}
};

/**
 * SSL context may be kept once it is inited.
 */
static ovas_scanner_context_t ovas_scanner_ctx;

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
  int soc2, opt = 1;
  if (soc <= 0)
    return;
  soc2 = ovas_scanner_context_attach (ovas_scanner_ctx, soc);
  if (soc2 < 0)
    {
      close (soc);
      return;
    }
  setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt));
  comm_loading (soc2);
  close_stream_connection (soc2);
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
  openvas_signal (SIGTERM, remove_pidfile);
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
      struct sockaddr_in6 address6;
      int soc;

      if (loading_stop_signal || kill (parent_pid, 0) < 0)
        break;
      lg_address = sizeof (struct sockaddr_in6);
      soc = accept (global_iana_socket, (struct sockaddr *) (&address6),
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
  int status;

  kill (handler_pid, SIGTERM);
  waitpid (handler_pid, &status, 0);
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
  struct arglist *plugins;
  const char *config_file;
  pid_t handler_pid;
  int i;

  log_write ("Reloading the scanner.");
  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);

  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return;
  /* Reload config file. */
  config_file = prefs_get ("config_file");
  prefs_init ();
  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  /* Reload the plugins */
  nvticache_free ();
  plugins = plugins_init ();
  set_globals_from_preferences ();
  plugins_free (global_plugins);
  global_plugins = plugins;
  loading_handler_stop (handler_pid);
  if (!global_plugins)
    exit (1);

  log_write ("Finished reloading the scanner.");
  reload_signal = 0;
  openvas_signal (SIGHUP, handle_reload_signal);
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
  char asciiaddr[INET6_ADDRSTRLEN];
  int opt = 1, soc2 = -1, soc;
  struct sockaddr_storage addr;
  socklen_t len;

  nvticache_reset ();
  soc = arg_get_value_int (globals, "global_socket");
  len = sizeof (addr);
  getpeername (soc, (struct sockaddr *) &addr, &len);
  if (addr.ss_family == AF_INET)
    {
      struct sockaddr_in *saddr = (struct sockaddr_in *) &addr;
      inet_ntop (AF_INET,  &saddr->sin_addr, asciiaddr, sizeof(asciiaddr));
    }
  else
    {
      struct sockaddr_in6 *s6addr = (struct sockaddr_in6 *) &addr;
      inet_ntop (AF_INET6, &s6addr->sin6_addr, asciiaddr, sizeof (asciiaddr));
    }
  proctitle_set ("openvassd: Serving %s", asciiaddr);

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

  soc2 = ovas_scanner_context_attach (ovas_scanner_ctx, soc);
  if (soc2 < 0)
    goto shutdown_and_exit;

  /* FIXME: The pre-gnutls code optionally printed information about
   * the peer's certificate at this point.
   */

  setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt));
  /* arg_set_value *replaces* an existing value, but it shouldn't fail here */
  arg_add_value (globals, "parent_socket", ARG_INT, GSIZE_TO_POINTER (soc));
  arg_set_value (globals, "global_socket", GSIZE_TO_POINTER (soc2));

  if (comm_init (soc2) < 0)
    {
      close_stream_connection (soc);
      exit (0);
    }
  handle_client (globals);

shutdown_and_exit:
  if (soc2 >= 0)
    close_stream_connection (soc2);
  else
    {
      shutdown (soc, 2);
      close (soc);
    }

  /* Kill left overs */
  end_daemon_mode ();
  exit (0);
}

static void
init_ssl_ctx (const char *priority, const char *dhparams)
{
  if (openvas_SSL_init () < 0)
    {
      log_write ("Could not initialize openvas SSL!\n");
      exit (1);
    }

  /* Only initialize ovas_scanner_ctx once */
  if (ovas_scanner_ctx == NULL)
    {
      const char *cert, *key, *passwd, *ca_file;

      ca_file = prefs_get ("ca_file");
      if (ca_file == NULL)
        {
          log_write ("Missing ca_file - Did you run openvas-mkcert?\n");
          exit (1);
        }
      cert = prefs_get ("cert_file");
      if (cert == NULL)
        {
          log_write ("Missing cert_file - Did you run openvas-mkcert?\n");
          exit (1);
        }
      key = prefs_get ("key_file");
      if (key == NULL)
        {
          log_write ("Missing key_file - Did you run openvas-mkcert?\n");
          exit (1);
        }

      passwd = prefs_get ("pem_password");
      ovas_scanner_ctx = ovas_scanner_context_new
                          (OPENVAS_ENCAPS_TLScustom, cert, key, passwd, ca_file,
                           priority, dhparams);
      if (!ovas_scanner_ctx)
        {
          log_write ("Could not create ovas_scanner_ctx");
          exit (1);
        }
    }
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

static void
main_loop ()
{
  log_write ("openvassd %s started", OPENVASSD_VERSION);
  proctitle_set ("openvassd: Waiting for incoming connections");
  for (;;)
    {
      int soc;
      unsigned int lg_address;
      struct sockaddr_in6 address6;
      struct arglist *globals;

      check_termination ();
      check_reload ();
      wait_for_children1 ();
      lg_address = sizeof (struct sockaddr_in6);
      soc = accept (global_iana_socket, (struct sockaddr *) (&address6),
                    &lg_address);
      if (soc == -1)
        continue;

      /*
       * MA: you cannot share an open SSL connection through fork/multithread
       * The SSL connection shall be open _after_ the fork */
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
 * Initialization of the network :
 * we setup the socket that will listen for incoming connections on port \<port\>
 * on address \<addr\>
 *
 * @param port Port on which to listen.
 * @param[out] sock Socket to be initialized.
 * @param addr Adress.
 *
 * @return 0 on success. Exit(1)s on failure.
 */
static int
init_network (int port, int *sock, struct addrinfo addr)
{
  int option = 1;

  if (addr.ai_family == AF_INET)
    ((struct sockaddr_in *) (addr.ai_addr))->sin_port = htons (port);
  else
    ((struct sockaddr_in6 *) (addr.ai_addr))->sin6_port = htons (port);
  if ((*sock = socket (addr.ai_family, SOCK_STREAM, 0)) == -1)
    {
      int ec = errno;
      log_write ("socket(AF_INET): %s", strerror (ec));
      exit (1);
    }

  setsockopt (*sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof (int));
  if (bind (*sock, (struct sockaddr *) (addr.ai_addr), addr.ai_addrlen) == -1)
    {
      log_write ("bind() failed : %s\n", strerror (errno));
      exit (1);
    }

  if (listen (*sock, 10) == -1)
    {
      log_write ("listen() failed : %s\n", strerror (errno));
      shutdown (*sock, 2);
      close (*sock);
      exit (1);
    }
  return (0);
}

static void
init_plugins (GHashTable *options)
{
  struct arglist *plugins;

  plugins = plugins_init ();

  g_hash_table_replace (options, "plugins", plugins);
  plugins_free (global_plugins);
  global_plugins = plugins;
}

/**
 * @brief Initialize everything.
 *
 * @param stop_early 0: do some initialization, 1: no initialization.
 */
static int
init_openvassd (GHashTable *options, int first_pass, int stop_early,
                int dont_fork)
{
  int isck = -1;
  int scanner_port;
  char *config_file;
  struct addrinfo *addr;
  int i;

  scanner_port = GPOINTER_TO_SIZE (g_hash_table_lookup (options,
                                                        "scanner_port"));
  config_file = g_hash_table_lookup (options, "config_file");
  addr = g_hash_table_lookup (options, "addr");

  prefs_init ();
  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  log_init (prefs_get ("logfile"));
  if (dont_fork == FALSE)
    setup_legacy_log_handler (log_vwrite);

  if (!stop_early)
    {
      if (first_pass != 0)
        init_network (scanner_port, &isck, *addr);
    }

  g_hash_table_replace (options, "isck", GSIZE_TO_POINTER (isck));

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

  rc = kb_flush (kb);

  kb_delete (kb);
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
  int exit_early = 0, scanner_port = 9391;
  pid_t handler_pid;
  char *myself;
  GHashTable *options;
  struct addrinfo *mysaddr;
  struct addrinfo hints;
  struct addrinfo ai;
  struct sockaddr_in saddr;
  struct sockaddr_in6 s6addr;

  proctitle_init (argc, argv);
  gcrypt_init ();

  if ((myself = strrchr (*argv, '/')) == 0)
    myself = *argv;
  else
    myself++;

  static gboolean display_version = FALSE;
  static gboolean dont_fork = FALSE;
  static gchar *address = NULL;
  static gchar *port = NULL;
  static gchar *config_file = NULL;
  static gchar *gnutls_priorities = "NORMAL";
  static gchar *dh_params = NULL;
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
    {"listen", 'a', 0, G_OPTION_ARG_STRING, &address,
     "Listen on <address>", "<address>"},
    {"port", 'p', 0, G_OPTION_ARG_STRING, &port,
     "Use port number <number>", "<number>"},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"cfg-specs", 's', 0, G_OPTION_ARG_NONE, &print_specs,
     "Print configuration settings", NULL},
    {"sysconfdir", 'y', 0, G_OPTION_ARG_NONE, &print_sysconfdir,
     "Print system configuration directory (set at compile time)", NULL},
    {"only-cache", 'C', 0, G_OPTION_ARG_NONE, &only_cache,
     "Exit once the NVT cache has been initialized or updated", NULL},
    {"gnutls-priorities", '\0', 0, G_OPTION_ARG_STRING, &gnutls_priorities,
     "GnuTLS priorities string", "<string>"},
    {"dh-params", '\0', 0, G_OPTION_ARG_STRING, &dh_params,
     "Diffie-Hellman parameters file", "<string>"},
    {NULL}
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

  if (print_specs)
    exit_early = 2;           /* no cipher initialization */

  if (address != NULL)
    {
      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = AI_NUMERICHOST;
      if (getaddrinfo (address, NULL, &hints, &mysaddr))
        {
          printf ("Invalid IP address.\n");
          printf ("Please use %s --help for more information.\n", myself);
          exit (0);
        }
      /* deep copy */
      ai.ai_family = mysaddr->ai_family;
      if (ai.ai_family == AF_INET)
        {
          memcpy (&saddr, mysaddr->ai_addr, mysaddr->ai_addrlen);
          ai.ai_addr = (struct sockaddr *) &saddr;
        }
      else
        {
          memcpy (&s6addr, mysaddr->ai_addr, mysaddr->ai_addrlen);
          ai.ai_addr = (struct sockaddr *) &s6addr;
        }
      ai.ai_family = mysaddr->ai_family;
      ai.ai_protocol = mysaddr->ai_protocol;
      ai.ai_socktype = mysaddr->ai_socktype;
      ai.ai_addrlen = mysaddr->ai_addrlen;
      freeaddrinfo (mysaddr);
    }
  else
    {
      /* Default to IPv4 */
      /*Warning: Not filling all the fields */
      saddr.sin_addr.s_addr = INADDR_ANY;
      saddr.sin_family = ai.ai_family = AF_INET;
      ai.ai_addrlen = sizeof (saddr);
      ai.ai_addr = (struct sockaddr *) &saddr;
    }

  if (port != NULL)
    {
      scanner_port = atoi (port);
      if ((scanner_port <= 0) || (scanner_port >= 65536))
        {
          printf ("Invalid port specification.\n");
          printf ("Please use %s --help for more information.\n", myself);
          exit (1);
        }
    }

  if (display_version)
    {
      printf ("OpenVAS Scanner %s\n", OPENVASSD_VERSION);
      printf
        ("Most new code since 2005: (C) 2015 Greenbone Networks GmbH\n");
      printf
        ("Nessus origin: (C) 2004 Renaud Deraison <deraison@nessus.org>\n");
      printf ("License GPLv2: GNU GPL version 2\n");
      printf
        ("This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n\n");
      exit (0);
    }

  options = g_hash_table_new (g_str_hash, g_str_equal);

  if (config_file != NULL)
    g_hash_table_insert (options, "acc_hint", GSIZE_TO_POINTER(1));
  else
    config_file = OPENVASSD_CONF;

  g_hash_table_insert (options, "scanner_port",
                       GSIZE_TO_POINTER (scanner_port));
  g_hash_table_insert (options, "config_file", config_file);
  g_hash_table_insert (options, "addr", &ai);

  if (only_cache)
    {
      init_openvassd (options, 0, 1, dont_fork);
      init_plugins (options);
      exit (0);
    }

  init_openvassd (options, 1, exit_early, dont_fork);
  flush_all_kbs ();
  global_options = options;
  global_iana_socket = GPOINTER_TO_SIZE (g_hash_table_lookup (options, "isck"));
  global_plugins = g_hash_table_lookup (options, "plugins");

  /* special treatment */
  if (print_specs)
    prefs_dump ();
  if (exit_early)
    exit (0);

  init_ssl_ctx (gnutls_priorities, dh_params);
  // Daemon mode:
  if (dont_fork == FALSE)
    set_daemon_mode ();
  pidfile_create ("openvassd");
  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return 1;
  init_plugins (options);
  loading_handler_stop (handler_pid);
  if (!global_plugins)
    return 1;
  init_signal_handlers ();
  main_loop ();
  g_hash_table_destroy (options);
  exit (0);
}
