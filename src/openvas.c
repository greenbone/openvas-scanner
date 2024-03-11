/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: 1998-2006 Tenable Network Security, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
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
 * OpenVAS main module, runs the scanner.
 */

#include "openvas.h"

#include "../misc/kb_cache.h"
#include "../misc/plugutils.h"     /* nvticache_free */
#include "../misc/scan_id.h"       /* to manage global scan_id */
#include "../misc/vendorversion.h" /* for vendor_version_set */
#include "attack.h"                /* for attack_network */
#include "debug_utils.h"           /* for init_sentry */
#include "pluginlaunch.h"          /* for init_loading_shm */
#include "processes.h"             /* for create_process */
#include "sighand.h"               /* for openvas_signal */
#include "utils.h"                 /* for store_file */

#include <bsd/unistd.h> /* for proctitle_init */
#include <errno.h>      /* for errno() */
#include <fcntl.h>      /* for open() */
#include <gcrypt.h>     /* for gcry_control */
#include <glib.h>
#include <gnutls/gnutls.h> /* for gnutls_global_set_log_*  */
#include <grp.h>
#include <gvm/base/logging.h> /* for setup_log_handler, load_log_configuration, free_log_configuration*/
#include <gvm/base/nvti.h>      /* for prefs_get() */
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/base/version.h>   /* for gvm_libs_version */
#include <gvm/util/kb.h>        /* for KB_PATH_DEFAULT */
#include <gvm/util/mqtt.h>      /* for mqtt_init */
#include <gvm/util/nvticache.h> /* nvticache_free */
#include <gvm/util/uuidutils.h> /* gvm_uuid_make */
#include <netdb.h>              /* for addrinfo */
#include <pwd.h>
#include <signal.h> /* for SIGTERM */
#include <stdio.h>  /* for fflush() */
#include <stdlib.h> /* for atoi() */
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h> /* for waitpid */
#include <unistd.h>   /* for close() */

#ifdef GIT_REV_AVAILABLE
#include "gitrevision.h"
#endif

#if GNUTLS_VERSION_NUMBER < 0x030300
#include "../misc/network.h" /* openvas_SSL_init */
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

#define PROCTITLE_WAITING "openvas: Waiting for incoming connections"
#define PROCTITLE_LOADING "openvas: Loading Handler"
#define PROCTITLE_RELOADING "openvas: Reloading"
#define PROCTITLE_SERVING "openvas: Serving %s"

/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

int global_min_memory = 0;
int global_max_sysload = 0;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;

static volatile int termination_signal = 0;
// static char *global_scan_id = NULL;

typedef struct
{
  char *option;
  char *value;
} openvas_option;

/**
 * @brief Default values for scanner options. Must be NULL terminated.
 *
 * Only include options which are dependent on CMake variables.
 * Empty options must be "\0", not NULL, to match the behavior of prefs_init.
 */
static openvas_option openvas_defaults[] = {
  {"plugins_folder", OPENVAS_NVT_DIR},
  {"include_folders", OPENVAS_NVT_DIR},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"scanner_plugins_timeout", G_STRINGIFY (SCANNER_NVT_TIMEOUT)},
  {"db_address", KB_PATH_DEFAULT},
  {NULL, NULL}};

/**
 * @brief Set the prefs from the openvas_defaults array.
 */
static void
set_default_openvas_prefs ()
{
  for (int i = 0; openvas_defaults[i].option != NULL; i++)
    prefs_set (openvas_defaults[i].option, openvas_defaults[i].value);
}

static void
my_gnutls_log_func (int level, const char *text)
{
  g_message ("(%d) %s", level, text);
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

  if ((str = prefs_get ("max_sysload")) != NULL)
    {
      global_max_sysload = atoi (str);
      if (global_max_sysload <= 0)
        global_max_sysload = 0;
    }

  if ((str = prefs_get ("min_free_mem")) != NULL)
    {
      global_min_memory = atoi (str);
      if (global_min_memory <= 0)
        global_min_memory = 0;
    }
}

static void
handle_termination_signal (int sig)
{
  termination_signal = sig;
  procs_terminate_childs ();
}

/**
 * @brief Initializes main scanner process' signal handlers.
 */
static void
init_signal_handlers (void)
{
  openvas_signal (SIGTERM, handle_termination_signal);
  openvas_signal (SIGINT, handle_termination_signal);
  openvas_signal (SIGQUIT, handle_termination_signal);
  openvas_signal (SIGCHLD, sighand_chld);
}

/**
 * @brief Read the scan preferences from redis
 *
 * Adds preferences to the global_prefs.
 * If preference already exists in global_prefs they will be overwritten by
 * prefs from client.
 *
 * @param globals Scan ID of globals used as key to find the corresponding KB
 * where to take the preferences from. Globals also used for file upload.
 *
 * @return 0 on success, -1 if the kb is not found or no prefs are found in
 *         the kb.
 */
static int
overwrite_openvas_prefs_with_prefs_from_client (struct scan_globals *globals)
{
  char key[1024];
  kb_t kb;
  struct kb_item *res = NULL;

  g_debug ("Start loading scan preferences.");
  if (!globals->scan_id)
    return -1;

  snprintf (key, sizeof (key), "internal/%s/scanprefs", globals->scan_id);

  kb = kb_find (prefs_get ("db_address"), key);
  if (!kb)
    return -1;
  // 2022-10-19: currently internal/%s/scanprefs are set by ospd which is the
  // main_kb in our context
  set_main_kb (kb);

  res = kb_item_get_all (kb, key);
  if (!res)
    return -1;

  while (res)
    {
      gchar **pref = g_strsplit (res->v_str, "|||", 2);
      if (pref[0])
        {
          gchar **pref_name = g_strsplit (pref[0], ":", 3);
          if (pref_name[1] && pref_name[2] && !strncmp (pref_name[2], "file", 4)
              && strcmp (pref[1], ""))
            {
              char *file_uuid = gvm_uuid_make ();
              int ret;
              prefs_set (pref[0], file_uuid);
              ret = store_file (globals, pref[1], file_uuid);
              if (ret)
                g_debug ("Load preference: Failed to upload file "
                         "for nvt %s preference.",
                         pref_name[0]);

              g_free (file_uuid);
            }
          else if (is_scanner_only_pref (pref[0]))
            g_warning ("%s is a scanner only preference. It can not be written "
                       "by the client and will be ignored.",
                       pref_name[0]);
          else
            prefs_set (pref[0], pref[1] ? pref[1] : "");
          g_strfreev (pref_name);
        }

      g_strfreev (pref);
      res = res->next;
    }
  kb_del_items (kb, key);
  snprintf (key, sizeof (key), "internal/%s", globals->scan_id);
  kb_item_set_str_with_main_kb_check (kb, key, "ready", 0);
  kb_item_set_int_with_main_kb_check (kb, "internal/ovas_pid", getpid ());
  kb_lnk_reset (kb);

  g_debug ("End loading scan preferences.");

  kb_item_free (res);
  return 0;
}

/**
 * @brief Init logging.
 *
 * @return 0 on success, -1 on error.
 */
static int
init_logging ()
{
  static gchar *log_config_file_name = NULL;
  int err;

  log_config_file_name =
    g_build_filename (OPENVAS_SYSCONF_DIR, "openvas_log.conf", NULL);
  if (g_file_test (log_config_file_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (log_config_file_name);
  err = setup_log_handlers (log_config);
  if (err)
    {
      g_warning ("%s: Can not open or create log file or directory. "
                 "Please check permissions of log files listed in %s.",
                 __func__, log_config_file_name);
      g_free (log_config_file_name);
      return -1;
    }
  g_free (log_config_file_name);

  return 0;
}

static void
gcrypt_init (void)
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
 * @brief Check TLS.
 */
static void
check_tls ()
{
#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
#endif

  if (prefs_get ("debug_tls") != NULL && atoi (prefs_get ("debug_tls")) > 0)
    {
      g_warning ("TLS debug is enabled and should only be used with care, "
                 "since it may reveal sensitive information in the scanner "
                 "logs and might make openvas fill your disk rather quickly.");
      gnutls_global_set_log_function (my_gnutls_log_func);
      gnutls_global_set_log_level (atoi (prefs_get ("debug_tls")));
    }
}

/**
 * @brief Print start message.
 */
static void
openvas_print_start_msg ()
{
#ifdef OPENVAS_GIT_REVISION
  g_message ("openvas %s (GIT revision %s) started", OPENVAS_VERSION,
             OPENVAS_GIT_REVISION);
#else
  g_message ("openvas %s started", OPENVAS_VERSION);
#endif
}

/**
 * @brief Search in redis the process ID of a running scan and
 * sends it the kill signal SIGUSR1, which will stop the scan.
 * To find the process ID, it uses the scan_id passed with the
 * --scan-stop option.
 *
 * @return 0 on success, 1 otherwise.
 */
static int
stop_single_task_scan (void)
{
  char key[1024];
  kb_t kb;
  int pid;

  if (!get_scan_id ())
    return 1;

  snprintf (key, sizeof (key), "internal/%s", get_scan_id ());
  kb = kb_find (prefs_get ("db_address"), key);
  if (!kb)
    return 1;

  pid = kb_item_get_int (kb, "internal/ovas_pid");

  /* Only send the signal if the pid is a positive value.
     Since kb_item_get_int() will return -1 if the key does
     not exist.
     Warning: killing with -1 pid will send the signal system wide.
   */
  if (pid <= 0)
    return 1;

  /* Send the signal to the process group. */
  killpg (pid, SIGUSR1);
  return 0;
}

/**
 * @brief Send a failure message and set the scan as finished.
 *
 * @param msg Message to send to the client.
 */
static void
send_message_to_client_and_finish_scan (const char *msg)
{
  char key[1024];
  kb_t kb;

  // We get the main kb. It is still not set as global at this point.
  snprintf (key, sizeof (key), "internal/%s/scanprefs", get_scan_id ());
  kb = kb_find (prefs_get ("db_address"), key);
  kb_item_push_str (kb, "internal/results", msg);
  snprintf (key, sizeof (key), "internal/%s", get_scan_id ());
  kb_item_set_str (kb, key, "finished", 0);
  kb_lnk_reset (kb);
}

/**
 * @brief Set up data needed for attack_network().
 *
 * @param globals scan_globals needed for client preference handling.
 * @param config_file Used for config preference handling.
 *
 * @return 0 on success, 1 otherwise.
 */
static int
attack_network_init (struct scan_globals *globals, const gchar *config_file)
{
  const char *mqtt_server_uri;
  const char *openvasd_server_uri;

  set_default_openvas_prefs ();
  prefs_config (config_file);
  set_globals_from_preferences ();

  if (prefs_get ("vendor_version") != NULL)
    vendor_version_set (prefs_get ("vendor_version"));
  check_tls ();
  openvas_print_start_msg ();

  if (plugins_cache_init ())
    {
      g_message ("Failed to initialize nvti cache.");
      send_message_to_client_and_finish_scan (
        "ERRMSG||| ||| ||| ||| |||NVTI cache initialization failed");
      nvticache_reset ();
      return 1;
    }
  nvticache_reset ();

  /* Init Notus communication */
  openvasd_server_uri = prefs_get ("openvasd_server");
  if (openvasd_server_uri)
    {
      g_message ("%s: LSC via openvasd", __func__);
      prefs_set ("openvasd_lsc_enabled", "yes");
    }
  else
    {
      mqtt_server_uri = prefs_get ("mqtt_server_uri");
      if (mqtt_server_uri)
        {
#ifdef AUTH_MQTT
          const char *mqtt_user = prefs_get ("mqtt_user");
          const char *mqtt_pass = prefs_get ("mqtt_pass");
          if ((mqtt_init_auth (mqtt_server_uri, mqtt_user, mqtt_pass)) != 0)
#else
          if ((mqtt_init (mqtt_server_uri)) != 0)
#endif
            {
              g_message ("%s: INIT MQTT: FAIL", __func__);
              send_message_to_client_and_finish_scan (
                "ERRMSG||| ||| ||| ||| |||MQTT initialization failed");
            }
          else
            {
              g_message ("%s: INIT MQTT: SUCCESS", __func__);
              prefs_set ("mqtt_enabled", "yes");
            }
        }
      else
        {
          g_message ("%s: Neither openvasd_server nor mqtt_server_uri given, "
                     "LSC disabled",
                     __func__);
        }
    }

  init_signal_handlers ();

  /* Make process a group leader, to make it easier to cleanup forked
   * processes & their children. */
  setpgid (0, 0);

  if (overwrite_openvas_prefs_with_prefs_from_client (globals))
    {
      g_warning ("No preferences found for the scan %s", globals->scan_id);
      return 1;
    }

  return 0;
}

/**
 * @brief openvas.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
int
openvas (int argc, char *argv[], char *env[])
{
  int err;

  setproctitle_init (argc, argv, env);
  gcrypt_init ();

  static gboolean display_version = FALSE;
  static gchar *config_file = NULL;
  static gchar *scan_id = NULL;
  static gchar *stop_scan_id = NULL;
  static gboolean print_specs = FALSE;
  static gboolean print_sysconfdir = FALSE;
  static gboolean update_vt_info = FALSE;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"cfg-specs", 's', 0, G_OPTION_ARG_NONE, &print_specs,
     "Print configuration settings", NULL},
    {"sysconfdir", 'y', 0, G_OPTION_ARG_NONE, &print_sysconfdir,
     "Print system configuration directory (set at compile time)", NULL},
    {"update-vt-info", 'u', 0, G_OPTION_ARG_NONE, &update_vt_info,
     "Updates VT info into redis store from VT files", NULL},
    {"scan-start", '\0', 0, G_OPTION_ARG_STRING, &scan_id,
     "ID of scan to start. ID and related data must be stored into redis "
     "before.",
     "<string>"},
    {"scan-stop", '\0', 0, G_OPTION_ARG_STRING, &stop_scan_id,
     "ID of scan to stop", "<string>"},

    {NULL, 0, 0, 0, NULL, NULL, NULL}};

  option_context =
    g_option_context_new ("- Open Vulnerability Assessment Scanner");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      return EXIT_SUCCESS;
    }
  g_option_context_free (option_context);

  /* --sysconfdir */
  if (print_sysconfdir)
    {
      g_print ("%s\n", SYSCONFDIR);
      return EXIT_SUCCESS;
    }

  /* --version */
  if (display_version)
    {
      printf ("OpenVAS %s\n", OPENVAS_VERSION);
#ifdef OPENVAS_GIT_REVISION
      printf ("GIT revision %s\n", OPENVAS_GIT_REVISION);
#endif
      printf ("gvm-libs %s\n", gvm_libs_version ());
      printf ("Most new code since 2005: (C) 2022 Greenbone Networks GmbH\n");
      printf (
        "Nessus origin: (C) 2004 Renaud Deraison <deraison@nessus.org>\n");
      printf ("License GPLv2: GNU GPL version 2\n");
      printf (
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n\n");
      return EXIT_SUCCESS;
    }

  /* Switch to UTC so that OTP times are always in UTC. */
  if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_print ("%s\n\n", strerror (errno));
      return EXIT_SUCCESS;
    }
  tzset ();

#ifdef LOG_REFERENCES_AVAILABLE
  if (scan_id)
    set_log_reference (scan_id);
  if (stop_scan_id)
    set_log_reference (stop_scan_id);
#endif // LOG_REFERENCES_AVAILABLE
  if (init_logging () != 0)
    return EXIT_FAILURE;

  if (!init_sentry ())
    {
      g_message ("Sentry is enabled. This can log sensitive information.");
    }

  /* Config file location */
  if (!config_file)
    config_file = OPENVAS_CONF;

  if (update_vt_info)
    {
      set_default_openvas_prefs ();
      prefs_config (config_file);
      set_globals_from_preferences ();
      err = plugins_init ();
      nvticache_reset ();
      gvm_close_sentry ();
      return err ? EXIT_FAILURE : EXIT_SUCCESS;
    }

  /* openvas --scan-stop */
  if (stop_scan_id)
    {
      set_default_openvas_prefs ();
      prefs_config (config_file);
      if (plugins_cache_init ())
        {
          g_message ("Failed to initialize nvti cache. Not possible to "
                     "stop the scan");
          nvticache_reset ();
          gvm_close_sentry ();
          return EXIT_FAILURE;
        }
      nvticache_reset ();

      set_scan_id (g_strdup (stop_scan_id));
      err = stop_single_task_scan ();
      gvm_close_sentry ();
#ifdef LOG_REFERENCES_AVAILABLE
      free_log_reference ();
#endif // LOG_REFERENCES_AVAILABLE
      return err ? EXIT_FAILURE : EXIT_SUCCESS;
    }

  /* openvas --scan-start */
  if (scan_id)
    {
      struct scan_globals *globals;
      set_scan_id (g_strdup (scan_id));
      globals = g_malloc0 (sizeof (struct scan_globals));
      globals->scan_id = g_strdup (get_scan_id ());

      if (attack_network_init (globals, config_file) != 0)
        {
          destroy_scan_globals (globals);
          return EXIT_FAILURE;
        }
      attack_network (globals);

      gvm_close_sentry ();
      destroy_scan_globals (globals);
#ifdef LOG_REFERENCES_AVAILABLE
      free_log_reference ();
#endif // LOG_REFERENCES_AVAILABLE
      return EXIT_SUCCESS;
    }

  if (print_specs)
    {
      set_default_openvas_prefs ();
      prefs_config (config_file);
      prefs_dump ();
      gvm_close_sentry ();
    }

  return EXIT_SUCCESS;
}
