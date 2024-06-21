/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2005 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl.c
 * @brief Source of the standalone NASL interpreter of OpenVAS.
 */

#include "nasl.h"

#include "../misc/kb_cache.h" // for get_main_kb
#include "../misc/network.h"
#include "../misc/nvt_categories.h"
#include "../misc/plugutils.h"
#include "../misc/vendorversion.h"
#include "exec.h"
#include "nasl_lex_ctxt.h"

#include <errno.h>  /* for errno */
#include <gcrypt.h> /* for gcry_control */
#include <glib.h>
#include <gnutls/gnutls.h>       /* for gnutls_check_version */
#include <gpgme.h>               /* for gpgme_check_version */
#include <gvm/base/hosts.h>      /* for gvm_hosts_* and gvm_host_* */
#include <gvm/base/networking.h> /* for gvm_source_iface_init */
#include <gvm/base/nvti.h>
#include <gvm/base/prefs.h> /* for prefs_get */
#include <gvm/util/kb.h>    /* for kb_new */
#include <libssh/libssh.h>  /* for ssh_version */
#include <signal.h>         /* for SIGINT */
#include <stdlib.h>         /* for exit */
#include <string.h>         /* for strlen */
#include <sys/wait.h>
#include <unistd.h> /* for geteuid */

#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

extern char *
nasl_version (void);

static void
my_gnutls_log_func (int level, const char *text)
{
  fprintf (stderr, "[%d] (%d) %s", getpid (), level, text);
  if (*text && text[strlen (text) - 1] != '\n')
    putc ('\n', stderr);
}

static struct script_infos *
init (struct in6_addr *ip, GSList *vhosts, kb_t kb)
{
  struct script_infos *infos = g_malloc0 (sizeof (struct script_infos));

  infos->standalone = 1;
  infos->key = kb;
  infos->ip = ip;
  infos->vhosts = vhosts;
  if (prefs_get_bool ("test_empty_vhost"))
    {
      gvm_vhost_t *vhost =
        gvm_vhost_new (addr6_as_str (ip), g_strdup ("IP-address"));
      infos->vhosts = g_slist_prepend (infos->vhosts, vhost);
    }
  infos->globals = g_malloc0 (sizeof (struct scan_globals));

  return infos;
}

extern FILE *nasl_trace_fp;

static nvti_t *
parse_script_infos (struct script_infos *infos)
{
  nvti_t *nvti;
  int mode = NASL_EXEC_DESCR | NASL_ALWAYS_SIGNED;

  nvti = nvti_new ();
  infos->nvti = nvti;
  if (exec_nasl_script (infos, mode) < 0)
    {
      printf ("%s could not be loaded\n", infos->name);
      return NULL;
    }
  infos->nvti = NULL;
  infos->oid = g_strdup (nvti_oid (nvti));

  return nvti;
}

/**
 * @brief Checks that an NVT category is safe.
 *
 * @param category  Category to check.
 *
 * @return 0 if category is unsafe, 1 otherwise.
 */
static int
nvti_category_is_safe (int category)
{
  if (category == ACT_DESTRUCTIVE_ATTACK || category == ACT_KILL_HOST
      || category == ACT_FLOOD || category == ACT_DENIAL)
    return 0;
  return 1;
}

/**
 * @brief Initialize Gcrypt.
 */
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
 * @brief Main of the standalone nasl interpreter.
 * @return The number of times a NVT was launched
 *         (should be (number of targets) * (number of NVTS provided)).
 */
int
main (int argc, char **argv)
{
  struct script_infos *script_infos;
  gvm_hosts_t *hosts;
  gvm_host_t *host;
  static gchar *target = NULL;
  gchar *default_target = "127.0.0.1";
  int mode = 0, err = 0, pos;
  extern int global_nasl_debug;
  GSList *unresolved;

  static gboolean display_version = FALSE;
  static gboolean nasl_debug = FALSE;
  static gboolean description_only = FALSE;
  static gboolean both_modes = FALSE;
  static gboolean parse_only = FALSE;
  static gboolean do_lint = FALSE;
  static gchar *trace_file = NULL;
  static gchar *config_file = NULL;
  static gchar *source_iface = NULL;
  static gchar *port_range = NULL;
  static gboolean with_safe_checks = FALSE;
  static gboolean signing_mode = FALSE;
  static gchar *include_dir = NULL;
  static gchar **nasl_filenames = NULL;
  static gchar **kb_values = NULL;
  static int debug_tls = 0;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"debug", 'd', 0, G_OPTION_ARG_NONE, &nasl_debug,
     "Output debug information to stderr.", NULL},
    {"description", 'D', 0, G_OPTION_ARG_NONE, &description_only,
     "Only run the 'description' part of the script", NULL},
    {"both", 'B', 0, G_OPTION_ARG_NONE, &both_modes,
     "Run in description mode before running the script.", NULL},
    {"parse", 'p', 0, G_OPTION_ARG_NONE, &parse_only,
     "Only parse the script, don't execute it", NULL},
    {"lint", 'L', 0, G_OPTION_ARG_NONE, &do_lint,
     "'lint' the script (extended checks)", NULL},
    {"target", 't', 0, G_OPTION_ARG_STRING, &target,
     "Execute the scripts against <target>", "<target>"},
    {"trace", 'T', 0, G_OPTION_ARG_FILENAME, &trace_file,
     "Log actions to <file> (or '-' for stderr)", "<file>"},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"source-iface", 'e', 0, G_OPTION_ARG_STRING, &source_iface,
     "Source network interface for established connections.", "<iface_name>"},
    {"safe", 's', 0, G_OPTION_ARG_NONE, &with_safe_checks,
     "Specifies that the script should be run with 'safe checks' enabled",
     NULL},
    {"disable-signing", 'X', 0, G_OPTION_ARG_NONE, &signing_mode,
     "Run the script with disabled signature verification", NULL},
    {"include-dir", 'i', 0, G_OPTION_ARG_STRING, &include_dir,
     "Search for includes in <dir>", "<dir>"},
    {"debug-tls", 0, 0, G_OPTION_ARG_INT, &debug_tls,
     "Enable TLS debugging at <level>", "<level>"},
    {"kb", 'k', 0, G_OPTION_ARG_STRING_ARRAY, &kb_values,
     "Set KB key to value. Can be used multiple times", "<key=value>"},
    {"port-range", 'r', 0, G_OPTION_ARG_STRING, &port_range,
     "Set the <port-range> used by nasl scripts. ", "<port-range>"},
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &nasl_filenames,
     "Absolute path to one or more nasl scripts", "NASL_FILE..."},
    {NULL, 0, 0, 0, NULL, NULL, NULL}};

  option_context =
    g_option_context_new ("- standalone NASL interpreter for OpenVAS");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      exit (0);
    }
  g_option_context_free (option_context);
  /*--------------------------------------------
         Command-line options
   ---------------------------------------------*/

  if (display_version)
    {
      printf ("openvas-nasl %s\n", nasl_version ());
      if (debug_tls)
        {
          printf ("gnutls %s\n", gnutls_check_version (NULL));
          printf ("libssh %s\n", ssh_version (0));
          printf ("gpgme %s\n", gpgme_check_version (NULL));
        }
      else
        putchar ('\n');
      printf ("Copyright (C) 2002 - 2004 Tenable Network Security\n");
      printf ("Copyright (C) 2022 Greenbone Networks GmbH\n\n");
      exit (0);
    }
  if (nasl_debug)
    global_nasl_debug = 1;
  mode |= NASL_COMMAND_LINE;
  if (signing_mode)
    mode |= NASL_ALWAYS_SIGNED;
  if (description_only)
    mode |= NASL_EXEC_DESCR;
  if (do_lint)
    mode |= NASL_LINT;
  if (parse_only)
    mode |= NASL_EXEC_PARSE_ONLY;
  if (trace_file)
    {
      if (!strcmp (trace_file, "-"))
        nasl_trace_fp = stderr;
      else
        {
          FILE *fp = fopen (trace_file, "w");
          if (fp == NULL)
            {
              perror (optarg);
              exit (2);
            }
          setvbuf (fp, NULL, _IOLBF, BUFSIZ);
          nasl_trace_fp = fp;
        }
    }

  gcrypt_init ();
  openvas_SSL_init ();
  if (!nasl_filenames)
    {
      fprintf (stderr, "Error. No input file(s) specified !\n");
      exit (1);
    }

  if (!(mode & (NASL_EXEC_PARSE_ONLY | NASL_LINT)) && geteuid ())
    {
      fprintf (stderr, "** WARNING : packet forgery will not work\n");
      fprintf (stderr, "** as NASL is not running as root\n");
    }
  signal (SIGPIPE, SIG_IGN);

  if (source_iface && gvm_source_iface_init (source_iface))
    {
      fprintf (stderr, "Erroneous network source interface: %s\n",
               source_iface);
      exit (1);
    }
  if (debug_tls)
    {
      gnutls_global_set_log_function (my_gnutls_log_func);
      gnutls_global_set_log_level (debug_tls);
    }

  if (!target)
    target = g_strdup (default_target);

  hosts = gvm_hosts_new (target);
  if (!hosts)
    {
      fprintf (stderr, "Erroneous target %s\n", target);
      exit (1);
    }
  unresolved = gvm_hosts_resolve (hosts);
  while (unresolved)
    {
      g_warning ("Couldn't resolve hostname '%s'", (char *) unresolved->data);
      unresolved = unresolved->next;
    }
  g_slist_free_full (unresolved, g_free);
  g_free (target);

  // for absolute and relative paths
  add_nasl_inc_dir ("");
  if (include_dir != NULL)
    {
      add_nasl_inc_dir (include_dir);
    }

  prefs_config (config_file ? config_file : OPENVAS_CONF);

  if (prefs_get ("vendor_version") != NULL)
    vendor_version_set (prefs_get ("vendor_version"));

  if (port_range != NULL)
    {
      prefs_set ("port_range", port_range);
      g_free (port_range);
    }

  if (with_safe_checks)
    prefs_set ("safe_checks", "yes");

  pos = 0; // Append the item on the right side of the list
  while ((host = gvm_hosts_next (hosts)))
    {
      struct in6_addr ip6;
      kb_t kb;
      int rc;
      int process_id;

      if (prefs_get_bool ("expand_vhosts"))
        gvm_host_add_reverse_lookup (host);
      gvm_vhosts_exclude (host, prefs_get ("exclude_hosts"));
      gvm_host_get_addr6 (host, &ip6);
      rc = kb_new (&kb, prefs_get ("db_address") ? prefs_get ("db_address")
                                                 : KB_PATH_DEFAULT);
      if (rc)
        exit (1);

      set_main_kb (kb);
      process_id = getpid ();

      script_infos = init (&ip6, host->vhosts, kb);
      for (int i = 0; nasl_filenames[i] != NULL; i++)
        {
          script_infos->name = nasl_filenames[i];
          if (both_modes || with_safe_checks)
            {
              nvti_t *nvti = parse_script_infos (script_infos);
              if (!nvti)
                {
                  err++;
                  continue;
                }
              else if (with_safe_checks
                       && !nvti_category_is_safe (nvti_category (nvti)))
                {
                  printf ("%s isn't safe\n", nasl_filenames[i]);
                  nvti_free (nvti);
                  err++;
                  continue;
                }
              nvti_free (nvti);
            }
          if (kb_values)
            {
              gchar **kb_values_aux = kb_values;
              while (*kb_values_aux)
                {
                  gchar **splits = g_strsplit (*kb_values_aux, "=", -1);
                  if (splits[2] || !splits[1])
                    {
                      fprintf (stderr, "Erroneous --kb entry %s\n",
                               *kb_values_aux);
                      exit (1);
                    }
                  kb_item_add_str_unique (kb, splits[0], splits[1], 0, pos);
                  kb_values_aux++;
                  g_strfreev (splits);
                }
            }

          if (exec_nasl_script (script_infos, mode) < 0)
            err++;

          if (process_id != getpid ())
            exit (0);
        }
      g_free (script_infos->globals);
      g_free (script_infos);

      kb_delete (kb);
    }

  if (nasl_trace_fp != NULL)
    fflush (nasl_trace_fp);

  gvm_hosts_free (hosts);
  return err;
}
