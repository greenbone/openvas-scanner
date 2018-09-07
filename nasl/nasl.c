/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2005 Tenable Network Security
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

 /**
  * @file
  * Source of the standalone NASL interpreter of OpenVAS.
  */

#include <errno.h>              /* for errno */
#include <signal.h>             /* for SIGINT */
#include <string.h>             /* for strlen */
#include <stdlib.h>             /* for exit */
#include <unistd.h>             /* for geteuid */
#include <libssh/libssh.h>      /* for ssh_version */
#include <gnutls/gnutls.h>      /* for gnutls_check_version */
#include <sys/wait.h>

#include <gcrypt.h>             /* for gcry_control */
#include <glib.h>
#include <gpgme.h>              /* for gpgme_check_version */

#include <gvm/base/hosts.h>     /* for gvm_hosts_* and gvm_host_* */
#include <gvm/base/networking.h> /* for gvm_source_iface_init */
#include <gvm/base/nvti.h>
#include <gvm/base/prefs.h>     /* for prefs_get */
#include <gvm/util/kb.h>        /* for kb_new */

#include "../misc/nvt_categories.h"
#include "../misc/network.h"
#include "../misc/vendorversion.h"

#include "nasl.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

extern char *nasl_version (void);


void
sighandler ()
{
  exit (0);
}

static void
my_gnutls_log_func (int level, const char *text)
{
  fprintf (stderr, "[%d] (%d) %s", getpid (), level, text);
  if (*text && text[strlen (text) -1] != '\n')
    putc ('\n', stderr);
}

struct script_infos *
init (struct in6_addr *ip, GSList *vhosts, kb_t kb)
{
  struct script_infos *infos = g_malloc0 (sizeof (struct script_infos));

  prefs_set ("checks_read_timeout", "5");
  infos->standalone = 1;
  infos->key = kb;
  infos->ip = ip;
  infos->vhosts = vhosts;
  if (prefs_get_bool ("test_empty_vhost"))
    {
      gvm_vhost_t *vhost = gvm_vhost_new
                            (addr6_as_str (ip), g_strdup ("IP-address"));
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
 * @brief Main of the standalone nasl interpretor.
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
  int mode = 0, err = 0;
  extern int global_nasl_debug;

  static gboolean display_version = FALSE;
  static gboolean nasl_debug = FALSE;
  static gboolean description_only = FALSE;
  static gboolean both_modes = FALSE;
  static gboolean parse_only = FALSE;
  static gboolean do_lint = FALSE;
  static gchar *trace_file = NULL;
  static gchar *config_file = NULL;
  static gchar *source_iface = NULL;
  static gchar *vendor_version_string = NULL;
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
     "Source network interface for established connections.",
     "<iface_name>"},
    {"vendor-version", '\0', 0, G_OPTION_ARG_STRING, &vendor_version_string,
     "Use <string> as vendor version.", "<string>"},
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
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &nasl_filenames,
     "Absolute path to one or more nasl scripts", "NASL_FILE..."},
    {NULL, 0, 0, 0, NULL, NULL, NULL}
  };

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
      printf ("Copyright (C) 2013 Greenbone Networks GmbH\n\n");
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
  if (with_safe_checks)
    prefs_set ("safe_checks", "yes");

  gcrypt_init();
  openvas_SSL_init ();
  if (!nasl_filenames)
    {
      fprintf (stderr, "Error. No input file(s) specified !\n");
      exit (1);
    }

  if (vendor_version_string)
    vendor_version_set (vendor_version_string);

#ifndef _CYGWIN_
  if (!(mode & (NASL_EXEC_PARSE_ONLY | NASL_LINT)) && geteuid ())
    {
      fprintf (stderr, "** WARNING : packet forgery will not work\n");
      fprintf (stderr, "** as NASL is not running as root\n");
    }
  signal (SIGINT, sighandler);
  signal (SIGTERM, sighandler);
  signal (SIGPIPE, SIG_IGN);
#endif

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
  gvm_hosts_resolve (hosts);
  g_free (target);

  // for absolute and relative paths
  add_nasl_inc_dir ("");
  if (include_dir != NULL)
    {
      add_nasl_inc_dir (include_dir);
    }

  prefs_config (config_file ?: OPENVASSD_CONF);
  while ((host = gvm_hosts_next (hosts)))
    {
      struct in6_addr ip6;
      kb_t kb;
      int rc, i = 0;

      gvm_host_add_reverse_lookup (host);
      gvm_host_get_addr6 (host, &ip6);
      rc = kb_new (&kb, prefs_get ("db_address") ?: KB_PATH_DEFAULT);
      if (rc)
        exit (1);

      script_infos = init (&ip6, host->vhosts, kb);
      while (nasl_filenames[i])
        {
          pid_t pid;

          script_infos->name = nasl_filenames[i];
          if (both_modes || with_safe_checks)
            {
              nvti_t *nvti = parse_script_infos (script_infos);
              if (!nvti)
                {
                  err++;
                  i++;
                  continue;
                }
              else if (with_safe_checks
                       && !nvti_category_is_safe (nvti_category (nvti)))
                {
                  printf ("%s isn't safe\n", nasl_filenames[i]);
                  nvti_free (nvti);
                  err++;
                  i++;
                  continue;
                }
              nvti_free (nvti);
            }
          if (kb_values)
            {
              while (*kb_values)
                {
                  gchar **splits = g_strsplit (*kb_values, "=", -1);
                  if (splits[2] || !splits[1])
                    {
                      fprintf (stderr, "Erroneous --kb entry %s\n", *kb_values);
                      exit (1);
                    }
                  kb_item_add_str (kb, splits[0], splits[1], 0);
                  kb_values++;
                  g_strfreev (splits);
                }
            }

          if ((pid = fork ()) == 0)
            {
              if (exec_nasl_script (script_infos, mode) < 0)
                exit (1);
              else
                exit (0);
            }
          else if (pid < 0)
            {
              fprintf (stderr, "fork(): %s\n", strerror (errno));
              exit (1);
            }
          else
            {
              int status;
              waitpid (pid, &status, 0);
              if (status)
                err++;
            }
          i++;
        }
      kb_delete (kb);
    }

  if (nasl_trace_fp != NULL)
    fflush (nasl_trace_fp);

  gvm_hosts_free (hosts);
  return err;
}
