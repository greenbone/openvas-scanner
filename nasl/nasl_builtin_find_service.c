/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define SMART_TCP_RW

#include "../misc/kb_cache.h"  /* for get_main_kb */
#include "../misc/network.h"   /* for get_encaps_through */
#include "../misc/plugutils.h" /* for OPENVAS_ENCAPS_IP */
#include "nasl_builtin_plugins.h"
#include "nasl_lex_ctxt.h"

#include <ctype.h> /* for tolower() */
#include <errno.h> /* for errno() */
#include <glib.h>
#include <gvm/util/mqtt.h>
#include <gvm/util/nvticache.h>
#include <regex.h>     /* for regex_t */
#include <signal.h>    /* for signal() */
#include <stdio.h>     /* for snprintf() */
#include <stdlib.h>    /* for atoi() */
#include <string.h>    /* for strstr() */
#include <sys/time.h>  /* for gettimeofday() */
#include <sys/types.h> /* for waitpid() */
#include <sys/wait.h>  /* for waitpid() */
#include <unistd.h>    /* for usleep() */

#define CERT_FILE "SSL certificate : "
#define KEY_FILE "SSL private key : "
#define PEM_PASS "PEM password : "
#define CA_FILE "CA file : "
#define CNX_TIMEOUT_PREF "Network connection timeout : "
#define RW_TIMEOUT_PREF "Network read/write timeout : "
#define WRAP_TIMEOUT_PREF "Wrapped service read timeout : "
#define TEST_SSL_PREF "Test SSL based services"

#define NUM_CHILDREN "Number of connections done in parallel : "

// we cannot use the GNU ones due to number mismatch
#define TLS_PRIME_UNACCEPTABLE -2
#define TLS_FATAL_ALERT -3

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

const char *oid;

static void
register_service (struct script_infos *desc, int port, const char *proto)
{
  char k[265];

  /* Old "magical" key set */
  snprintf (k, sizeof (k), "Services/%s", proto);
  /* Do NOT use plug_replace_key! */
  plug_set_key (desc, k, ARG_INT, GSIZE_TO_POINTER (port));

  /*
   * 2002-08-24 - MA - My new key set There is a problem: if
   * register_service is called twice for a port, e.g. first with HTTP
   * and then with SWAT, the plug_get_key function will fork. This
   * would not happen if we registered a boolean (i.e. "known") instead
   * of the name of the protocol. However, we *need* this name for some
   * scripts. We'll just have to keep in mind that a fork is
   * possible...
   *
   * 2005-06-01 - MA - with plug_replace_key the problem is solved, but I
   * wonder if this is so great...
   */
  snprintf (k, sizeof (k), "Known/tcp/%d", port);
  plug_replace_key (desc, k, ARG_STRING, (char *) proto);
}

/**
 * @brief Compares string with the regular expression.
 *        Null characters in buffer are replaced by 'x'.
 * @param[in] string  String to compare
 * @param[in] pattern regular expression
 *
 * @return 1 if match, 0 if not match.
 */
static int
regex_match (char *string, char *pattern)
{
  regex_t re;
  int ret = 1;

  if (regcomp (&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE))
    ret = 0;
  if (regexec (&re, string, 0, NULL, 0))
    ret = 0;

  regfree (&re);
  return ret;
}

static void
mark_chargen_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "chargen");
  post_log (oid, desc, port, "Chargen is running on this port");
}

static void
mark_echo_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "echo");
  post_log (oid, desc, port, "An echo server is running on this port");
}

static void
mark_ncacn_http_server (struct script_infos *desc, int port, char *buffer)
{
  char ban[256];
  if (port == 593)
    {
      register_service (desc, port, "http-rpc-epmap");
      snprintf (ban, sizeof (ban), "http-rpc-epmap/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
    }
  else
    {
      register_service (desc, port, "ncacn_http");
      snprintf (ban, sizeof (ban), "ncacn_http/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
    }
}

static void
mark_vnc_server (struct script_infos *desc, int port, char *buffer)
{
  char ban[512];
  register_service (desc, port, "vnc");
  snprintf (ban, sizeof (ban), "vnc/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
}

static void
mark_nntp_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "nntp");
  snprintf (ban, sizeof (ban), "nntp/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "An NNTP server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_swat_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "swat");
}

static void
mark_vqserver (struct script_infos *desc, int port)
{
  register_service (desc, port, "vqServer-admin");
}

static void
mark_mldonkey (struct script_infos *desc, int port)
{
  char ban[512];
  register_service (desc, port, "mldonkey");
  snprintf (ban, sizeof (ban), "A mldonkey server is running on this port");
  post_log (oid, desc, port, ban);
}

static void
mark_http_server (struct script_infos *desc, int port, unsigned char *buffer,
                  int trp)
{
  char ban[512];
  register_service (desc, port, "www");
  snprintf (ban, sizeof (ban), "www/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A web server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_locked_adsubtract_server (struct script_infos *desc, int port,
                               unsigned char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "AdSubtract");
  snprintf (ban, sizeof (ban), "AdSubtract/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban),
            "A (locked) AdSubtract server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_gopher_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "gopher");
  post_log (oid, desc, port, "A gopher server is running on this port");
}

static void
mark_rmserver (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "realserver");
  snprintf (ban, sizeof (ban), "realserver/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);

  snprintf (ban, sizeof (ban), "A RealMedia server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_smtp_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "smtp");
  snprintf (ban, sizeof (ban), "smtp/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);

  if (strstr (buffer, " postfix"))
    plug_replace_key (desc, "smtp/postfix", ARG_INT, (void *) 1);

  {
    char *report = g_malloc0 (255 + strlen (buffer));
    char *t = strchr (buffer, '\n');
    if (t)
      t[0] = 0;
    snprintf (report, 255 + strlen (buffer),
              "An SMTP server is running on this port%s\n\
Here is its banner : \n%s",
              get_encaps_through (trp), buffer);
    post_log (oid, desc, port, report);
    g_free (report);
  }
}

static void
mark_snpp_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512], *report, *t;
  register_service (desc, port, "snpp");
  snprintf (ban, sizeof (ban), "snpp/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);

  report = g_malloc0 (255 + strlen (buffer));
  t = strchr (buffer, '\n');
  if (t != NULL)
    *t = '\0';
  snprintf (report, 255 + strlen (buffer),
            "An SNPP server is running on this port%s\n\
Here is its banner : \n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, report);
  g_free (report);
}

static void
mark_ftp_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  register_service (desc, port, "ftp");

  if (buffer != NULL)
    {
      char ban[255];

      snprintf (ban, sizeof (ban), "ftp/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
    }
  if (buffer != NULL)
    {
      char *report = g_malloc0 (255 + strlen (buffer));
      char *t = strchr (buffer, '\n');
      if (t != NULL)
        t[0] = '\0';
      snprintf (report, 255 + strlen (buffer),
                "An FTP server is running on this port%s.\n\
Here is its banner : \n%s",
                get_encaps_through (trp), buffer);
      post_log (oid, desc, port, report);
      g_free (report);
    }
  else
    {
      char report[255];
      snprintf (report, sizeof (report),
                "An FTP server is running on this port%s.",
                get_encaps_through (trp));
      post_log (oid, desc, port, report);
    }
}

static void
mark_ssh_server (struct script_infos *desc, int port, char *buffer)
{
  register_service (desc, port, "ssh");
  while ((buffer[strlen (buffer) - 1] == '\n')
         || (buffer[strlen (buffer) - 1] == '\r'))
    buffer[strlen (buffer) - 1] = '\0';
  post_log (oid, desc, port, "An ssh server is running on this port");
}

static void
mark_http_proxy (struct script_infos *desc, int port, int trp)
{
  char ban[512];
  /* the banner is in www/banner/port */
  register_service (desc, port, "http_proxy");
  snprintf (ban, sizeof (ban), "An HTTP proxy is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_pop_server (struct script_infos *desc, int port, char *buffer)
{
  char *c = strchr (buffer, '\n');
  char ban[512];
  char *buffer2;
  unsigned int i;

  if (c)
    c[0] = 0;
  buffer2 = g_strdup (buffer);
  for (i = 0; i < strlen (buffer2); i++)
    buffer2[i] = tolower (buffer2[i]);
  if (!strcmp (buffer2, "+ok"))
    {
      register_service (desc, port, "pop1");
      snprintf (ban, sizeof (ban), "pop1/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
    }
  else if (strstr (buffer2, "pop2"))
    {
      register_service (desc, port, "pop2");
      snprintf (ban, sizeof (ban), "pop2/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
      post_log (oid, desc, port, "a pop2 server is running on this port");
    }
  else
    {
      register_service (desc, port, "pop3");
      snprintf (ban, sizeof (ban), "pop3/banner/%d", port);
      plug_replace_key (desc, ban, ARG_STRING, buffer);
      post_log (oid, desc, port, "A pop3 server is running on this port");
    }
  g_free (buffer2);
}

static void
mark_imap_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "imap");
  snprintf (ban, sizeof (ban), "imap/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  {
    snprintf (ban, sizeof (ban), "An IMAP server is running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_auth_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "auth");
  post_log (oid, desc, port, "An identd server is running on this port");
}

/*
 * Postgres, MySQL & CVS pserver detection by Vincent Renardias
 * <vincent@strongholdnet.com>
 */
static void
mark_postgresql (struct script_infos *desc, int port)
{
  register_service (desc, port, "postgresql");
  /* if (port != 5432) */
  post_log (oid, desc, port, "A PostgreSQL server is running on this port");
}

static void
mark_sphinxql (struct script_infos *desc, int port)
{
  register_service (desc, port, "sphinxql");
  post_log (oid, desc, port,
            "A Sphinx search server (MySQL listener) "
            "seems to be running on this port");
}

static void
mark_mysql (struct script_infos *desc, int port)
{
  register_service (desc, port, "mysql");
  /* if (port != 3306) */
  post_log (oid, desc, port, "A MySQL server is running on this port");
}

static void
mark_cvspserver (struct script_infos *desc, int port)
{
  register_service (desc, port, "cvspserver");
  /* if (port != 2401) */
  post_log (oid, desc, port, "A CVS pserver server is running on this port");
}

static void
mark_cvsupserver (struct script_infos *desc, int port)
{
  register_service (desc, port, "cvsup");
  post_log (oid, desc, port, "A CVSup server is running on this port");
}

static void
mark_cvslockserver (struct script_infos *desc, int port)
{
  register_service (desc, port, "cvslockserver");
  /* if (port != 2401) */
  post_log (oid, desc, port, "A CVSLock server server is running on this port");
}

static void
mark_rsync (struct script_infos *desc, int port)
{
  register_service (desc, port, "rsync");
  post_log (oid, desc, port, "A rsync server is running on this port");
}

static void
mark_wild_shell (struct script_infos *desc, int port)
{
  register_service (desc, port, "wild_shell");

  post_alarm (
    oid, desc, port,
    "A shell seems to be running on this port ! (this is a possible backdoor)",
    NULL);
}

static void
mark_telnet_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "telnet");
  {
    snprintf (ban, sizeof (ban),
              "A telnet server seems to be running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_gnome14_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "gnome14");
  {
    snprintf (ban, sizeof (ban),
              "A Gnome 1.4 server seems to be running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_eggdrop_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "eggdrop");
  {
    snprintf (
      ban, sizeof (ban),
      "An eggdrop IRC bot seems to be running a control server on this port%s",
      get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_netbus_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "netbus");
  post_alarm (oid, desc, port, "NetBus is running on this port", NULL);
}

static void
mark_linuxconf (struct script_infos *desc, int port, unsigned char *buffer)
{
  char ban[512];
  register_service (desc, port, "linuxconf");
  snprintf (ban, sizeof (ban), "linuxconf/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  post_log (oid, desc, port, "Linuxconf is running on this port");
}

static void
mark_finger_server (struct script_infos *desc, int port, int trp)
{
  char tmp[256];

  register_service (desc, port, "finger");

  snprintf (tmp, sizeof (tmp),
            "A finger server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_vtun_server (struct script_infos *desc, int port, unsigned char *banner,
                  int trp)
{
  char tmp[255];

  snprintf (tmp, sizeof (tmp), "vtun/banner/%d", port);
  plug_replace_key (desc, tmp, ARG_STRING, (char *) banner);

  register_service (desc, port, "vtun");

  if (banner == NULL)
    {
      snprintf (tmp, sizeof (tmp),
                "A VTUN server seems to be running on this port%s",
                get_encaps_through (trp));
    }
  else
    snprintf (tmp, sizeof (tmp),
              "A VTUN server seems to be running on this port%s\n"
              "Here is its banner:\n%s\n",
              get_encaps_through (trp), banner);

  post_log (oid, desc, port, tmp);
}

static void
mark_uucp_server (struct script_infos *desc, int port, unsigned char *banner,
                  int trp)
{
  char tmp[255];

  snprintf (tmp, sizeof (tmp), "uucp/banner/%d", port);
  plug_replace_key (desc, tmp, ARG_STRING, (char *) banner);

  register_service (desc, port, "uucp");

  snprintf (tmp, sizeof (tmp),
            "An UUCP server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_lpd_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "lpd");
  snprintf (tmp, sizeof (tmp),
            "A LPD server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

/* http://www.lysator.liu.se/lyskom/lyskom-server/ */
static void
mark_lyskom_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "lyskom");
  snprintf (tmp, sizeof (tmp),
            "A LysKOM server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

/* http://www.emailman.com/ph/ */
static void
mark_ph_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "ph");
  snprintf (tmp, sizeof (tmp), "A PH server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_time_server (struct script_infos *desc, int port, int trp)
{
  char tmp[256];

  register_service (desc, port, "time");
  snprintf (tmp, sizeof (tmp),
            "A time server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_ens_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];
  register_service (desc, port, "iPlanetENS");

  snprintf (tmp, sizeof (tmp),
            "An iPlanet ENS (Event Notification Server) seems to be running on "
            "this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_citrix_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "citrix");
  snprintf (tmp, sizeof (tmp),
            "a Citrix server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, tmp);
}

static void
mark_giop_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "giop");
  snprintf (tmp, sizeof (tmp),
            "A GIOP-enabled service is running on this port%s",
            get_encaps_through (trp));

  post_log (oid, desc, port, tmp);
}

static void
mark_exchg_routing_server (struct script_infos *desc, int port, char *buffer,
                           int trp)
{
  char ban[255];

  register_service (desc, port, "exchg-routing");
  snprintf (ban, sizeof (ban), "exchg-routing/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  {
    snprintf (ban, sizeof (ban),
              "A Microsoft Exchange routing server is running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_tcpmux_server (struct script_infos *desc, int port, int trp)
{
  char msg[255];

  register_service (desc, port, "tcpmux");
  snprintf (msg, sizeof (msg),
            "A tcpmux server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, msg);
}

static void
mark_BitTorrent_server (struct script_infos *desc, int port, int trp)
{
  char msg[255];

  register_service (desc, port, "BitTorrent");
  snprintf (msg, sizeof (msg),
            "A BitTorrent server seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, msg);
}

static void
mark_smux_server (struct script_infos *desc, int port, int trp)
{
  char msg[255];

  register_service (desc, port, "smux");
  snprintf (msg, sizeof (msg),
            "A SNMP Multiplexer (smux) seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, msg);
}

/*
 * LISa is the LAN Information Server that comes
 * with KDE in Mandrake Linux 9.0. Apparently
 * it usually runs on port 7741.
 */
static void
mark_LISa_server (struct script_infos *desc, int port, int trp)
{
  char tmp[255];

  register_service (desc, port, "LISa");
  snprintf (tmp, sizeof (tmp), "A LISa daemon is running on this port%s",
            get_encaps_through (trp));

  post_log (oid, desc, port, tmp);
}

/*
 * msdtc is Microsoft Distributed Transaction Coordinator
 *
 * Thanks to jtant@shardwebdesigns.com for reporting it
 *
 */
static void
mark_msdtc_server (struct script_infos *desc, int port)
{
  register_service (desc, port, "msdtc");
  post_log (oid, desc, port, "A MSDTC server is running on this port");
}

static void
mark_pop3pw_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];
  register_service (desc, port, "pop3pw");
  snprintf (ban, sizeof (ban), "pop3pw/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A pop3pw server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * whois++ server, thanks to Adam Stephens -
 * http://roads.sourceforge.net/index.php
 *
 * 00: 25 20 32 32 30 20 4c 55 54 20 57 48 4f 49 53 2b    % 220 LUT WHOIS+
 * 10: 2b 20 73 65 72 76 65 72 20 76 32 2e 31 20 72 65    + server v2.1 re
 * 20: 61 64 79 2e 20 20 48 69 21 0d 0a 25 20 32 30 30    ady.  Hi!..% 200
 * 30: 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 47     Searching for G
 * 40: 45 54 26 2f 26 48 54 54 50 2f 31 2e 30 0d 0a 25    ET&/&HTTP/1.0..%
 * 50: 20 35 30 30 20 45 72 72 6f 72 20 70 61 72 73 69     500 Error parsi
 * 60: 6e 67 20 42 6f 6f 6c 65 61 6e 20 65 78 70 72 65    ng Boolean expre
 * 70: 73 73 69 6f 6e 0d 0a                               ssion..
 */

static void
mark_whois_plus2_server (struct script_infos *desc, int port, char *buffer,
                         int trp)
{
  char ban[255];
  register_service (desc, port, "whois++");
  snprintf (ban, sizeof (ban), "whois++/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A whois++ server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * mon server, thanks to Rafe Oxley <rafe.oxley@moving-edge.net>
 * (http://www.kernel.org/software/mon/)
 *
 * An unknown server is running on this port. If you know what it is, please
 * send this banner to the development team: 00: 35 32 30 20 63 6f 6d 6d 61 6e
 * 64 20 63 6f 75 6c 520 command coul 10: 64 20 6e 6f 74 20 62 65 20 65 78 65 63
 * 75 74 65 d not be execute 20: 64 0a d.
 */
static void
mark_mon_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[255];
  register_service (desc, port, "mon");
  snprintf (ban, sizeof (ban), "mon/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A mon server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_fw1 (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[255];
  register_service (desc, port, "cpfw1");
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban),
            "A CheckPoint FW1 SecureRemote or FW1 FWModule server is running "
            "on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From: Mike Gitarev [mailto:mik@bofh.lv]
 *
 * http://www.psychoid.lam3rz.de
 * 00: 3a 57 65 6c 63 6f 6d 65 21 70 73 79 42 4e 43 40    :Welcome!psyBNC@
 * 10: 6c 61 6d 33 72 7a 2e 64 65 20 4e 4f 54 49 43 45    lam3rz.de NOTICE
 * 20: 20 2a 20 3a 70 73 79 42 4e 43 32 2e 33 2e 31 2d     * :psyBNC2.3.1-
 * 30: 37 0d 0a                                           7..
 */

static void
mark_psybnc (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[255];
  register_service (desc, port, "psybnc");
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A PsyBNC IRC proxy is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From "Russ Paton" <russell.paton@blueyonder.co.uk>
 *
 * 00: 49 43 59 20 32 30 30 20 4f 4b 0d 0a 69 63 79 2d ICY 200 OK..icy-
 * 10: 6e 6f 74 69 63 65 31 3a 3c 42 52 3e 54 68 69 73 notice1:<BR>This
 * 20: 20 73 74 72 65 61 6d 20 72 65 71 75 69 72 65 73 stream requires
 */
static void
mark_shoutcast_server (struct script_infos *desc, int port, char *buffer,
                       int trp)
{
  char ban[255];
  register_service (desc, port, "shoutcast");
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban), "A shoutcast server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From "Hendrickson, Chris" <chendric@qssmeds.com>
 * 00: 41 64 73 47 6f 6e 65 20 42 6c 6f 63 6b 65 64 20    AdsGone Blocked
 * 10: 48 54 4d 4c 20 41 64                               HTML Ad
 */

static void
mark_adsgone (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[255];
  register_service (desc, port, "adsgone");
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (
    ban, sizeof (ban),
    "An AdsGone (a popup banner blocking server) is running on this port%s",
    get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * Sig from  harm vos <h.vos@fwn.rug.nl> :
 *
 * 00: 2a 20 41 43 41 50 20 28 49 4d 50 4c 45 4d 45 4e    * ACAP (IMPLEMEN 10:
 * 54 41 54 49 4f 4e 20 22 43 6f 6d 6d 75 6e 69 47    TATION "CommuniG 20: 61
 * 74 65 20 50 72 6f 20 41 43 41 50 20 34 2e 30    ate Pro ACAP 4.0 30: 62 39
 * 22 29 20 28 53 54 41 52 54 54 4c 53 29 20    b9") (STARTTLS) 40: 28 53 41
 * 53 4c 20 22 4c 4f 47 49 4e 22 20 22 50    (SASL "LOGIN" "P 50: 4c 41 49 4e
 * 22 20 22 43 52 41 4d 2d 4d 44 35 22    LAIN" "CRAM-MD5" 60: 20 22 44 49 47
 * 45 53 54 2d 4d 44 35 22 20 22 4e     "DIGEST-MD5" "N 70: 54 4c 4d 22 29 20
 * 28 43 4f 4e 54 45 58 54 4c 49    TLM") (CONTEXTLI 80: 4d 49 54 20 22 32 30
 * 30 22 29 0d 0a                MIT "200")..
 *
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address
 * books).
 */
static void
mark_acap_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[255];
  register_service (desc, port, "acap");
  snprintf (ban, sizeof (ban), "acap/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  {
    snprintf (ban, sizeof (ban), "An ACAP server is running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

/*
 * Sig from Cedric Foll <cedric.foll@ac-rouen.fr>
 *
 *
 * 00: 53 6f 72 72 79 2c 20 79 6f 75 20 28 31 37 32 2e Sorry, you (172. 10: 33
 * 30 2e 31 39 32 2e 31 30 33 29 20 61 72 65 20 30.192.103)are 20: 6e 6f 74
 * 20 61 6d 6f 6e 67 20 74 68 65 20 61 6c not among the al 30: 6c 6f 77 65 64
 * 20 68 6f 73 74 73 2e 2e 2e 0a lowed hosts....
 *
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address
 * books).
 */
static void
mark_nagiosd_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "nagiosd");
  snprintf (ban, sizeof (ban), "A nagiosd server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * Sig from  Michael Löffler <nimrod@n1mrod.de>
 *
 * 00: 5b 54 53 5d 0a 65 72 72 6f 72 0a                   [TS].error.
 *
 * That's Teamspeak2 rc2 Server - http://www.teamspeak.org/
 */
static void
mark_teamspeak2_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "teamspeak2");
  snprintf (ban, sizeof (ban), "A teamspeak2 server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * Sig from <Gary.Crowell@experian.com>
 *
 *
 *
 *
 * 00: 4c 61 6e 67 75 61 67 65 20 72 65 63 65 69 76 65    Language receive 10:
 * 64 20 66 72 6f 6d 20 63 6c 69 65 6e 74 3a 20 47    d from client: G 20: 45
 * 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 53    ET / HTTP/1.0..S 30: 65 74
 * 6c 6f 63 61 6c 65 3a 20 0a                   etlocale: .
 *
 * Port 9090 is for WEBSM, the GUI SMIT tool that AIX RMC  (port 657) is
 * configured and used with.  (AIX Version 5.1)
 */
static void
mark_websm_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "websm");
  snprintf (ban, sizeof (ban), "A WEBSM server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From Gary Crowell :
 * 00: 43 4e 46 47 41 50 49                               CNFGAPI
 */
static void
mark_ofa_express_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "ofa_express");
  snprintf (ban, sizeof (ban),
            "An OFA/Express server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From Pierre Abbat <phma@webjockey.net> 00: 53 75 53 45 20 4d 65 74 61 20
 * 70 70 70 64 20 28 SuSE Meta pppd ( 10: 73 6d 70 70 70 64 29 2c 20 56 65 72
 * 73 69 6f 6e    smpppd), Version 20: 20 30 2e 37 38 0d 0a
 * 0.78..
 */
static void
mark_smppd_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "smppd");
  snprintf (ban, sizeof (ban),
            "A SuSE Meta pppd server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From DaLiV <daliv@apollo.lv
 *
 * 00: 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d 43 4f 4d 4d ERR UNKNOWN-COMM
 * 10: 41 4e 44 0a 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d AND.ERR UNKNOWN-
 * 20: 43 4f 4d 4d 41 4e 44 0a COMMAND.
 */
static void
mark_upsmon_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "upsmon");
  snprintf (ban, sizeof (ban),
            "An upsd/upsmon server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/*
 * From Andrew Yates <pilot1_ace@hotmail.com>
 *
 * 00: 63 6f 6e 6e 65 63 74 65 64 2e 20 31 39 3a 35 31    connected. 19:51
 * 10: 20 2d 20 4d 61 79 20 32 35 2c 20 32 30 30 33 2c     - May 25, 2003,
 * 20: 20 53 75 6e 64 61 79 2c 20 76 65 72 3a 20 4c 65     Sunday, ver: Le
 * 30: 67 65 6e 64 73 20 32 2e 31                         gends 2.1
 */
static void
mark_sub7_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "sub7");
  snprintf (ban, sizeof (ban), "The Sub7 trojan is running on this port%s",
            get_encaps_through (trp));
  post_alarm (oid, desc, port, ban, NULL);
}

/*
 * From "Alex Lewis" <alex@sgl.org.au>
 *
 *  00: 53 50 41 4d 44 2f 31 2e 30 20 37 36 20 42 61 64    SPAMD/1.0 76 Bad
 *  10: 20 68 65 61 64 65 72 20 6c 69 6e 65 3a 20 47 45     header line: GE
 *  20: 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0d 0a       T /
 */
static void
mark_spamd_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "spamd");
  snprintf (ban, sizeof (ban),
            "a spamd server (part of spamassassin) is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/* Thanks to Mike Blomgren */
static void
mark_quicktime_streaming_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "quicktime-streaming-server");
  snprintf (ban, sizeof (ban),
            "a quicktime streaming server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/* Thanks to Allan <als@bpal.com> */
static void
mark_dameware_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "dameware");
  snprintf (ban, sizeof (ban), "a dameware server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_stonegate_auth_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "SG_ClientAuth");
  snprintf (ban, sizeof (ban),
            "a StoneGate authentication server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_listserv_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "listserv");
  {
    snprintf (ban, sizeof (ban),
              "A LISTSERV daemon seems to be running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

static void
mark_fssniffer (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "FsSniffer");
  {
    snprintf (ban, sizeof (ban),
              "A FsSniffer backdoor seems to be running on this port%s",
              get_encaps_through (trp));
    post_alarm (oid, desc, port, ban, NULL);
  }
}

static void
mark_remote_nc_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "RemoteNC");
  {
    snprintf (ban, sizeof (ban),
              "A RemoteNC backdoor seems to be running on this port%s",
              get_encaps_through (trp));
    post_log (oid, desc, port, ban);
  }
}

/* Do not use register_service for unknown and wrapped services! */

static void
mark_wrapped_svc (struct script_infos *desc, int port, int delta)
{
  char msg[256];

  snprintf (msg, sizeof (msg),
            "The service closed the connection after %d seconds "
            "without sending any data\n"
            "It might be protected by some TCP wrapper\n",
            delta);
  post_log (oid, desc, port, msg);
  /* Do NOT use plug_replace_key! */
  plug_set_key (desc, "Services/wrapped", ARG_INT, GSIZE_TO_POINTER (port));
}

static const char *
port_to_name (int port)
{
  /* Note: only includes services that are recognized by this plugin! */
  switch (port)
    {
    case 7:
      return "Echo";
    case 19:
      return "Chargen";
    case 21:
      return "FTP";
    case 22:
      return "SSH";
    case 23:
      return "Telnet";
    case 25:
      return "SMTP";
    case 37:
      return "Time";
    case 70:
      return "Gopher";
    case 79:
      return "Finger";
    case 80:
      return "HTTP";
    case 98:
      return "Linuxconf";
    case 109:
      return "POP2";
    case 110:
      return "POP3";
    case 113:
      return "AUTH";
    case 119:
      return "NNTP";
    case 143:
      return "IMAP";
    case 220:
      return "IMAP3";
    case 443:
      return "HTTPS";
    case 465:
      return "SMTPS";
    case 563:
      return "NNTPS";
    case 593:
      return "Http-Rpc-Epmap";
    case 873:
      return "Rsyncd";
    case 901:
      return "SWAT";
    case 993:
      return "IMAPS";
    case 995:
      return "POP3S";
    case 1109:
      return "KPOP"; /* ? */
    case 2309:
      return "Compaq Management Server";
    case 2401:
      return "CVSpserver";
    case 3128:
      return "Squid";
    case 3306:
      return "MySQL";
    case 5000:
      return "VTUN";
    case 5432:
      return "Postgres";
    case 8080:
      return "HTTP-Alt";
    }
  return NULL;
}

static void
mark_unknown_svc (struct script_infos *desc, int port,
                  const unsigned char *banner, int trp)
{
  char tmp[1600], *norm = NULL;

  /* Do NOT use plug_replace_key! */
  plug_set_key (desc, "Services/unknown", ARG_INT, GSIZE_TO_POINTER (port));
  snprintf (tmp, sizeof (tmp), "unknown/banner/%d", port);
  plug_replace_key (desc, tmp, ARG_STRING, (char *) banner);

  norm = (char *) port_to_name (port);
  *tmp = '\0';
  if (norm != NULL)
    {
      snprintf (tmp, sizeof (tmp),
                "An unknown service is running on this port%s.\n"
                "It is usually reserved for %s",
                get_encaps_through (trp), norm);
    }
  if (*tmp != '\0')
    post_log (oid, desc, port, tmp);
}

static void
mark_gnuserv (struct script_infos *desc, int port)
{
  register_service (desc, port, "gnuserv");
  post_log (oid, desc, port, "gnuserv is running on this port");
}

static void
mark_iss_realsecure (struct script_infos *desc, int port)
{
  register_service (desc, port, "issrealsecure");
  post_log (oid, desc, port, "ISS RealSecure is running on this port");
}

static void
mark_vmware_auth (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];

  register_service (desc, port, "vmware_auth");

  snprintf (ban, sizeof (ban),
            "A VMWare authentication daemon is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

static void
mark_interscan_viruswall (struct script_infos *desc, int port, char *buffer,
                          int trp)
{
  char ban[512];

  register_service (desc, port, "interscan_viruswall");

  snprintf (ban, sizeof (ban),
            "An interscan viruswall is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

static void
mark_ppp_daemon (struct script_infos *desc, int port, int trp)
{
  char ban[512];

  register_service (desc, port, "pppd");

  snprintf (ban, sizeof (ban), "A PPP daemon is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_zebra_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];

  register_service (desc, port, "zebra");
  snprintf (ban, sizeof (ban), "zebra/banner/%d", port);
  plug_replace_key (desc, ban, ARG_STRING, buffer);
  snprintf (ban, sizeof (ban),
            "A zebra daemon (bgpd or zebrad) is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_ircxpro_admin_server (struct script_infos *desc, int port, int trp)
{
  char ban[512];

  register_service (desc, port, "ircxpro_admin");

  snprintf (ban, sizeof (ban),
            "An IRCXPro administrative server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_gnocatan_server (struct script_infos *desc, int port, int trp)
{
  char ban[512];

  register_service (desc, port, "gnocatan");

  snprintf (ban, sizeof (ban),
            "A gnocatan game server is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/* Thanks to Owell Crow */
static void
mark_pbmaster_server (struct script_infos *desc, int port, char *buffer,
                      int trp)
{
  char ban[512];

  register_service (desc, port, "power-broker-master");

  snprintf (ban, sizeof (ban),
            "A PowerBroker master server is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

/* Thanks to Paulo Jorge */
static void
mark_dictd_server (struct script_infos *desc, int port, char *buffer, int trp)
{
  char ban[512];

  register_service (desc, port, "dicts");

  snprintf (ban, sizeof (ban), "A dictd server is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

/* Thanks to Tony van Lingen */
static void
mark_pnsclient (struct script_infos *desc, int port, int trp)
{
  char ban[512];

  register_service (desc, port, "pNSClient");

  snprintf (ban, sizeof (ban),
            "A Netsaint plugin (pNSClient.exe) is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

/* Thanks to Jesus D. Munoz */
static void
mark_veritas_backup (struct script_infos *desc, int port, int trp)
{
  char ban[512];
  register_service (desc, port, "VeritasNetBackup");

  snprintf (ban, sizeof (ban), "VeritasNetBackup is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_pblocald_server (struct script_infos *desc, int port, char *buffer,
                      int trp)
{
  char ban[512];

  register_service (desc, port, "power-broker-master");

  snprintf (ban, sizeof (ban),
            "A PowerBroker locald server is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

static void
mark_jabber_server (struct script_infos *desc, int port, int trp)
{
  char ban[255];
  register_service (desc, port, "jabber");
  snprintf (ban, sizeof (ban),
            "jabber daemon seems to be running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, ban);
}

static void
mark_avotus_mm_server (struct script_infos *desc, int port, char *buffer,
                       int trp)
{
  char ban[512];

  register_service (desc, port, "avotus_mm");

  snprintf (ban, sizeof (ban),
            "An avotus 'mm' server is running on this port%s:\n%s",
            get_encaps_through (trp), buffer);
  post_log (oid, desc, port, ban);
}

static void
mark_socks_proxy (struct script_infos *desc, int port, int ver)
{
  char str[256];

  snprintf (str, sizeof (str), "socks%d", ver);
  register_service (desc, port, str);
  snprintf (str, sizeof (str), "A SOCKS%d proxy is running on this port. ",
            ver);
  post_log (oid, desc, port, str);
}

static void
mark_direct_connect_hub (struct script_infos *desc, int port, int trp)
{
  char str[256];

  register_service (desc, port, "DirectConnectHub");
  snprintf (str, sizeof (str), "A Direct Connect Hub is running on this port%s",
            get_encaps_through (trp));
  post_log (oid, desc, port, str);
}

static void
mark_mongodb (struct script_infos *desc, int port)
{
  register_service (desc, port, "mongodb");
  post_log (oid, desc, port, "A MongoDB server is running on this port");
}

/*
 * We determine if the 4 bytes we received look like a date. We
 * accept clocks desynched up to 3 years;
 *
 * MA 2002-09-09 : time protocol (RFC 738) returns number of seconds since
 * 1900-01-01, while time() returns nb of sec since 1970-01-01.
 * The difference is 2208988800 seconds.
 * By the way, although the RFC is imprecise, it seems that the returned
 * integer is in "network byte order" (i.e. big endian)
 */
#define MAX_SHIFT (3 * 365 * 86400)
#define DIFF_1970_1900 2208988800U

static int
may_be_time (time_t *rtime)
{
#ifndef ABS
#define ABS(x) (((x) < 0) ? -(x) : (x))
#endif
  time_t now = time (NULL);
  int rt70 = ntohl (*rtime) - DIFF_1970_1900;

  if (ABS (now - rt70) < MAX_SHIFT)
    return 1;
  else
    return 0;
}

static int
retry_stream_connection (int test_ssl, struct script_infos *desc, int port,
                         int timeout, int *trp)
{
  const char *p = "NORMAL:+ARCFOUR-128:%COMPAT";
  const char *lp = "LEGACY:%COMPAT:%UNSAFE_RENEGOTIATION";
  int cnx;

  if (test_ssl)
    *trp = OPENVAS_ENCAPS_TLScustom;
  else
    *trp = OPENVAS_ENCAPS_IP;

  cnx = open_stream_connection (desc, port, *trp, timeout);
  if (test_ssl)
    {
      switch (cnx)
        {
        case TLS_PRIME_UNACCEPTABLE:
          // retry with insecure bit
          g_debug ("%s: NO_PRIORITY_FLAGS failed, retrying with "
                   "INSECURE_DH_PRIME_BITS",
                   __func__);
          cnx = open_stream_connection_ext (desc, port, *trp, timeout, p,
                                            INSECURE_DH_PRIME_BITS);
          if (cnx >= 0)
            {
              open_stream_tls_default_priorities (p, INSECURE_DH_PRIME_BITS);
            }
          break;
        case TLS_FATAL_ALERT:
          // retry with legacy option
          g_debug ("%s: %s failed, retrying with %s", __func__, p, lp);
          cnx = open_stream_connection_ext (desc, port, *trp, timeout, lp,
                                            NO_PRIORITY_FLAGS);
          if (cnx >= 0)
            {
              open_stream_tls_default_priorities (lp, NO_PRIORITY_FLAGS);
            }
          break;
        default:
          // do nothing
          break;
        }
      // verify if retries went successful and if not retry without tls
      if (cnx < 0)
        {
          g_debug ("%s: unable to establish a TLS connection to %s; falling "
                   "back to unencrypted connection",
                   __func__, plug_get_host_fqdn (desc));
          *trp = OPENVAS_ENCAPS_IP;
          cnx = open_stream_connection (desc, port, *trp, timeout);
        }
    }

  return cnx;
}

static int
plugin_do_run (struct script_infos *desc, GSList *h, int test_ssl)
{
  char *head = "Ports/tcp/", *host_fqdn;
  u_short unknown[65535];
  int num_unknown = 0;
  size_t len_head = strlen (head);

  int rw_timeout = 20, cnx_timeout = 20, wrap_timeout = 20;
  int x, timeout;
  char *rw_timeout_s = get_plugin_preference (oid, RW_TIMEOUT_PREF, -1);
  char *cnx_timeout_s = get_plugin_preference (oid, CNX_TIMEOUT_PREF, -1);
  char *wrap_timeout_s = get_plugin_preference (oid, WRAP_TIMEOUT_PREF, -1);
  unsigned char *p;
  fd_set rfds, wfds;
  struct timeval tv;
  char k[32], *http_get;

  host_fqdn = plug_get_host_fqdn (desc);
  http_get = g_strdup_printf ("GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host_fqdn);
  g_free (host_fqdn);

  if (rw_timeout_s != NULL && (x = atoi (rw_timeout_s)) > 0)
    rw_timeout = x;
  if (cnx_timeout_s != NULL && (x = atoi (cnx_timeout_s)) > 0)
    cnx_timeout = x;
  if (wrap_timeout_s != NULL && (x = atoi (wrap_timeout_s)) >= 0)
    wrap_timeout = x;

  bzero (unknown, sizeof (unknown));

  while (h)
    {
      if ((strlen (h->data) > len_head) && !strncmp (h->data, head, len_head))
        {
          int cnx;
          char *line;
          char *origline;
          int trp;
          char buffer[2049];
          unsigned char *banner = NULL, *bannerHex = NULL;
          size_t banner_len, i;
          int port = atoi ((const char *) h->data + len_head);
          int flg = 0;
          int unindentified_service = 0;
          int three_digits = 0;
          int maybe_wrapped = 0;
          char kb[64];
          int get_sent = 0;
          struct timeval tv1, tv2;
          int diff_tv = 0, diff_tv2 = 0;
          int type, no_banner_grabbed = 0;

#define DIFFTV1000(t1, t2) \
  ((t1.tv_sec - t2.tv_sec) * 1000 + (t1.tv_usec - t2.tv_usec) / 1000)

          bzero (buffer, sizeof (buffer));
          banner_len = 0;
          snprintf (kb, sizeof (kb), "BannerHex/%d", port);
          bannerHex = plug_get_key (desc, kb, &type, NULL, 0);
          if (type == ARG_STRING && bannerHex != NULL && bannerHex[0] != '\0')
            {
              int c1, c2;
              unsigned int j;
              banner_len = strlen ((char *) bannerHex) / 2;
              if (banner_len >= sizeof (buffer))
                banner_len = sizeof (buffer) - 1;
              for (j = 0; j < banner_len; j++)
                {
                  c1 = bannerHex[2 * j];
                  if (c1 >= 0 && c1 <= 9)
                    c1 -= '0';
                  else if (c1 >= 'a' && c1 <= 'f')
                    c1 -= 'a';
                  else if (c1 >= 'A' && c1 <= 'F')
                    c1 -= 'A';
                  else
                    banner_len = 0; /* Invalid value */
                  c2 = bannerHex[2 * j + 1];
                  if (c2 >= 0 && c2 <= 9)
                    c2 -= '0';
                  else if (c2 >= 'a' && c2 <= 'f')
                    c2 -= 'a';
                  else if (c2 >= 'A' && c2 <= 'F')
                    c2 -= 'A';
                  else
                    banner_len = 0; /* Invalid value */
                  buffer[j] = c1 << 4 | c2;
                }
              buffer[j] = '\0';
              if (banner_len > 0)
                banner = (unsigned char *) buffer;
            }
          g_free (bannerHex);
          if (banner_len == 0)
            {
              snprintf (kb, sizeof (kb), "Banner/%d", port);
              banner = plug_get_key (desc, kb, &type, NULL, 0);
              if (banner)
                banner_len = strlen ((char *) banner);
            }
          if (banner_len > 0)
            {
              cnx = -1;
              trp = OPENVAS_ENCAPS_IP;
            }
          else
            {
              if (banner != NULL)
                {
                  g_free (banner);
                  banner = NULL;
                }
              gettimeofday (&tv1, NULL);
              cnx = retry_stream_connection (test_ssl, desc, port, cnx_timeout,
                                             &trp);
              gettimeofday (&tv2, NULL);
              diff_tv = DIFFTV1000 (tv2, tv1);
            }

          if (cnx >= 0 || banner_len > 0)
            {
              int line_len, realfd = -1;
              size_t len;

              if (cnx >= 0)
                {
                  realfd = openvas_get_socket_from_connection (cnx);
                  snprintf (k, sizeof (k), "FindService/CnxTime1000/%d", port);
                  plug_replace_key (desc, k, ARG_INT,
                                    GSIZE_TO_POINTER (diff_tv));
                  snprintf (k, sizeof (k), "FindService/CnxTime/%d", port);
                  plug_replace_key (
                    desc, k, ARG_INT,
                    GSIZE_TO_POINTER (((diff_tv + 500) / 1000)));
                  if (diff_tv / 1000 > cnx_timeout)
                    plug_replace_key (desc, "/tmp/SlowFindService", ARG_INT,
                                      GSIZE_TO_POINTER (1));
                }
              plug_set_port_transport (desc, port, trp);
              (void) stream_set_timeout (port, rw_timeout);

              if (IS_ENCAPS_SSL (trp))
                {
                  char report[160];
                  snprintf (report, sizeof (report),
                            "A %s server answered on this port\n",
                            get_encaps_name (trp));
                  post_log (oid, desc, port, report);
                  plug_set_key (desc, "Transport/SSL", ARG_INT,
                                GSIZE_TO_POINTER (port));
                }

              len = 0;
              timeout = 0;
              if (banner_len > 0)
                {
                  len = banner_len;
                  if (banner != (unsigned char *) buffer)
                    {
                      if (len >= sizeof (buffer))
                        len = sizeof (buffer) - 1;
                      memcpy (buffer, banner, len);
                      buffer[len] = '\0';
                    }
                }
              else
                {
                  snprintf (kb, sizeof (kb), "/tmp/NoBanner/%d", port);
                  p = plug_get_key (desc, kb, &type, NULL, 0);
                  if (p != NULL)
                    {
                      if (type == ARG_INT)
                        no_banner_grabbed = GPOINTER_TO_SIZE (p);
                      else if (type == ARG_STRING)
                        no_banner_grabbed = atoi ((char *) p);
                    }
                  g_free (p);

                  if (!no_banner_grabbed)
                    {
#ifdef SMART_TCP_RW
                      if (trp == OPENVAS_ENCAPS_IP && realfd >= 0)
                        {
                        select_again:
                          FD_ZERO (&rfds);
                          FD_ZERO (&wfds);
                          FD_SET (realfd, &rfds);
                          FD_SET (realfd, &wfds);

                          (void) gettimeofday (&tv1, NULL);
                          tv.tv_usec = 0;
                          tv.tv_sec = rw_timeout;
                          x = select (realfd + 1, &rfds, &wfds, NULL, &tv);
                          if (x < 0)
                            {
                              if (errno == EINTR)
                                goto select_again;
                              perror ("select");
                            }
                          else if (x == 0)
                            timeout = 1;
                          else if (x > 0)
                            {
                              if (FD_ISSET (realfd, &rfds))
                                {
                                  len = read_stream_connection_min (
                                    cnx, buffer, 1, sizeof (buffer) - 2);
                                }
                            }
                          (void) gettimeofday (&tv2, NULL);
                          diff_tv = DIFFTV1000 (tv2, tv1);
                        }
                    }
                  else
                    { /* No banner was found
                       * by openvas_tcp_scanner */
                      len = 0;
                      timeout = 0;
                    }

                  if (len <= 0 && !timeout)
#endif
                    {
                      write_stream_connection (cnx, http_get,
                                               strlen (http_get));
                      (void) gettimeofday (&tv1, NULL);
                      get_sent = 1;
                      buffer[sizeof (buffer) - 1] = '\0';
                      len = read_stream_connection (cnx, buffer,
                                                    sizeof (buffer) - 1);
#if 1
                      /*
                       * Try to work around broken
                       * web server (or "magic
                       * read" bug??)
                       */
                      if (len > 0 && len < 8
                          && strncmp (buffer, "HTTP/1.", len) == 0)
                        {
                          int len2 = read_stream_connection (
                            cnx, buffer + len, sizeof (buffer) - 1 - len);
                          if (len2 > 0)
                            len += len2;
                        }
#endif
                      (void) gettimeofday (&tv2, NULL);
                      diff_tv = DIFFTV1000 (tv2, tv1);
                    }
                  if (len > 0)
                    {
                      snprintf (k, sizeof (k), "FindService/RwTime1000/%d",
                                port);
                      plug_replace_key (desc, k, ARG_INT,
                                        GSIZE_TO_POINTER (diff_tv));
                      snprintf (k, sizeof (k), "FindService/RwTime/%d", port);
                      plug_replace_key (
                        desc, k, ARG_INT,
                        GSIZE_TO_POINTER ((diff_tv + 500) / 1000));
                      if (diff_tv / 1000 > rw_timeout)
                        plug_replace_key (desc, "/tmp/SlowFindService", ARG_INT,
                                          GSIZE_TO_POINTER (1));
                    }
                }

              if (len > 0)
                {
                  char *t;
                  banner = g_malloc0 (len + 1);
                  memcpy (banner, buffer, len);
                  banner[len] = '\0';

                  for (i = 0; i < len; i++)
                    buffer[i] = (buffer[i] == '\0') ? 'x' : tolower (buffer[i]);

                  line = g_strdup (buffer);

                  t = strchr (line, '\n');
                  if (t)
                    t[0] = '\0';
                  if (isdigit (banner[0]) && isdigit (banner[1])
                      && isdigit (banner[2])
                      && (banner[3] == '\0' || isspace (banner[3])
                          || banner[3] == '-'))
                    {
                      /*
                       * Do NOT use
                       * plug_replace_key!
                       */
                      plug_set_key (desc, "Services/three_digits", ARG_INT,
                                    GSIZE_TO_POINTER (port));
                      /*
                       * Do *not* set
                       * Known/tcp/<port> to
                       * "three_digits": the
                       * service must remain
                       * "unknown"
                       */
                      three_digits = 1;
                    }
                  if (get_sent)
                    snprintf (kb, sizeof (kb), "FindService/tcp/%d/get_http",
                              port);
                  else
                    snprintf (kb, sizeof (kb), "FindService/tcp/%d/spontaneous",
                              port);
                  plug_replace_key (desc, kb, ARG_STRING, banner);

                  {
                    char buf2[sizeof (buffer) * 2 + 1];
                    int flag = 0;
                    unsigned int y;

                    strcat (kb, "Hex");

                    if (len >= sizeof (buffer))
                      len = sizeof (buffer);

                    for (y = 0; y < len; y++)
                      {
                        snprintf (buf2 + 2 * y, sizeof (buf2) - (2 * y), "%02x",
                                  (unsigned char) banner[y]);
                        if (banner[y] == '\0')
                          flag = 1;
                      }
                    buf2[2 * y] = '\0';
                    if (flag)
                      plug_replace_key (desc, kb, ARG_STRING, buf2);
                  }

                  origline = g_strdup ((char *) banner);
                  t = strchr (origline, '\n');
                  if (t)
                    t[0] = '\0';
                  line_len = strlen (origline);

                  /*
                   * Many services run on the top of an HTTP protocol,
                   * so the HTTP test is not an 'ELSE ... IF'
                   */
                  if ((!strncmp (line, "http/1.", 7)
                       || strstr ((char *) banner,
                                  "<title>Not supported</title>")))
                    { /* <- broken hp
                       * jetdirect */
                      flg++;
                      if (!(port == 5000
                            && (strstr (line, "http/1.1 400 bad request")
                                != NULL))
                          && !(strncmp (line, "http/1.0 403 forbidden",
                                        strlen ("http/1.0 403 forbidden"))
                                 == 0
                               && strstr (buffer, "server: adsubtract") != NULL)
                          && !(strstr (
                                 buffer,
                                 "it looks like you are trying to access "
                                 "mongodb over http on the native driver port.")
                                 != NULL
                               && strstr (buffer, "content-length: 84")
                                    != NULL))
                        mark_http_server (desc, port, banner, trp);
                    }
                  /*
                   * RFC 854 defines commands between 240 and 254
                   * shouldn't we look for them too?
                   */
                  if (((u_char) buffer[0] == 255)
                      && (((u_char) buffer[1] == 251)
                          || ((u_char) buffer[1] == 252)
                          || ((u_char) buffer[1] == 253)
                          || ((u_char) buffer[1] == 254)))
                    mark_telnet_server (desc, port, trp);
                  else if (((u_char) buffer[0] == 0)
                           && ((u_char) buffer[1] == 1)
                           && ((u_char) buffer[2] == 1)
                           && ((u_char) buffer[3] == 0))
                    mark_gnome14_server (desc, port, trp);
                  else if (strncmp (line, "http/1.0 403 forbidden",
                                    strlen ("http/1.0 403 forbidden"))
                             == 0
                           && strstr (buffer, "server: adsubtract") != NULL)
                    {
                      mark_locked_adsubtract_server (desc, port, banner, trp);
                    }
                  else if (strstr ((char *) banner, "Eggdrop") != NULL
                           && strstr ((char *) banner, "Eggheads") != NULL)
                    mark_eggdrop_server (desc, port, trp);
                  else if (strncmp (line, "$lock ", strlen ("$lock ")) == 0)
                    mark_direct_connect_hub (desc, port, trp);
                  else if (len > 34 && strstr (&(buffer[34]), "iss ecnra"))
                    mark_iss_realsecure (desc, port);
                  else if (len == 4 && origline[0] == 'Q' && origline[1] == 0
                           && origline[2] == 0 && origline[3] == 0)
                    mark_fw1 (desc, port, origline, trp);
                  else if (strstr (line, "adsgone blocked html ad") != NULL)
                    mark_adsgone (desc, port, origline, trp);
                  else if (strncmp (line, "icy 200 ok", strlen ("icy 200 ok"))
                           == 0)
                    mark_shoutcast_server (desc, port, origline, trp);
                  else if ((!strncmp (line, "200", 3)
                            && (strstr (line,
                                        "running eudora internet mail server")))
                           || (strstr (line, "+ok applepasswordserver")
                               != NULL))
                    mark_pop3pw_server (desc, port, origline, trp);
                  else if ((strstr (line, "smtp")
                            || strstr (line, "simple mail transfer")
                            || strstr (line, "mail server")
                            || strstr (line, "messaging")
                            || strstr (line, "Weasel"))
                           && !strncmp (line, "220", 3))
                    mark_smtp_server (desc, port, origline, trp);
                  else if (strstr (line, "220 ***************")
                           || strstr (line, "220 eSafe@")) /* CISCO SMTP (?) -
                                                            * see bug #175 */
                    mark_smtp_server (desc, port, origline, trp);
                  else if (strstr (line, "220 esafealert") != NULL)
                    mark_smtp_server (desc, port, origline, trp);
                  else if (strncmp (line, "220", 3) == 0
                           && strstr (line, "groupwise internet agent") != NULL)
                    mark_smtp_server (desc, port, origline, trp);
                  else if (strncmp (line, "220", 3) == 0
                           && strstr (line, " SNPP ") != NULL)
                    mark_snpp_server (desc, port, origline, trp);
                  else if (strncmp (line, "200", 3) == 0
                           && strstr (line, "mail ") != NULL)
                    mark_smtp_server (desc, port, origline, trp);
                  else if (strncmp (line, "421", 3) == 0
                           && strstr (line, "smtp ") != NULL)
                    mark_smtp_server (desc, port, origline, trp);
                  // Null characters in buffer were replaced by 'x'.
                  else if ((line[0] != '\0'
                            || (strstr (buffer, "mysql") != NULL))
                           && (regex_match (
                                 buffer,
                                 "^.x{3}\n[0-9.]+ [0-9a-z]+@[0-9a-z]+ release")
                               || regex_match (
                                 buffer, "^.x{3}\n[0-9.]+-(id[0-9]+-)?release"
                                         " \\([0-9a-z-]+\\)")))
                    mark_sphinxql (desc, port);
                  else if (line[0] != '\0'
                           && ((strncmp (buffer + 1, "host '", 6) == 0)
                               || (strstr (buffer, "mysql") != NULL
                                   || strstr (buffer, "mariadb") != NULL)))
                    mark_mysql (desc, port);
                  else if (!strncmp (line, "efatal", 6)
                           || !strncmp (line, "einvalid packet length",
                                        strlen ("einvalid packet length")))
                    mark_postgresql (desc, port);
                  else if (strstr (line, "cvsup server ready") != NULL)
                    mark_cvsupserver (desc, port);
                  else if (!strncmp (line, "cvs [pserver aborted]:", 22)
                           || !strncmp (line, "cvs [server aborted]:", 21))
                    mark_cvspserver (desc, port);
                  else if (!strncmp (line, "cvslock ", 8))
                    mark_cvslockserver (desc, port);
                  else if (!strncmp (line, "@rsyncd", 7))
                    mark_rsync (desc, port);
                  else if ((len == 4) && may_be_time ((time_t *) banner))
                    mark_time_server (desc, port, trp);
                  else if (strstr (buffer, "rmserver")
                           || strstr (buffer, "realserver"))
                    mark_rmserver (desc, port, origline, trp);
                  else if ((strstr (line, "ftp") || strstr (line, "winsock")
                            || strstr (line, "axis network camera")
                            || strstr (line, "netpresenz")
                            || strstr (line, "serv-u")
                            || strstr (line, "service ready for new user"))
                           && !strncmp (line, "220", 3))
                    mark_ftp_server (desc, port, origline, trp);
                  else if (strncmp (line, "220-", 4) == 0) /* FTP server with a
                                                            * long banner */
                    mark_ftp_server (desc, port, NULL, trp);
                  else if (strstr (line, "220") && strstr (line, "whois+"))
                    mark_whois_plus2_server (desc, port, origline, trp);
                  else if (strstr (line, "520 command could not be executed"))
                    mark_mon_server (desc, port, origline, trp);
                  else if (strstr (line, "ssh-"))
                    mark_ssh_server (desc, port, origline);
                  else if (!strncmp (line, "+ok", 3)
                           || (!strncmp (line, "+", 1) && strstr (line, "pop")))
                    mark_pop_server (desc, port, origline);
                  else if (strstr (line, "imap4") && !strncmp (line, "* ok", 4))
                    mark_imap_server (desc, port, origline, trp);
                  else if (strstr (line, "*ok iplanet messaging multiplexor"))
                    mark_imap_server (desc, port, origline, trp);
                  else if (strstr (line, "*ok communigate pro imap server"))
                    mark_imap_server (desc, port, origline, trp);
                  else if (strstr (line, "* ok courier-imap"))
                    mark_imap_server (desc, port, origline, trp);
                  else if (strncmp (line, "giop", 4) == 0)
                    mark_giop_server (desc, port, trp);
                  else if (strstr (line, "microsoft routing server"))
                    mark_exchg_routing_server (desc, port, origline, trp);
                  /* Apparently an iPlanet ENS server */
                  else if (strstr (line, "gap service ready"))
                    mark_ens_server (desc, port, trp);
                  else if (strstr (line, "-service not available"))
                    mark_tcpmux_server (desc, port, trp);
                  /*
                   * Citrix sends 7f 7f 49 43 41, that
                   * we converted to lowercase
                   */
                  else if (strlen (line) > 2 && line[0] == 0x7F
                           && line[1] == 0x7F
                           && strncmp (&line[2], "ica", 3) == 0)
                    mark_citrix_server (desc, port, trp);

                  else if (strstr (origline, " INN ")
                           || strstr (origline, " Leafnode ")
                           || strstr (line, "  nntp daemon")
                           || strstr (line, " nnrp service ready")
                           || strstr (line, "posting ok")
                           || strstr (line, "posting allowed")
                           || strstr (line, "502 no permission")
                           || (strcmp (line, "502") == 0
                               && strstr (line, "diablo") != NULL))
                    mark_nntp_server (desc, port, origline, trp);
                  else if (strstr (buffer, "networking/linuxconf")
                           || strstr (buffer, "networking/misc/linuxconf")
                           || strstr (buffer, "server: linuxconf"))
                    mark_linuxconf (desc, port, banner);
                  else if (strncmp (buffer, "gnudoit:", 8) == 0)
                    mark_gnuserv (desc, port);
                  else if ((buffer[0] == '0'
                            && strstr (buffer, "error.host\t1") != NULL)
                           || (buffer[0] == '3'
                               && strstr (
                                 buffer,
                                 "That item is not currently available")))

                    mark_gopher_server (desc, port);
                  else if (strstr (buffer,
                                   "www-authenticate: basic realm=\"swat\""))
                    mark_swat_server (desc, port);
                  else if (strstr (buffer, "vqserver")
                           && strstr (buffer,
                                      "www-authenticate: basic realm=/"))
                    mark_vqserver (desc, port);
                  else if (strstr (buffer, "1invalid request") != NULL)
                    mark_mldonkey (desc, port);
                  else if (strstr (buffer, "get: command not found"))
                    mark_wild_shell (desc, port);
                  else if (strstr (buffer, "microsoft windows") != NULL
                           && strstr (buffer, "c:\\") != NULL
                           && strstr (buffer, "(c) copyright 1985-") != NULL
                           && strstr (buffer, "microsoft corp.") != NULL)
                    mark_wild_shell (desc, port);
                  else if (strstr (buffer, "netbus"))
                    mark_netbus_server (desc, port);
                  else if (strstr (line, "0 , 0 : error : unknown-error")
                           || strstr (line, "0, 0: error: unknown-error")
                           || strstr (line, "get : error : unknown-error")
                           || strstr (line, "0 , 0 : error : invalid-port"))
                    mark_auth_server (desc, port);
                  else if (!strncmp (line, "http/1.", 7)
                           && strstr (line, "proxy")) /* my proxy "HTTP/1.1
                                                       * 502 Proxy Error" */
                    mark_http_proxy (desc, port, trp);
                  else if (!strncmp (line, "http/1.", 7)
                           && strstr (buffer, "via: "))
                    mark_http_proxy (desc, port, trp);
                  else if (!strncmp (line, "http/1.", 7)
                           && strstr (buffer, "proxy-connection: "))
                    mark_http_proxy (desc, port, trp);
                  else if (!strncmp (line, "http/1.", 7)
                           && strstr (buffer, "cache")
                           && strstr (line, "bad request"))
                    mark_http_proxy (desc, port, trp);
                  else if (!strncmp (origline, "RFB 00", 6)
                           && strstr (line, ".00"))
                    mark_vnc_server (desc, port, origline);
                  else if (!strncmp (line, "ncacn_http/1.", 13))
                    mark_ncacn_http_server (desc, port, origline);
                  else if (line_len >= 14 && /* no ending \r\n */
                           line_len <= 18 && /* full GET request
                                              * length */
                           strncmp (origline, http_get, line_len) == 0)
                    mark_echo_server (desc, port);
                  else if (strstr ((char *) banner, "!\"#$%&'()*+,-./")
                           && strstr ((char *) banner, "ABCDEFGHIJ")
                           && strstr ((char *) banner, "abcdefghij")
                           && strstr ((char *) banner, "0123456789"))
                    mark_chargen_server (desc, port);
                  else if (strstr (line, "vtun server"))
                    mark_vtun_server (desc, port, banner, trp);
                  else if (strcmp (line, "login: password: ") == 0)
                    mark_uucp_server (desc, port, banner, trp);
                  else if (strcmp (line, "bad request") == 0
                           || /* See bug # 387 */
                           strstr (
                             line,
                             "invalid protocol request (71): gget / http/1.0")
                           || (strncmp (line, "lpd:", 4) == 0)
                           || (strstr (line, "lpsched") != NULL)
                           || (strstr (line, "malformed from address") != NULL)
                           || (strstr (line, "no connect permissions") != NULL)
                           || /* <- RH 8 lpd */
                           strcmp (line, "bad request") == 0)
                    mark_lpd_server (desc, port, trp);
                  else if (strstr (line, "%%lyskom unsupported protocol"))
                    mark_lyskom_server (desc, port, trp);
                  else if (strstr (line, "598:get:command not recognized"))
                    mark_ph_server (desc, port, trp);
                  else if (strstr (line, "BitTorrent prot"))
                    mark_BitTorrent_server (desc, port, trp);
                  else if (banner[0] == 'A' && banner[1] == 0x01
                           && banner[2] == 0x02 && banner[3] == '\0')
                    mark_smux_server (desc, port, trp);
                  else if (!strncmp (line, "0 succeeded\n",
                                     strlen ("0 succeeded\n")))
                    mark_LISa_server (desc, port, trp);
                  else if (strlen ((char *) banner) == 3 && banner[2] == '\n')
                    mark_msdtc_server (desc, port);
                  else if ((!strncmp (line, "220", 3)
                            && strstr (line, "poppassd")))
                    mark_pop3pw_server (desc, port, origline, trp);
                  else if (strstr (line, "welcome!psybnc@") != NULL)
                    mark_psybnc (desc, port, origline, trp);
                  else if (strncmp (line, "* acap ", strlen ("* acap ")) == 0)
                    mark_acap_server (desc, port, origline, trp);
                  else if (strstr (origline, "Sorry, you (") != NULL
                           && strstr (origline,
                                      "are not among the allowed hosts...\n")
                                != NULL)
                    mark_nagiosd_server (desc, port, trp);
                  else if (strstr (line, "[ts].error") != NULL
                           || strstr (line, "[ts].\n") != NULL)
                    mark_teamspeak2_server (desc, port, trp);
                  else if (strstr (origline, "Language received from client:")
                           && strstr (origline, "Setlocale:"))
                    mark_websm_server (desc, port, trp);
                  else if (strncmp (origline, "CNFGAPI", 7) == 0)
                    mark_ofa_express_server (desc, port, trp);
                  else if (strstr (line, "suse meta pppd") != NULL)
                    mark_smppd_server (desc, port, trp);
                  else if (strncmp (origline, "ERR UNKNOWN-COMMAND",
                                    strlen ("ERR UNKNOWN-COMMAND"))
                           == 0)
                    mark_upsmon_server (desc, port, trp);
                  else if (strncmp (line, "connected. ", strlen ("connected. "))
                             == 0
                           && strstr (line, "legends") != NULL)
                    mark_sub7_server (desc, port, trp);
                  else if (strncmp (line, "spamd/", strlen ("spamd/")) == 0)
                    mark_spamd_server (desc, port, trp);
                  else if (strstr (line, " dictd ")
                           && strncmp (line, "220", 3) == 0)
                    mark_dictd_server (desc, port, origline, trp);
                  else if (strncmp (line, "220 ", 4) == 0
                           && strstr (line, "vmware authentication daemon")
                                != NULL)
                    mark_vmware_auth (desc, port, origline, trp);
                  else if (strncmp (line, "220 ", 4) == 0
                           && strstr (line, "interscan version") != NULL)
                    mark_interscan_viruswall (desc, port, origline, trp);
                  else if ((strlen ((char *) banner) > 1) && (banner[0] == '~')
                           && (banner[strlen ((char *) banner) - 1] == '~')
                           && (strchr ((char *) banner, '}') != NULL))
                    mark_ppp_daemon (desc, port, trp);
                  else if (strstr ((char *) banner, "Hello, this is zebra ")
                           != NULL)
                    mark_zebra_server (desc, port, origline, trp);
                  else if (strstr (line, "ircxpro ") != NULL)
                    mark_ircxpro_admin_server (desc, port, trp);
                  else if (strncmp (origline, "version report",
                                    strlen ("version report"))
                           == 0)
                    mark_gnocatan_server (desc, port, trp);
                  else if (strncmp (origline, "RTSP/1.0", strlen ("RTSP/1.0"))
                           && strstr (origline, "QTSS/") != NULL)
                    mark_quicktime_streaming_server (desc, port, trp);
                  else if (strlen (origline) >= 2 && origline[0] == 0x30
                           && origline[1] == 0x11 && origline[2] == 0)
                    mark_dameware_server (desc, port, trp);
                  else if (strstr (line, "stonegate firewall") != NULL)
                    mark_stonegate_auth_server (desc, port, trp);
                  else if (strncmp (line, "pbmasterd", strlen ("pbmasterd"))
                           == 0)
                    mark_pbmaster_server (desc, port, origline, trp);
                  else if (strncmp (line, "pblocald", strlen ("pblocald")) == 0)
                    mark_pblocald_server (desc, port, origline, trp);
                  else if (strncmp (
                             line, "<stream:error>invalid xml</stream:error>",
                             strlen (
                               "<stream:error>invalid xml</stream:error>"))
                           == 0)
                    mark_jabber_server (desc, port, trp);
                  else if (strncmp (line, "/c -2 get ctgetoptions",
                                    strlen ("/c -2 get ctgetoptions"))
                           == 0)
                    mark_avotus_mm_server (desc, port, origline, trp);
                  else if (strncmp (line, "error:wrong password",
                                    strlen ("error:wrong password"))
                           == 0)
                    mark_pnsclient (desc, port, trp);
                  else if (strncmp (line, "1000      2", strlen ("1000      2"))
                           == 0)
                    mark_veritas_backup (desc, port, trp);
                  else if (strstr (line,
                                   "the file name you specified is invalid")
                           && strstr (line, "listserv"))
                    mark_listserv_server (desc, port, trp);
                  else if (strncmp (line, "control password:",
                                    strlen ("control password:"))
                           == 0)
                    mark_fssniffer (desc, port, trp);
                  else if (strncmp (line, "remotenc control password:",
                                    strlen ("remotenc control password:"))
                           == 0)
                    mark_remote_nc_server (desc, port, trp);
                  else if (((p = (unsigned char *) strstr (
                               (char *) banner, "finger: GET: no such user"))
                              != NULL
                            && strstr ((char *) banner,
                                       "finger: /: no such user")
                                 != NULL
                            && strstr ((char *) banner,
                                       "finger: HTTP/1.0: no such user")
                                 != NULL))
                    {
                      char c = '\0';
                      if (p != NULL)
                        {
                          while (p - banner > 0 && isspace (*p))
                            p--;
                          c = *p;
                          *p = '\0';
                          mark_finger_server (desc, port, trp);
                        }

                      if (p != NULL)
                        *p = c;
                    }
                  else if (banner[0] == 5 && banner[1] <= 8 && banner[2] == 0
                           && banner[3] <= 4)
                    mark_socks_proxy (desc, port, 5);
                  else if (banner[0] == 0 && banner[1] >= 90 && banner[1] <= 93)
                    mark_socks_proxy (desc, port, 4);
                  else if (strstr (
                             buffer,
                             "it looks like you are trying to access mongodb "
                             "over http on the native driver port.")
                           != NULL)
                    mark_mongodb (desc, port);
                  else
                    unindentified_service = !flg;
                  g_free (line);
                  g_free (origline);
                }
              /* len >= 0 */
              else
                {
                  unindentified_service = 1;
#define TESTSTRING "OpenVAS Wrap Test"
                  if (trp == OPENVAS_ENCAPS_IP && wrap_timeout > 0)
                    maybe_wrapped = 1;
                }
              if (cnx > 0)
                close_stream_connection (cnx);

              /*
               * I'll clean this later. Meanwhile, we will not print a silly
               * message for rsh and rlogin.
               */
              if (port == 513 /* rlogin */ || port == 514 /* rsh */)
                maybe_wrapped = 0;

              if (maybe_wrapped /* && trp ==
                                 * OPENVAS_ENCAPS_IP &&
                                 wrap_timeout > 0 */ )
                {
                  int nfd, fd, wx, flag = 0;
                  char b;

                  nfd = open_stream_connection (desc, port, OPENVAS_ENCAPS_IP,
                                                cnx_timeout);
                  if (nfd >= 0)
                    {
                      fd = openvas_get_socket_from_connection (nfd);
                    select_again2:
                      FD_ZERO (&rfds);
                      FD_SET (fd, &rfds);
                      tv.tv_sec = wrap_timeout;
                      tv.tv_usec = 0;

                      signal (SIGALRM, SIG_IGN);

                      (void) gettimeofday (&tv1, NULL);
                      wx = select (fd + 1, &rfds, NULL, NULL, &tv);
                      (void) gettimeofday (&tv2, NULL);
                      diff_tv2 = DIFFTV1000 (tv2, tv1);
                      if (wx < 0)
                        {
                          if (errno == EINTR)
                            goto select_again2;
                          perror ("select");
                        }
                      else if (wx > 0)
                        {
                          errno = 0;
                          wx = recv (fd, &b, 1, MSG_DONTWAIT);
                          if (wx == 0 || (wx < 0 && errno == EPIPE))
                            {
                              /*
                               * If the service quickly closes the connection
                               * when we send garbage but not when we don't send
                               * anything, it is not wrapped
                               */
                              flag = 1;
                            }
                        }
                      else
                        {
                          /*
                           * Timeout - one last
                           * check
                           */
                          errno = 0;
                          if (send (fd, "Z", 1, MSG_DONTWAIT) < 0)
                            {
                              perror ("send");
                              if (errno == EPIPE)
                                flag = 1;
                            }
                        }
                      close_stream_connection (nfd);
                      if (flag)
                        {
                          if (diff_tv2 <= 2 * diff_tv + 1)
                            {
                              mark_wrapped_svc (desc, port, diff_tv2 / 1000);
                              unindentified_service = 0;
                            }
                        }
                    }
                }

              if (unindentified_service && port != 139 && port != 135
                  && port != 445)
                /*
                 * port 139 can't be marked as
                 * 'unknown'
                 */
                {
                  unknown[num_unknown++] = port;
                  /*
                   * find_service_3digits will run
                   * after us
                   */
                  if (!three_digits)
                    mark_unknown_svc (desc, port, banner, trp);
                }
              g_free (banner);
            }
        }
      h = h->next;
    }
  g_free (http_get);

  return (0);
}

#define MAX_SONS 128

static pid_t sons[MAX_SONS];

static void
sigterm (int s)
{
  int i;

  (void) s;
  for (i = 0; i < MAX_SONS; i++)
    {
      if (sons[i] != 0)
        kill (sons[i], SIGTERM);
    }
  _exit (0);
}

static void
sigchld (int s)
{
  int i;

  (void) s;
  for (i = 0; i < MAX_SONS; i++)
    {
      waitpid (sons[i], NULL, WNOHANG);
    }
}

tree_cell *
plugin_run_find_service (lex_ctxt *lexic)
{
  struct script_infos *desc = lexic->script_infos;

  oid = lexic->oid;

  kb_t kb = plug_get_kb (desc);
  struct kb_item *kbitem, *kbitem_tmp;

  GSList *sons_args[MAX_SONS];
  int num_ports = 0;
  char *num_sons_s;
  int num_sons = 6;
  int port_per_son;
  int i;
  int test_ssl = 1;
  char *key = get_plugin_preference (oid, KEY_FILE, -1);
  char *cert = get_plugin_preference (oid, CERT_FILE, -1);
  char *pempass = get_plugin_preference (oid, PEM_PASS, -1);
  char *cafile = get_plugin_preference (oid, CA_FILE, -1);
  char *test_ssl_s = get_plugin_preference (oid, TEST_SSL_PREF, -1);

  if (key && key[0] != '\0')
    key = (char *) get_plugin_preference_fname (desc, key);
  else
    key = NULL;

  if (cert && cert[0] != '\0')
    cert = (char *) get_plugin_preference_fname (desc, cert);
  else
    cert = NULL;

  if (cafile && cafile[0] != '\0')
    cafile = (char *) get_plugin_preference_fname (desc, cafile);
  else
    cafile = NULL;

  if (test_ssl_s != NULL)
    {
      if (strcmp (test_ssl_s, "None") == 0)
        test_ssl = 0;
    }
  g_free (test_ssl_s);
  if (key || cert)
    {
      if (!key)
        key = cert;
      if (!cert)
        cert = key;
      plug_set_ssl_cert (desc, cert);
      plug_set_ssl_key (desc, key);
    }
  if (pempass != NULL)
    plug_set_ssl_pem_password (desc, pempass);
  if (cafile != NULL)
    plug_set_ssl_CA_file (desc, cafile);

  signal (SIGTERM, sigterm);
  signal (SIGCHLD, sigchld);
  num_sons_s = get_plugin_preference (oid, NUM_CHILDREN, -1);
  if (num_sons_s != NULL)
    num_sons = atoi (num_sons_s);
  g_free (num_sons_s);

  if (num_sons <= 0)
    num_sons = 6;

  if (num_sons > MAX_SONS)
    num_sons = MAX_SONS;

  for (i = 0; i < num_sons; i++)
    {
      sons[i] = 0;
      sons_args[i] = NULL;
    }

  if (kb == NULL)
    return NULL; // TODO: in old days returned "1". Still relevant?

  kbitem = kb_item_get_pattern (kb, "Ports/tcp/*");

  /* count the number of open TCP ports */
  kbitem_tmp = kbitem;
  while (kbitem_tmp != NULL)
    {
      num_ports++;
      kbitem_tmp = kbitem_tmp->next;
    }

  port_per_son = num_ports / num_sons;

  /* The next two loops distribute the ports across a number of 'sons'.
   */

  kbitem_tmp = kbitem;

  for (i = 0; i < num_sons; i = i + 1)
    {
      int j;

      if (kbitem_tmp != NULL)
        {
          for (j = 0; j < port_per_son && kbitem_tmp != NULL;)
            {
              sons_args[i] =
                g_slist_prepend (sons_args[i], g_strdup (kbitem_tmp->name));
              j++;
              kbitem_tmp = kbitem_tmp->next;
            }
        }
      else
        break;
    }

  for (i = 0; (i < num_ports % num_sons) && kbitem_tmp != NULL;)
    {
      sons_args[i] =
        g_slist_prepend (sons_args[i], g_strdup (kbitem_tmp->name));
      i++;
      kbitem_tmp = kbitem_tmp->next;
    }

  kb_item_free (kbitem);

  for (i = 0; i < num_sons; i++)
    if (sons_args[i] == NULL)
      break;

  num_sons = i;

  for (i = 0; i < num_sons; i++)
    {
      usleep (5000);
      if (sons_args[i] != NULL)
        {
          sons[i] = fork ();
          if (sons[i] == 0)
            {
              kb_lnk_reset (kb);
              kb_lnk_reset (get_main_kb ());
              mqtt_reset ();
              nvticache_reset ();

              signal (SIGTERM, _exit);
              plugin_do_run (desc, sons_args[i], test_ssl);
              _exit (0);
            }
          else
            {
              if (sons[i] < 0)
                sons[i] = 0; /* Fork failed */
            }
          g_slist_free_full (sons_args[i], g_free);
        }
    }

  for (;;)
    {
      int flag = 0;

      for (i = 0; i < num_sons; i++)
        {
          if (sons[i] != 0)
            {
              while (waitpid (sons[i], NULL, WNOHANG) && errno == EINTR)
                ;

              if (kill (sons[i], 0) >= 0)
                flag++;
            }
        }

      if (flag == 0)
        break;
      usleep (100000);
    }

  return NULL;
}
