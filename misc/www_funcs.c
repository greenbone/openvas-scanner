/* Copyright (C) 1998 - 2003 Renaud Deraison
 * Portions (C)  2002 - 2003 Michel Arboi
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
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <gvm/base/networking.h>
#include <gvm/util/kb.h>

#include "plugutils.h"
#include "support.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/*
 * This function implements "whisker like" IDS evasion tactics plus a couple
 * of other methods.
 * Read http://www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html
 *
 * Note: RFP is not responsible for the bugs here. I (Michel Arboi) wrote it!
 *
 * 2002-02-26: added Pavel kankovsky's "absolute URI"
 * 2002-03-06: added "CGI.pm parameters" by Noam Rathaus from securiteam.com
 * Partial support: we should changed & to ; in the "posted" data.
 * 2002-05-29: added "protocol string". See Alla Bezroutchko's message on
 * VULN-DEV (Date: 15 Feb 2002; From: <alla@scanit.be>;
 * Subject: Possible IDS-evasion technique
 * Message-ID: <3C6D434B.4377034A@scanit.be>)
 */

/* TBD
 * Pollute Apache logs with this:

To make a request and to make it seem like it came from NO IP ADDRESS at
all, the request should be made as this :

GET / HTTP/1.0 \r\r\n

In this case APACHE will print in the log file the carriage return
character. So when we try to tail the access_log file it will be shown in
the screen as :

" 414 3461.251 - - [24/Oct/2001:18:58:18 +0100] "GET / HTTP/1.0

A normal line would be :

127.0.0.1 - - [24/Oct/2001:19:00:32 +0100] "GET / HTTP/1.0" 200 164

The normal line output will help us to understand that what happens is cat
made a carriage return after the HTTP/1.0 and printed the rest of the log
over the Ip Address field.
We can also make it look like the request came from another Ip address, and
this is preferable because like this the SysAdmin will see no apparent
strange behaviour in the logfile. Just be careful with the timestamp !!
So the request should be :

GET / HTTP/1.0 \r10.0.0.1 - - [24/Oct/2001:19:00:32 +0100] "GET /
HTTP/1.0\r\n

And the logfile will appear like this :

10.0.0.1 - - [24/Oct/2001:19:00:32 +0100] "GET / HTTP/1.0" 200 164

This is a perfect log entry and nobody can suspect on it :-)

*/

char *
build_encode_URL (struct arglist *data, char *method, char *path, char *name,
                  char *httpver)
{
  int i, l = 0, n_slash = 0, n_backslash = 0, start_with_slash = 0;
  char *ret, *ret2;
  /* NIDS evasion options */
  char *s, *s2;
  int double_slash, reverse_traversal, self_ref_dir;
  int prem_req_end, param_hiding, cgipm_param;
  int dos_win_syntax, null_method, tab_sep, http09;
  char *abs_URI_type, *abs_URI_host;
  char sep_c;
#define URL_CODE_NONE		0
#define URL_CODE_HEX		1
#define URL_CODE_UTF16		2
#define URL_CODE_UTF16MS	3
#define URL_CODE_UTF8BAD	4
  int url_encoding;
  char gizmo[32];
  kb_t kb = plug_get_kb (data);

  /* Basically, we need to store the path, a slash, and the name.
   * Encoding will expand this
   * We'll add the method in front of all this and the HTTP version
   * at the end when all is done. That's not optimized, but that's simpler.
   */
  l = path != NULL ? strlen (path) : 0;
  l += strlen (name) + (path != NULL);

  /** @todo Evaluate if GLib functions for building paths are applicable here */
  ret = g_malloc0 (l + 1);
  if (path == NULL)
    strcpy (ret, name);
  else
    sprintf (ret, "%s/%s", path, name);

#ifdef URL_DEBUG
  g_message ("Request => %s", ret);
#endif

  for (s = ret; *s != '\0'; s++)
    if (*s == '/')
      n_slash++;
    else if (*s == '\\')
      n_backslash++;

  start_with_slash = (*ret == '/');

  s = kb_item_get_str (kb, "NIDS/HTTP/CGIpm_param");
  cgipm_param = (s != NULL && strcmp (s, "yes") == 0);
  if (cgipm_param)
    {
#ifdef URL_DEBUG
      i = 0;
#endif
      for (s = ret; *s != '\0' && *s != '?'; s++)
        ;
      if (*s == '?')
        for (; *s != '\0'; s++)
          if (*s == '&')
            {
              *s = ';';
#ifdef URL_DEBUG
              i++;
#endif
            }
#ifdef URL_DEBUG
      if (i > 0)
        g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/self_ref_dir");
  self_ref_dir = (s != NULL && strcmp (s, "yes") == 0);
  if (self_ref_dir)
    {
      l += 2 * n_slash;
      ret2 = g_malloc0 (l + 1);
      for (s = ret, s2 = ret2; *s != '\0' && *s != '?'; s++)
        if (*s != '/')
          *s2++ = *s;
        else
          {
            strncpy (s2, "/./", l);
            s2 += 3;
          }
      while (*s != '\0')
        *s2++ = *s++;
      *s2 = '\0';
      g_free (ret);
      ret = ret2;
      n_slash *= 2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/reverse_traversal");
  reverse_traversal = (s == NULL ? 0 : atoi (s));

  if (reverse_traversal > 0)
    {
      l += (reverse_traversal + 4) * n_slash;
      ret2 = g_malloc0 (l + 1);

      for (s = ret, s2 = ret2; *s != '\0' && *s != '?'; s++)
        if (*s != '/')
          *s2++ = *s;
        else
          {
            *s2++ = '/';
            for (i = reverse_traversal; i > 0; i--)
              *s2++ = lrand48 () % 26 + 'a';
            strncpy (s2, "/../", l);
            s2 += 4;
          }
      while (*s != '\0')
        *s2++ = *s++;
      *s2 = '\0';
      g_free (ret);
      ret = ret2;
      n_slash *= 3;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/premature_request_ending");
  prem_req_end = (s != NULL && strcmp (s, "yes") == 0);
  if (prem_req_end)
    {
      l += 36;
      ret2 = g_malloc0 (l + 1);
      n_slash += 4;

      s = gizmo;
      *s++ = lrand48 () % 26 + 'A';
      for (i = 1; i < 8; i++)
        *s++ = lrand48 () % 26 + 'a';
      *s++ = '\0';
      snprintf (ret2, l, "/%%20HTTP/1.0%%0d%%0a%s:%%20/../..%s", gizmo, ret);
      g_free (ret);
      ret = ret2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/param_hiding");
  param_hiding = (s != NULL && strcmp (s, "yes") == 0);
  if (param_hiding)
    {
      l += 25;
      ret2 = g_malloc0 (l + 1);
      n_slash += 2;

      s = gizmo;
      for (i = 0; i < 8; i++)
        *s++ = lrand48 () % 26 + 'a';
      *s++ = '\0';
      snprintf (ret2, l, "/index.htm%%3f%s=/..%s", gizmo, ret);
      g_free (ret);
      ret = ret2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/double_slash");
  double_slash = (s != NULL && strcmp (s, "yes") == 0);
  if (double_slash)
    {
      l += n_slash;

      ret2 = g_malloc0 (l + 1);
      for (s = ret, s2 = ret2; *s != '\0' && *s != '?'; s++)
        if (*s != '/')
          *s2++ = *s;
        else
          {
            *s2++ = '/';
            *s2++ = '/';
          }
      while (*s != '\0')
        *s2++ = *s++;
      *s2 = '\0';
      g_free (ret);
      ret = ret2;
      n_slash *= 2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/dos_win_syntax");
  dos_win_syntax = (s != NULL && strcmp (s, "yes") == 0);
  if (dos_win_syntax)
    {
      for (s = ret + 1; *s != '\0' && *s != '?'; s++)
        if (*s == '/')
          {
            *s = '\\';
            n_backslash++;
          }
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  s = kb_item_get_str (kb, "NIDS/HTTP/URL_encoding");
  url_encoding = URL_CODE_NONE;
  if (s != NULL)
    {
      if (strcmp (s, "Hex") == 0)
        url_encoding = URL_CODE_HEX;
      else if (strcmp (s, "UTF-16 (double byte)") == 0)
        url_encoding = URL_CODE_UTF16;
      else if (strcmp (s, "UTF-16 (MS %u)") == 0)
        url_encoding = URL_CODE_UTF16MS;
      else if (strcmp (s, "Incorrect UTF-8") == 0)
        url_encoding = URL_CODE_UTF8BAD;
    }


  switch (url_encoding)
    {
    case URL_CODE_UTF16:
    case URL_CODE_UTF16MS:
    case URL_CODE_UTF8BAD:
      /* Let's try first without encoding [back]slashes */
      l = (l - n_slash - n_backslash) * 6 + n_slash + n_backslash;
      break;
    case URL_CODE_HEX:
      /* We do not encode slashes, as this does not work against Apache,
       * at least apache-1.3.22-2 from redhat */
      l = (l - n_slash) * 3 + n_slash;
      break;
    }

  if (url_encoding != URL_CODE_NONE)
    {
      ret2 = g_malloc0 (l + 1);

      for (s = ret, s2 = ret2; *s != '\0'; s++)
        if (*s == '/'
            ||
            ((url_encoding == URL_CODE_UTF8BAD || url_encoding == URL_CODE_UTF16
              || url_encoding == URL_CODE_UTF16MS) && *s == '\\'))
          *s2++ = *s;
        else if (s[0] == '%' && isxdigit (s[1]) && isxdigit (s[2]))
          {
            /* Already % encoded. Do not change it! */
            *s2++ = *s++;
            *s2++ = *s++;
            *s2++ = *s;
          }
        else if (s[0] == '%' && tolower (s[1]) == 'u' && isxdigit (s[2])
                 && isxdigit (s[3]) && isxdigit (s[4]) && isxdigit (s[5]))
          {
            /* Already %u encoded. Do not change it! */
            *s2++ = *s++;
            *s2++ = *s++;
            *s2++ = *s++;
            *s2++ = *s++;
            *s2++ = *s;
          }
        else if (url_encoding == URL_CODE_UTF16MS)
          {
            sprintf (s2, "%%u00%02x", *(unsigned char *) s);
            /* The argument MUST be "unsigned char" */
            s2 += 6;
          }
        else if (url_encoding == URL_CODE_UTF16)
          {
            sprintf (s2, "%%00%%%02x", *(unsigned char *) s);
            /* The argument MUST be "unsigned char" */
            s2 += 6;
          }
        else if (url_encoding == URL_CODE_UTF8BAD)
          {
            unsigned char c = *(unsigned char *) s;
            sprintf (s2, "%%%02x%%%02x", 0xC0 | (c >> 6), 0x80 | (c & 0x3F));
            s2 += 6;
            /* Note: we could also use the raw unencoded characters */
          }
        else
          {
            sprintf (s2, "%%%02x", *(unsigned char *) s);
            /* The argument MUST be "unsigned char", so that it stays between
             * 0 and 255. Otherwise, we might get something like %FFFFFF42 */
            s2 += 3;
            if (*s == '\\')
              n_backslash--;
          }
      *s2 = '\0';
      g_free (ret);
      ret = ret2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }

  abs_URI_type = kb_item_get_str (kb, "NIDS/HTTP/absolute_URI/type");
  if (start_with_slash && abs_URI_type != NULL
      && strcmp (abs_URI_type, "none") != 0)
    {
#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	64
#endif
      char h[MAXHOSTNAMELEN];

      abs_URI_host = kb_item_get_str (kb, "NIDS/HTTP/absolute_URI/host");
      h[0] = '\0';
      if (abs_URI_host != NULL)
        {
          if (strcmp (abs_URI_host, "host name") == 0)
            {
              if ((s = (char *) plug_get_hostname (data)) != NULL)
                strncpy (h, s, sizeof (h));
              h[sizeof (h) - 1] = '\0';
            }
          else if (strcmp (abs_URI_host, "host IP") == 0)
            {
              struct in6_addr *ptr;

              if ((ptr = plug_get_host_ip (data)) != NULL)
                {
                  char *asc = addr6_as_str (ptr);
                  strncpy (h, asc, sizeof (h));
                  g_free (asc);
                }
              h[sizeof (h) - 1] = '\0';
            }
          else if (strcmp (abs_URI_host, "random name") == 0)
            {
              for (s2 = h, i = 0; i < 16; i++)
                *s2++ = lrand48 () % 26 + 'a';
              *s2++ = '\0';
            }
          else if (strcmp (abs_URI_host, "random IP") == 0)
            sprintf (h, "%d.%d.%d.%d", rand () % 256, rand () % 256,
                     rand () % 256, rand () % 256);
        }

      l += strlen (h) + strlen (abs_URI_type) + 3;
      ret2 = g_malloc0 (l + 1);

      snprintf (ret2, l, "%s://%s%s", abs_URI_type, h, ret);
      g_free (ret);
      ret = ret2;
#ifdef URL_DEBUG
      g_message ("Request =  %s", ret);
#endif
    }


  s = kb_item_get_str (kb, "NIDS/HTTP/null_method");
  null_method = (s != NULL && strcmp (s, "yes") == 0);
  if (null_method)
    {
      l += 3;
      ret2 = g_malloc0 (l + 1);
      strncpy (ret2, "%00", l);
      strncpy (ret2 + 3, ret, (l - 3));
      g_free (ret);
      ret = ret2;
    }

  l += strlen (method) + 1;

  s = kb_item_get_str (kb, "NIDS/HTTP/http09");
  http09 = (s != NULL && strcmp (s, "yes") == 0);
  if (!http09)
    {
      s = kb_item_get_str (kb, "NIDS/HTTP/protocol_string");
      if (s != NULL && *s != '\0')
        httpver = s;
      l += strlen (httpver) + 2;
    }


  s = kb_item_get_str (kb, "NIDS/HTTP/tab_separator");
  tab_sep = (s != NULL && strcmp (s, "yes") == 0);
  sep_c = (tab_sep ? '\t' : ' ');

  ret2 = g_malloc0 (l + 1);
  if (http09)
    snprintf (ret2, l, "%s%c%s", method, sep_c, ret);
  else
    snprintf (ret2, l, "%s%c%s%c%s", method, sep_c, ret, sep_c, httpver);
  g_free (ret);
  ret = ret2;

#ifdef URL_DEBUG
  g_message ("Request <= %s", ret);
#endif
  return ret;
}
