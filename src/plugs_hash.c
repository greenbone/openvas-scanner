/* OpenVAS
* $Id$
* Description: Calculates hash values of plugins, calculates the hash value of all hashes.
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

#include <stdio.h>    /* for snprintf() */
#include <fcntl.h>    /* for open() */
#include <sys/stat.h> /* for fstat() */
#include <unistd.h>   /* for close() */
#include <sys/mman.h> /* for mmap() */
#include <dirent.h>   /* for opendir() */
#include <errno.h>    /* for errno() */

#include <openvas/base/nvti.h>       /* for nvti_t */
#include <openvas/misc/network.h>    /* for auth_printf */
#include <openvas/misc/share_fd.h>   /* for send_fd */
#include <openvas/misc/system.h>     /* for efree */

#include <openvas/base/nvticache.h>     /* for nvticache_t */

#include <gcrypt.h>
#include "log.h"

/*
 * Creates an emalloc'ed string with a hexadecimal representation of the
 * binary md5sum md.
 */
char *
md5sum_hex (const unsigned char *md)
{
  char *ret = emalloc (33);
  int i;

  for (i = 0; i < 16; i++)
    {
      snprintf (ret + i * 2, 3, "%02x", md[i]);
    }

  return ret;
}

char *
file_hash (fname)
     char *fname;
{
  struct stat st;
  int fd = open (fname, O_RDONLY);
  char *content;
  int len;

  if (fd < 0)
    return NULL;

  fstat (fd, &st);

  len = (int) st.st_size;
  content = mmap (NULL, len, PROT_READ, MAP_SHARED, fd, 0);
  if (content && (content != MAP_FAILED))
    {
      unsigned char digest[16];
      gcry_md_hash_buffer (GCRY_MD_MD5, digest, content, len);
      char *ret = md5sum_hex (digest);
      munmap (content, len);
      close (fd);
      return ret;
    }
  return NULL;
}


/*
 * Returns a hash of each plugin hash
 */
static void
dir_plugins_hash (gcry_md_hd_t ctx, char *dirname)
{
  DIR *dir;
  struct dirent *dp;


  if (!dirname)
    return;

  dir = opendir (dirname);
  if (!dir)
    {
      log_write ("plugins_hash(): could not open %s - %s\n", dirname,
                 strerror (errno));
      return;
    }


  while ((dp = readdir (dir)))
    {
      char fullname[PATH_MAX + 1];
      char *tmp;
      if ((strlen (dirname) + strlen (dp->d_name) + 1) >
          (sizeof (fullname) - 1))
        {
          log_write ("plugins_hash(): filename too long\n");
          continue;
        }

      if (dp->d_name[0] == '.')
        continue;               /* Skip .dot files */

      bzero (fullname, sizeof (fullname));
      strcat (fullname, dirname);
      strcat (fullname, "/");
      strcat (fullname, dp->d_name);
      tmp = file_hash (fullname);
      if (tmp != NULL)
        {
          gcry_md_write (ctx, tmp, strlen (tmp));
          efree (&tmp);
        }
    }
  closedir (dir);
}


/*
 * returns the hash of the hashes of the plugins in the plugins dir. Returns
 * NULL in case of severe errors (for instance if libgrypt cannot initialize
 * the md5 message digest object).
 */
char *
plugins_hash (globals)
     struct arglist *globals;
{
  struct arglist *preferences = arg_get_value (globals, "preferences");
  char *dir = arg_get_value (preferences, "plugins_folder");
  gcry_md_hd_t ctx;
  gcry_error_t err;
  unsigned char *digest;
  char *ret;

  err = gcry_md_open (&ctx, GCRY_MD_MD5, 0);
  if (err)
    {
      log_write ("plugins_hash(): gcry_md_open failed: %s/%s\n",
                 gcry_strsource (err), gcry_strerror (err));
      return NULL;
    }

  /* FIXME: check for error return from gcry_md_open */
  dir_plugins_hash (ctx, dir);
  digest = gcry_md_read (ctx, GCRY_MD_MD5);
  ret = md5sum_hex (digest);
  gcry_md_close (ctx);
  return ret;
}

void
plugins_send_md5 (struct arglist *globals)
{
  struct arglist *plugins = arg_get_value (globals, "plugins");
  nvticache_t *nvticache = (nvticache_t *)arg_get_value (globals, "nvticache");

  auth_printf (globals, "SERVER <|> PLUGINS_MD5\n");

  if (plugins == NULL)
    return;

  while (plugins->next != NULL)
    {
      char *oid = (char *)arg_get_value (plugins->value, "OID");
      nvti_t *nvti = (oid == NULL ? NULL : nvticache_get_by_oid (nvticache, oid));
      char *md5 = file_hash ((char *)nvti_src (nvti));
      auth_printf (globals, "%s <|> %s\n", oid, md5);
      efree (&md5);
      plugins = plugins->next;
    }
  auth_printf (globals, "<|> SERVER\n");
}
