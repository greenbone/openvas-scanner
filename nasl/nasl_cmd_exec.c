/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
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

/**
 * @brief
 * This file contains all the "unsafe" functions found in NASL.
 */

#include <errno.h>              /* for errno */
#include <fcntl.h>              /* for open */
#include <glib.h>               /* for g_get_tmp_dir */
#include <signal.h>             /* for kill */
#include <string.h>             /* for strncpy */
#include <sys/wait.h>           /* for waitpid */
#include <sys/stat.h>           /* for stat */
#include <sys/param.h>          /* for MAXPATHLEN */
#include <unistd.h>             /* for getcwd */

#include "../misc/plugutils.h"          /* for find_in_path */
#include "../misc/popen.h"              /* for openvas_popen4 */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"

#include "nasl_cmd_exec.h"
#include "nasl_debug.h"

static pid_t pid = 0;
static void (*old_sig_t) () = NULL, (*old_sig_i) () = NULL, (*old_sig_c) = NULL;

static void
sig_h ()
{
  if (pid > 0)
    (void) kill (pid, SIGKILL);
}

static void
sig_c ()
{
  if (pid > 0)
    (void) waitpid (pid, NULL, WNOHANG);
}

/** @todo Supspects to glib replacements, all path related stuff. */
tree_cell *
nasl_pread (lex_ctxt * lexic)
{
  tree_cell *retc = NULL, *a;
  anon_nasl_var *v;
  nasl_array *av;
  int i, j, n, sz, sz2, cd, nice;
  char **args = NULL, *cmd, *str, *str2, buf[8192];
  FILE *fp;
  char cwd[MAXPATHLEN], newdir[MAXPATHLEN];

  if (pid != 0)
    {
      nasl_perror (lexic, "nasl_pread is not reentrant!\n");
      return NULL;
    }

  a = get_variable_by_name (lexic, "argv");
  cmd = get_str_local_var_by_name (lexic, "cmd");
  if (cmd == NULL || a == NULL || (v = a->x.ref_val) == NULL)
    {
      deref_cell (a);
      nasl_perror (lexic, "pread() usage: cmd:..., argv:...\n");
      return NULL;
    }
  deref_cell (a);

  nice = get_int_local_var_by_name (lexic, "nice", 0);

  if (v->var_type == VAR2_ARRAY)
    av = &v->v.v_arr;
  else
    {
      nasl_perror (lexic, "pread: argv element must be an array (0x%x)\n",
                   v->var_type);
      return NULL;
    }

  cd = get_int_local_var_by_name (lexic, "cd", 0);

  cwd[0] = '\0';
  if (cd)
    {
      char *p;

      if (cmd[0] == '/')
        {
          strncpy (newdir, cmd, sizeof (newdir) - 1);
          p = strrchr (newdir, '/');
          if (p != newdir)
            *p = '\0';
        }
      else
        {
          p = find_in_path (cmd, 0);
          if (p != NULL)
            strncpy (newdir, p, sizeof (newdir) - 1);
          else
            {
              nasl_perror (lexic, "pread: '%s' not found in $PATH\n", cmd);
              return NULL;
            }

        }
      newdir[sizeof (newdir) - 1] = '\0';

      if (getcwd (cwd, sizeof (cwd)) == NULL)
        {
          nasl_perror (lexic, "pread(): getcwd: %s\n", strerror (errno));
          *cwd = '\0';
        }

      if (chdir (newdir) < 0)
        {
          nasl_perror (lexic, "pread: could not chdir to %s\n", newdir);
          return NULL;
        }
      if (cmd[0] != '/' && strlen (newdir) + strlen (cmd) + 1 < sizeof (newdir))
        {
          strcat (newdir, "/");
          strcat (newdir, cmd);
          cmd = newdir;
        }
    }

  if (av->hash_elt != NULL)
    nasl_perror (lexic, "pread: named elements in 'cmd' are ignored!\n");
  n = av->max_idx;
  args = g_malloc0 (sizeof (char **) * (n + 2));  /* Last arg is NULL */
  for (j = 0, i = 0; i < n; i++)
    {
      str = (char *) var2str (av->num_elt[i]);
      if (str != NULL)
        args[j++] = g_strdup (str);
    }
  args[j++] = NULL;

  old_sig_t = signal (SIGTERM, sig_h);
  old_sig_i = signal (SIGINT, sig_h);
  old_sig_c = signal (SIGCHLD, sig_c);

  fp = openvas_popen4 ((const char *) cmd, args, &pid, nice);

  for (i = 0; i < n; i++)
    g_free (args[i]);
  g_free (args);

  if (fp != NULL)
    {
      sz = 0;
      str = g_malloc0 (1);

      errno = 0;
      while ((n = fread (buf, 1, sizeof (buf), fp)) > 0 || errno == EINTR)      /* && kill(pid, 0) >= 0) */
        {
          if (errno == EINTR)
            {
              errno = 0;
              continue;
            }
          sz2 = sz + n;
          str2 = g_realloc (str, sz2);
          str = str2;
          memcpy (str + sz, buf, n);
          sz = sz2;
        }
      if (ferror (fp) && errno != EINTR)
        nasl_perror (lexic, "nasl_pread: fread(): %s\n", strerror (errno));

      (void) openvas_pclose (fp, pid);
      pid = 0;

      if (*cwd != '\0')
        if (chdir (cwd) < 0)
          nasl_perror (lexic, "pread(): chdir(%s): %s\n", cwd,
                       strerror (errno));

      retc = alloc_typed_cell (CONST_DATA);
      retc->x.str_val = str;
      retc->size = sz;
    }

  signal (SIGINT, old_sig_i);
  signal (SIGTERM, old_sig_t);
  signal (SIGCHLD, old_sig_c);

  return retc;
}

tree_cell *
nasl_find_in_path (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *cmd;

  cmd = get_str_var_by_num (lexic, 0);
  if (cmd == NULL)
    {
      nasl_perror (lexic, "find_in_path() usage: cmd\n");
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = (find_in_path (cmd, 0) != NULL);
  return retc;
}

/*
 * Not a command, but dangerous anyway
 */
/**
 * @brief Read file
 * @ingroup nasl_implement
 */
tree_cell *
nasl_fread (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *fname;
  struct stat lstat_info, fstat_info;
  int fd;
  char *buf, *p;
  int alen, len, n;
  FILE *fp;

  fname = get_str_var_by_num (lexic, 0);
  if (fname == NULL)
    {
      nasl_perror (lexic, "fread: need one argument (file name)\n");
      return NULL;
    }

  if (lstat (fname, &lstat_info) == -1)
    {
      if (errno != ENOENT)
        {
          nasl_perror (lexic, "fread: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
      fd = open (fname, O_RDONLY | O_EXCL, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "fread: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
    }
  else
    {
      fd = open (fname, O_RDONLY | O_EXCL, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "fread: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      if (fstat (fd, &fstat_info) == -1)
        {
          close (fd);
          nasl_perror (lexic, "fread: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      else
        {
          if (lstat_info.st_mode != fstat_info.st_mode
              || lstat_info.st_ino != fstat_info.st_ino
              || lstat_info.st_dev != fstat_info.st_dev)
            {
              close (fd);
              nasl_perror (lexic, "fread: %s: possible symlink attack!?!\n",
                           fname);
              return NULL;
            }
        }
    }
  fp = fdopen (fd, "r");
  if (fp == NULL)
    {
      close (fd);
      nasl_perror (lexic, "fread: %s: %s\n", fname, strerror (errno));
      return NULL;
    }

  alen = lstat_info.st_size + 1;
  buf = g_malloc0 (alen);
  len = 0;
  while ((n = fread (buf + len, 1, alen - len, fp)) > 0)
    {
      len += n;
      if (alen <= len)
        {
          alen += 4096;
          p = g_realloc (buf, alen);
          buf = p;
        }
    }

  buf[len] = '\0';
  if (alen > len + 1)
    {
      p = g_realloc (buf, len + 1);
      buf = p;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = buf;
  fclose (fp);
  return retc;
}

/*
 * Not a command, but dangerous anyway
 */
/**
 * @brief Unlink file
 * @ingroup nasl_implement
 */
tree_cell *
nasl_unlink (lex_ctxt * lexic)
{
  char *fname;

  fname = get_str_var_by_num (lexic, 0);
  if (fname == NULL)
    {
      nasl_perror (lexic, "unlink: need one argument (file name)\n");
      return NULL;
    }

  if (unlink (fname) < 0)
    {
      nasl_perror (lexic, "unlink(%s): %s\n", fname, strerror (errno));
      return NULL;
    }
  /* No need to return a value */
  return FAKE_CELL;
}

/* Definitely dangerous too */
/**
 * @brief Write file
 */
tree_cell *
nasl_fwrite (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *content, *fname;
  struct stat lstat_info, fstat_info;
  int fd;
  int len, i, x;
  FILE *fp;

  content = get_str_local_var_by_name (lexic, "data");
  fname = get_str_local_var_by_name (lexic, "file");
  if (content == NULL || fname == NULL)
    {
      nasl_perror (lexic, "fwrite: need two arguments 'data' and 'file'\n");
      return NULL;
    }
  len = get_var_size_by_name (lexic, "data");

  if (lstat (fname, &lstat_info) == -1)
    {
      if (errno != ENOENT)
        {
          nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
      fd = open (fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
    }
  else
    {
      fd = open (fname, O_WRONLY | O_CREAT, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "fwrite: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      if (fstat (fd, &fstat_info) == -1)
        {
          close (fd);
          nasl_perror (lexic, "fwrite: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      else
        {
          if (lstat_info.st_mode != fstat_info.st_mode
              || lstat_info.st_ino != fstat_info.st_ino
              || lstat_info.st_dev != fstat_info.st_dev)
            {
              close (fd);
              nasl_perror (lexic, "fwrite: %s: possible symlink attack!?!\n",
                           fname);
              return NULL;
            }
        }
    }
  if (ftruncate (fd, 0) == -1)
    {
      close (fd);
      nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
      return NULL;
    }
  fp = fdopen (fd, "w");
  if (fp == NULL)
    {
      close (fd);
      nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
      return NULL;
    }

  for (i = 0; i < len;)
    {
      x = fwrite (content + i, 1, len - i, fp);
      if (x > 0)
        i += x;
      else
        {
          nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
          (void) fclose (fp);
          unlink (fname);
          return NULL;
        }
    }

  if (fclose (fp) < 0)
    {
      nasl_perror (lexic, "fwrite: %s: %s\n", fname, strerror (errno));
      unlink (fname);
      return NULL;
    }
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = len;
  return retc;
}



tree_cell *
nasl_get_tmp_dir (lex_ctxt * lexic)
{
  tree_cell *retc;
  char path[MAXPATHLEN];

  snprintf (path, sizeof (path), "%s/", g_get_tmp_dir ());
  if (access (path, R_OK | W_OK | X_OK) < 0)
    {
      nasl_perror (lexic,
                   "get_tmp_dir(): %s not available - check your OpenVAS installation\n",
                   path);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (path);
  retc->size = strlen (retc->x.str_val);

  return retc;
}


/*
 *  File access functions : Dangerous
 */

/**
 * @brief Stat file
 * @ingroup nasl_implement
 */
tree_cell *
nasl_file_stat (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *fname;
  struct stat st;

  fname = get_str_var_by_num (lexic, 0);
  if (fname == NULL)
    {
      nasl_perror (lexic, "file_stat: need one argument (file name)\n");
      return NULL;
    }

  if (stat (fname, &st) < 0)
    return NULL;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = (int) st.st_size;
  return retc;
}

/**
 * @brief Open file
 */
tree_cell *
nasl_file_open (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *fname, *mode;
  struct stat lstat_info, fstat_info;
  int fd;
  int imode = O_RDONLY;

  fname = get_str_local_var_by_name (lexic, "name");
  if (fname == NULL)
    {
      nasl_perror (lexic, "file_open: need file name argument\n");
      return NULL;
    }

  mode = get_str_local_var_by_name (lexic, "mode");
  if (mode == NULL)
    {
      nasl_perror (lexic, "file_open: need file mode argument\n");
      return NULL;
    }

  if (strcmp (mode, "r") == 0)
    imode = O_RDONLY;
  else if (strcmp (mode, "w") == 0)
    imode = O_WRONLY | O_CREAT;
  else if (strcmp (mode, "w+") == 0)
    imode = O_WRONLY | O_TRUNC | O_CREAT;
  else if (strcmp (mode, "a") == 0)
    imode = O_WRONLY | O_APPEND | O_CREAT;
  else if (strcmp (mode, "a+") == 0)
    imode = O_RDWR | O_APPEND | O_CREAT;

  if (lstat (fname, &lstat_info) == -1)
    {
      if (errno != ENOENT)
        {
          nasl_perror (lexic, "file_open: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
      fd = open (fname, imode, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "file_open: %s: %s\n", fname, strerror (errno));
          return NULL;
        }
    }
  else
    {
      fd = open (fname, imode, 0600);
      if (fd < 0)
        {
          nasl_perror (lexic, "file_open: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      if (fstat (fd, &fstat_info) == -1)
        {
          close (fd);
          nasl_perror (lexic, "fread: %s: possible symlink attack!?! %s\n",
                       fname, strerror (errno));
          return NULL;
        }
      else
        {
          if (lstat_info.st_mode != fstat_info.st_mode
              || lstat_info.st_ino != fstat_info.st_ino
              || lstat_info.st_dev != fstat_info.st_dev)
            {
              close (fd);
              nasl_perror (lexic, "fread: %s: possible symlink attack!?!\n",
                           fname);
              return NULL;
            }
        }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = fd;
  return retc;
}

/**
 * @brief Close file
 */
tree_cell *
nasl_file_close (lex_ctxt * lexic)
{
  tree_cell *retc;
  int fd;

  fd = get_int_var_by_num (lexic, 0, -1);
  if (fd < 0)
    {
      nasl_perror (lexic, "file_close: need file pointer argument\n");
      return NULL;
    }

  if (close (fd) < 0)
    {
      nasl_perror (lexic, "file_close: %s\n", strerror (errno));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 0;
  return retc;
}


/**
 * @brief Read file
 */
tree_cell *
nasl_file_read (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *buf;
  int fd;
  int flength;
  int n;

  fd = get_int_local_var_by_name (lexic, "fp", -1);
  if (fd < 0)
    {
      nasl_perror (lexic, "file_read: need file pointer argument\n");
      return NULL;
    }

  flength = get_int_local_var_by_name (lexic, "length", 0);

  buf = g_malloc0 (flength + 1);

  for (n = 0; n < flength;)
    {
      int e;
      errno = 0;
      e = read (fd, buf + n, flength - n);
      if (e < 0 && errno == EINTR)
        continue;
      else if (e <= 0)
        break;
      else
        n += e;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = n;
  retc->x.str_val = buf;
  return retc;
}


/**
 * @brief Write file
 */
tree_cell *
nasl_file_write (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *content;
  int len;
  int fd;
  int n;

  content = get_str_local_var_by_name (lexic, "data");
  fd = get_int_local_var_by_name (lexic, "fp", -1);
  if (content == NULL || fd < 0)
    {
      nasl_perror (lexic, "file_write: need two arguments 'fp' and 'data'\n");
      return NULL;
    }
  len = get_var_size_by_name (lexic, "data");


  for (n = 0; n < len;)
    {
      int e;
      errno = 0;
      e = write (fd, content + n, len - n);
      if (e < 0 && errno == EINTR)
        continue;
      else if (e <= 0)
        {
          nasl_perror (lexic, "file_write: write() failed - %s\n",
                       strerror (errno));
          break;
        }
      else
        n += e;
    }



  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = n;
  return retc;
}

/**
 * @brief Seek in file.
 */
tree_cell *
nasl_file_seek (lex_ctxt * lexic)
{
  tree_cell *retc;
  int fd;
  int foffset;

  foffset = get_int_local_var_by_name (lexic, "offset", 0);
  fd = get_int_local_var_by_name (lexic, "fp", -1);
  if (fd < 0)
    {
      nasl_perror (lexic, "file_seek: need one arguments 'fp'\n");
      return NULL;
    }

  if (lseek (fd, foffset, SEEK_SET) < 0)
    {
      nasl_perror (lexic, "fseek: %s\n", strerror (errno));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 0;
  return retc;
}
