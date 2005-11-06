/* Nessus
 * Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 */

#ifndef _NESSUSC_PREFERENCES_H
#define _NESSUSC_PREFERENCES_H

int    preferences_init(struct arglist **);
void   preferences_save(struct arglist *);
void   preferences_save_fname(char*, struct arglist*);
int    pluginset_apply(struct arglist *, char *);
void   pluginset_reload(struct arglist *, struct arglist *);
void   prefs_check_defaults(struct arglist *);
int    preferences_process(char *, struct arglist *);
int    preferences_generate_new_file();
char * plugin_asc_id(struct arglist*);
char * preferences_get_filename();
char * preferences_get_altname(const char*);

#ifdef _WIN32
/* applies to some windows misunderstanding */
#define CANNOT_SET_HOMEVAR "\
There is no personal directory known, where Nessus can store the key\n\
and the configuration cache.\n\
\n\
So please set the environment variable NESSUSHOME with explicit path\n\
(eg. C:\\WHAT\\SO\\EVER\\...) to some existing directory.  Make sure that\n\
this variable is set every time you have Windows rebooted.\n\
\n\
Having finshed with the NESSUSHOME variable, close all message boxes\n\
to terminate Nessus, then restart Nessus, again."

#else /* not  _WIN32 */
#define CANNOT_SET_HOMEVAR "\
Your HOME environment variable might be unset,  or your home directiory\n\
might be unaccessable.  So you need to check/set your HOME variable.\n\
\n\
In case you do not want to change HOME, you can alternatively set the\n\
variable NESSUSHOME, instead (do not forget to \"export NESSUSHOME;\"\n\
after setting it.  NESSUSHOME overwrites the meaning of HOME for this\n\
application."
#endif /* _WIN32 */

#endif
