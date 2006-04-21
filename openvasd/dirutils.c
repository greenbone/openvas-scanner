/* OpenVAS
 * Copyright (C) 1998 - 2004 Renaud Deraison
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <includes.h>

#ifdef _UNUSED_
static char * env = "OPENVAS_HOME";
static char * home_dir = NULL;
char * OPENVASD_CONFDIR = NULL;
char * OPENVASD_STATEDIR = 0;
char * OPENVASD_DATADIR = 0;
char * OPENVASD_LIBDIR = 0;
char * OPENVASD_PLUGINS = 0;
char * OPENVASD_REPORTS = 0;
char * OPENVASD_LOGINS = 0;
char * OPENVASD_LOGS = 0;
char * OPENVASD_JOBS = 0;
char * OPENVASD_CONF = 0;
char * OPENVASD_DATAPOOL = 0;
char * OPENVASD_RULES = 0;
char * OPENVASD_USERS = 0;
char * OPENVASD_USERPWDS = 0;
char * OPENVASD_KEYFILE = 0;
char * OPENVASD_LOGPIPE = 0;
char * OPENVASD_MESSAGES = 0;
char * OPENVASD_DEBUGMSG = 0;
char * OPENVASD_USERKEYS = 0;
#endif

int init_directories() {
#ifndef _UNUSED_
  	return 0;
#else		
	char *buf;
	char * p = getenv(env);
	if(!p)
		return -1;

	home_dir = strdup(p);
	buf = malloc(4096);

	sprintf(buf, "%s/etc", home_dir); 
	OPENVASD_CONFDIR = strdup(buf);

	sprintf(buf, "%s/var/openvas", home_dir); 
	OPENVASD_STATEDIR = strdup(buf);

	sprintf(buf, "%s/etc/openvas", home_dir); 
	OPENVASD_DATADIR = strdup(buf);

	sprintf(buf, "%s/lib/openvas", home_dir); 
	OPENVASD_LIBDIR = strdup(buf);

	sprintf(buf, "%s/lib/openvas/plugins", home_dir); 
	OPENVASD_PLUGINS = strdup(buf);

	sprintf(buf, "%s/lib/openvas/reports", home_dir); 
	OPENVASD_REPORTS = strdup(buf);

	sprintf(buf, "%s/logs", OPENVASD_STATEDIR); 
	OPENVASD_LOGS = strdup(buf);

	sprintf(buf, "%s/users", OPENVASD_STATEDIR); 
	OPENVASD_LOGINS = strdup(buf);

	sprintf(buf, "%s/jobs", OPENVASD_STATEDIR); 
	OPENVASD_JOBS = strdup(buf);

	sprintf(buf, "%s/openvas/openvasd.conf", OPENVASD_CONFDIR); 
	OPENVASD_CONF = strdup(buf);

	sprintf(buf, "%s/-datapool", OPENVASD_STATEDIR); 
	OPENVASD_DATAPOOL = strdup(buf);

	sprintf(buf, "%s/openvasd.rules", OPENVASD_DATADIR); 
	OPENVASD_RULES = strdup(buf);

	sprintf(buf, "%s/openvasd.users", OPENVASD_DATADIR); 
	OPENVASD_USERS = strdup(buf);

	sprintf(buf, "%s/openvasd.user-pwds", OPENVASD_DATADIR); 
	OPENVASD_USERPWDS = strdup(buf);

	sprintf(buf, "%s/openvasd.private-keys", OPENVASD_DATADIR); 
	OPENVASD_KEYFILE = strdup(buf);

	sprintf(buf, "%s/openvasd.logpipe", OPENVASD_DATADIR); 
	OPENVASD_LOGPIPE = strdup(buf);

	sprintf(buf, "%s/openvasd.messages", OPENVASD_LOGS); 
	OPENVASD_MESSAGES = strdup(buf);

	sprintf(buf, "%s/openvasd.dump", OPENVASD_LOGS); 
	OPENVASD_DEBUGMSG = strdup(buf);

	sprintf(buf, "%s/auth/openvasd.user-keys", OPENVASD_DATADIR);
	OPENVASD_USERKEYS = strdup(buf);

	free(buf);
	return 0;
#endif	
}
