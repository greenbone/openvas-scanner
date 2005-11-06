/* Nessus
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
static char * env = "NESSUS_HOME";
static char * home_dir = NULL;
char * NESSUSD_CONFDIR = NULL;
char * NESSUSD_STATEDIR = 0;
char * NESSUSD_DATADIR = 0;
char * NESSUSD_LIBDIR = 0;
char * NESSUSD_PLUGINS = 0;
char * NESSUSD_REPORTS = 0;
char * NESSUSD_LOGINS = 0;
char * NESSUSD_LOGS = 0;
char * NESSUSD_JOBS = 0;
char * NESSUSD_CONF = 0;
char * NESSUSD_DATAPOOL = 0;
char * NESSUSD_RULES = 0;
char * NESSUSD_USERS = 0;
char * NESSUSD_USERPWDS = 0;
char * NESSUSD_KEYFILE = 0;
char * NESSUSD_LOGPIPE = 0;
char * NESSUSD_MESSAGES = 0;
char * NESSUSD_DEBUGMSG = 0;
char * NESSUSD_USERKEYS = 0;
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
	NESSUSD_CONFDIR = strdup(buf);

	sprintf(buf, "%s/var/nessus", home_dir); 
	NESSUSD_STATEDIR = strdup(buf);

	sprintf(buf, "%s/etc/nessus", home_dir); 
	NESSUSD_DATADIR = strdup(buf);

	sprintf(buf, "%s/lib/nessus", home_dir); 
	NESSUSD_LIBDIR = strdup(buf);

	sprintf(buf, "%s/lib/nessus/plugins", home_dir); 
	NESSUSD_PLUGINS = strdup(buf);

	sprintf(buf, "%s/lib/nessus/reports", home_dir); 
	NESSUSD_REPORTS = strdup(buf);

	sprintf(buf, "%s/logs", NESSUSD_STATEDIR); 
	NESSUSD_LOGS = strdup(buf);

	sprintf(buf, "%s/users", NESSUSD_STATEDIR); 
	NESSUSD_LOGINS = strdup(buf);

	sprintf(buf, "%s/jobs", NESSUSD_STATEDIR); 
	NESSUSD_JOBS = strdup(buf);

	sprintf(buf, "%s/nessus/nessusd.conf", NESSUSD_CONFDIR); 
	NESSUSD_CONF = strdup(buf);

	sprintf(buf, "%s/-datapool", NESSUSD_STATEDIR); 
	NESSUSD_DATAPOOL = strdup(buf);

	sprintf(buf, "%s/nessusd.rules", NESSUSD_DATADIR); 
	NESSUSD_RULES = strdup(buf);

	sprintf(buf, "%s/nessusd.users", NESSUSD_DATADIR); 
	NESSUSD_USERS = strdup(buf);

	sprintf(buf, "%s/nessusd.user-pwds", NESSUSD_DATADIR); 
	NESSUSD_USERPWDS = strdup(buf);

	sprintf(buf, "%s/nessusd.private-keys", NESSUSD_DATADIR); 
	NESSUSD_KEYFILE = strdup(buf);

	sprintf(buf, "%s/nessusd.logpipe", NESSUSD_DATADIR); 
	NESSUSD_LOGPIPE = strdup(buf);

	sprintf(buf, "%s/nessusd.messages", NESSUSD_LOGS); 
	NESSUSD_MESSAGES = strdup(buf);

	sprintf(buf, "%s/nessusd.dump", NESSUSD_LOGS); 
	NESSUSD_DEBUGMSG = strdup(buf);

	sprintf(buf, "%s/auth/nessusd.user-keys", NESSUSD_DATADIR);
	NESSUSD_USERKEYS = strdup(buf);

	free(buf);
	return 0;
#endif	
}
