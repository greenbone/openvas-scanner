/* OpenVAS
* $Id$
* Description: Authentication manager.
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
*
*
*/ 

/*
 * This authentification scheme is BADLY written, and will NOT
 * be used in the future
 *
 */


#include <includes.h>
#include <stdarg.h>
#include "rules.h"
#include "comm.h"
#include "auth.h"
#include "log.h"
#include "sighand.h"


/*
 * auth_check_user() :
 *
 * Checks if a user has the right to use openvasd,
 * and return its permissions
 */
struct openvas_rules * 
auth_check_user(globals, from, dname)
   struct arglist * globals;
   char * from;
   char * dname;
{
  char * buf_user, * buf_password;
  int free_buf_user = 1;
  struct openvas_rules * permissions;
  {
    int l;

    buf_user = emalloc(255);
    buf_password = emalloc(255);
  
    auth_printf(globals,"User : ");
    auth_gets(globals, buf_user, 254);
    if( buf_user[0] == '\0' ) {
		EXIT(0);
    }
  
    auth_printf(globals, "Password : ");
    auth_gets(globals, buf_password, 254);
    if( buf_password[0] == '\0' ) {
	EXIT(0);
    }
  
    l = strlen(buf_user);
    if (l  &&  buf_user[l - 1] == '\n')buf_user[--l] = '\0';
    if (l  &&  buf_user[l - 1] == '\r')buf_user[--l] = '\0';
    
  
    l = strlen(buf_password);
    if (l  &&  buf_password[l - 1] == '\n')buf_password[--l] = '\0';
    if (l  &&  buf_password[l - 1] == '\r')buf_password[--l] = '\0';
  }

  if((permissions = check_user(buf_user, buf_password, dname))
     && (permissions != BAD_LOGIN_ATTEMPT))
  {
	char* user = emalloc(strlen(buf_user)+1);
	strncpy(user, buf_user, strlen(buf_user));

	log_write("successful login of %s from %s\n", buf_user, from);
	if(arg_get_value(globals, "user"))
	 arg_set_value(globals, "user", strlen(user), user);
	else
	 arg_add_value(globals, "user", ARG_STRING, strlen(user), user);
  }
  if(free_buf_user)efree(&buf_user);
  efree(&buf_password);
  return(permissions);
}


