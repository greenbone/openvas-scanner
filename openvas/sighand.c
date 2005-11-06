/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 *
 * Signals handler
 */

#include <includes.h>
#include "nsr_output.h"
#include "error_dialog.h"
#include "globals.h"
#include "backend.h"
#include "auth.h"


void
nessus_exit(code)
 int code;
{
 backend_clear_all();
 exit(code);
}
void 
sighand_pipe()
{
#ifdef USE_GTK
  if(!F_quiet_mode)
   show_error_and_wait("Connection closed by the server (SIGPIPE caught)");
  else
#endif
  fprintf(stderr, "Connection closed by the server (SIGPIPE caught)\n");  
}


void 
sighand_alarm()
{
#ifdef USE_GTK
  if(!F_quiet_mode)show_error_and_wait("Connection timed out");
  else
#endif
 fprintf(stderr, "Connection timed out\n");  
}
 
void sighand_exit()
{
 if(GlobalSocket > 0)
 {
   network_printf( "CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n");
#ifdef NESSUS_ON_SSL
   close_stream_connection(GlobalSocket);
#else   
   shutdown(GlobalSocket, 2);
   closesocket(GlobalSocket);
#endif   
   GlobalSocket = -1;
 }
 nessus_exit (1);
}
