/* OpenVAS
* $Id$
* Description: Provides somekind of remote plugin upload service.
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


#include <includes.h>
#include "preferences.h"
#include "users.h"
#include "log.h"
#include "pluginload.h"


int
plugin_recv(struct arglist * globals)
{
  int soc = (int)arg_get_value(globals, "global_socket");
  int n;
  long bytes = 0;
  char input[4096];

  /* Read and ignore the "name:" line */
  n = recv_line(soc, input, sizeof(input) - 1);
  if (n <= 0)
    return -1;
  if (strncmp(input, "name: ", strlen("name: ")) != 0)
    return -1;

  /* Read and ignore the "content:" line */
  n = recv_line(soc, input, sizeof(input) - 1);
  if (n <= 0)
    return -1;

  /* Read and parse the "bytes:" line */
  n = recv_line(soc, input, sizeof(input) - 1);
  if (n <= 0)
    return -1;

  if (!strncmp(input, "bytes: ", strlen("bytes: ")))
    {
      char * t = input + strlen("bytes: ");
      bytes = atol(t);
    }
  else
    return -1;

  /* Don't accept plugins bigger than 5Mb */
  if (bytes > 5*1024*1024)
    return -1;

  /*
   * Read and discard the <bytes> bytes with the actual plugin.
   */
  while (bytes > 0)
    {
      int e;
      int chunk_size = bytes < sizeof(input) ? bytes : sizeof(input);
      e = read_stream_connection_min(soc, input, chunk_size, chunk_size);
      if (e <= 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    break;
	}
      bytes -= e;
    }

  /* Always deny the upload since openvasd does not support it */
  auth_printf(globals, "SERVER <|> PLUGIN_DENIED <|> SERVER\n");

  return 0;
}
