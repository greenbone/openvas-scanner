/* OpenVAS Libraries
 * $Id$
 * Description: Defines for internal communication of scanner instances.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef _INTERNAL_COM_H
#define _INTERNAL_COM_H

#define INTERNAL_COMM_MSG_TYPE_CTRL (1 << 16)
#define INTERNAL_COMM_MSG_TYPE_DATA (1 << 18)

#define INTERNAL_COMM_CTRL_FINISHED (1 << 0)
#define INTERNAL_COMM_CTRL_ACK      (1 << 1)

#endif /* not _INTERNAL_COM_H */
