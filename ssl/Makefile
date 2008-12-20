# OpenVAS
# $Id$
# Description: Makefile for the entropy generator openvas-mkrand.c.
#
# Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
#          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
#          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
#          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
#
# Copyright:
# Portions Copyright (C) 2006 Software in the Public Interest, Inc.
# Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
#
#


include ../openvas.tmpl


OBJS = openvas-mkrand.o 

all : openvas-mkrand

openvas-mkrand: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o openvas-mkrand -lm

openvas-mkrand.o: openvas-mkrand.c
	$(CC) $(CFLAGS) -c openvas-mkrand.c 

clean : 
	rm -f *.o openvas-mkrand
