# OpenVAS
# $Id$
# Description: Makefile for gmo scripts
#
# Authors: - Jan-Oliver Wagner <jan@intevation.de> (Original develoment)
#          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
#          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
#
# Copyright:
# Copyright (C) 2006 Software in the Public Interest, Inc.
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

datadir = ${prefix}/share
localedir = $(datadir)/locale

INSTALL_DATA = ${INSTALL} -m 644

.SUFFIXES: .po .gmo

.po.gmo:
	@lang=`echo $* | sed -e 's,.*/,,'`; \
	test "$(srcdir)" = . && cdcmd="" || cdcmd="cd $(srcdir) && "; \
	echo "$${cdcmd}rm -f $${lang}.gmo && $(GMSGFMT) -c --statistics -o $${lang}.gmo $${lang}.po"; \
	cd $(srcdir) && rm -f $${lang}.gmo && $(GMSGFMT) -c --statistics -o t-$${lang}.gmo $${lang}.po && mv t-$${lang}.gmo $${lang}.gmo

# Attention: this is a handcrafted direct hack to get the
# german translations of the scripts installed with a single
# make command.
install-openvas-scripts: openvas-scripts-de.gmo
	$(INSTALL_DATA) openvas-scripts-de.gmo \
		$(localedir)/de/LC_MESSAGES/openvas-scripts.mo
