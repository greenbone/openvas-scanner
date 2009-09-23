# OpenVAS
# $Id$
# Description: the OpenVAS Makefile.
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


include openvas.tmpl

ALLDEPS = openvas.tmpl

all: $(ALLDEPS) scanner sslstuff man mknvts


openvas.tmpl: openvas.tmpl.in configure VERSION
	$(SHELL) configure $(CONFIGURE_ARGS)
	touch $@

install: all install-bin install-man install-nvts
	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' openvas-scanner has been sucessfully installed. '
	@echo " Make sure that $(bindir) and $(sbindir) are in your PATH before"
	@echo " you continue."
	@echo " openvassd has been installed into $(sbindir)"
	@echo ' --------------------------------------------------------------'
	@echo

install-bin:
	@test -d $(DESTDIR)${bindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${bindir}
	@test -d $(DESTDIR)${sbindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sbindir}
	@test -d $(DESTDIR)${sysconfdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}
	@test -d $(DESTDIR)${sysconfdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}/openvas
	@test -d $(DESTDIR)${sysconfdir}/openvas/gnupg || $(INSTALL_DIR) -m 700 $(DESTDIR)${sysconfdir}/openvas/gnupg
	@test -d $(DESTDIR)${localstatedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/users || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}/users
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/logs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}/logs
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/tmp || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}/tmp
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/jobs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}/jobs
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/CA || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_STATEDIR}/CA
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/private || $(INSTALL_DIR) -m 700 $(DESTDIR)${OPENVASSD_STATEDIR}/private
	@test -d $(DESTDIR)${OPENVASSD_STATEDIR}/private/CA || $(INSTALL_DIR) -m 700 $(DESTDIR)${OPENVASSD_STATEDIR}/private/CA
	@test -d $(DESTDIR)${OPENVASSD_LOGDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_LOGDIR}
	@test -d $(DESTDIR)${localstatedir}/run || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/run
	@test -d $(DESTDIR)${includedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}
	@test -d $(DESTDIR)${includedir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}/openvas
	@test -d $(DESTDIR)${OPENVASSD_CACHE} || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASSD_CACHE}
	$(INSTALL) -m 755 openvas-nvt-sync $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-mkcert-client $(DESTDIR)${bindir}/openvas-mkcert-client
	$(INSTALL) -m 755 ssl/openvas-mkrand $(DESTDIR)${bindir}/openvas-mkrand
	$(INSTALL) -m $(SERVERMODE) openvassd/openvassd $(DESTDIR)${sbindir}/openvassd
	$(INSTALL) -m 755 openvas-adduser $(DESTDIR)${sbindir}/openvas-adduser
	$(INSTALL) -m 755 openvas-rmuser $(DESTDIR)${sbindir}/openvas-rmuser
	$(INSTALL) -m 755 openvas-mkcert $(DESTDIR)${sbindir}/openvas-mkcert
	$(INSTALL) -c -m 0444 openvas-services  $(DESTDIR)${OPENVASSD_STATEDIR}/openvas-services

install-man:
	@echo installing man pages ...
	@test -d $(DESTDIR)${mandir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}
	@test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}/man1
	@test -d $(DESTDIR)${mandir}/man8 || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}/man8
	$(INSTALL) -c -m 0444 doc/openvas-mkrand.1 $(DESTDIR)${mandir}/man1/openvas-mkrand.1
	$(INSTALL) -c -m 0444 doc/openvassd.8 $(DESTDIR)${mandir}/man8/openvassd.8
	$(INSTALL) -c -m 0444 doc/openvas-nvt-sync.8 $(DESTDIR)${mandir}/man8/openvas-nvt-sync.8
	$(INSTALL) -c -m 0444 doc/openvas-adduser.8 $(DESTDIR)${mandir}/man8/openvas-adduser.8
	$(INSTALL) -c -m 0444 doc/openvas-rmuser.8 $(DESTDIR)${mandir}/man8/openvas-rmuser.8
	$(INSTALL) -c -m 0444 doc/openvas-mkcert.8 $(DESTDIR)${mandir}/man8/openvas-mkcert.8
	$(INSTALL) -c -m 0444 doc/openvas-mkcert-client.1 $(DESTDIR)${mandir}/man1/openvas-mkcert-client.1

install-nvts:
	test -d $(DESTDIR)${libdir}/openvas || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${libdir}/openvas
	test -d $(DESTDIR)${libdir}/openvas/plugins || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${libdir}/openvas/plugins
	for plugins in bin/*.nes; do \
	$(INSTALL) -m 555 $$plugins \
		$(DESTDIR)${libdir}/openvas/plugins; \
	done

scanner :
	cd openvassd && $(MAKE)

sslstuff :
	cd ssl && $(MAKE)

mknvts:
	cd cnvts && ./make_world

man : $(MAN_OPENVASSD_8)

$(MAN_OPENVASSD_8) : $(MAN_OPENVASSD_8).in
	@sed -e 's?@OPENVASSD_CONFDIR@?${OPENVASSD_CONFDIR}?g;s?@OPENVASSD_DATADIR@?${OPENVASSD_DATADIR}?g;s?@OPENVASSD_PLUGINS@?${OPENVASSD_PLUGINS}?g;' $(MAN_OPENVASSD_8).in  >$(MAN_OPENVASSD_8)


clean:
	cd openvassd && $(MAKE) clean
	cd ssl && $(MAKE) clean
	cd cnvts && ./make_world clean

distclean: clean
	[ -z "${rootdir}" ] || rm -f ${rootdir}/include/config.h ${rootdir}/include/corevers.h
	rm -f openvas.tmpl doc/openvas.1.cat doc/openvassd.8.cat
	[ -z "${make_bindir}" ] || rm -f $(make_bindir)/openvas*
	rm -f config.cache config.status config.log
	rm -f openvas-nvt-sync
	rm -f openvas-adduser
	rm -f openvas-rmuser
	rm -f openvas-mkcert
	rm -f openvas-mkcert-client
	rm -f openvas-install-cert
	[ -z "${MAN_OPENVASSD_8}" ] || rm -f ${MAN_OPENVASSD_8}

dist:
	version="`cat VERSION`"; \
	rm -rf openvas-scanner-$${version}* ; \
	mkdir openvas-scanner-$${version} ; \
	tar cf openvas-scanner-$${version}/x.tar `cat MANIFEST`; \
	( cd openvas-scanner-$${version} ; tar xf x.tar ; rm -f x.tar ) ; \
	tar cf openvas-scanner-$${version}.tar openvas-scanner-$${version} ; \
	gzip -9 openvas-scanner-$${version}.tar

distcheck:
	find . -type f | sed -e 's/^.\///' -e '/~$$/d' -e '/CVS/d' \
			     -e '/\.o$$/d' -e '/^openvas.tmpl$$/d' \
			     -e '/^openvassd\/OBJ\/openvassd$$/d' \
			     -e '/^bin\/openvassd$$/d' \
			     -e '/^config\.cache$$/d' \
			     -e '/^config\.log$$/d' \
			     -e '/^config\.status$$/d' \
			     -e '/^include\/config\.h$$/d' \
		| sort | diff -cb - MANIFEST

# Generates basic code documentation (placed in doc/generated)
doc :
	doxygen doc/Doxyfile

# Generates more extensive code documentation with graphs 
# (placed in doc/generated) and builts doc/generated/latex/refman.pdf
doc-full:
	doxygen doc/Doxyfile_full
	if [ -d doc/generated/latex ]; then make -C doc/generated/latex; fi

.PHONY: doc
