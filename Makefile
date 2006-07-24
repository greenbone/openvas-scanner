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
#
#


include openvas.tmpl

ALLDEPS = openvas.tmpl

all: $(ALLDEPS) server sslstuff doc fetchtool


openvas.tmpl: openvas.tmpl.in configure VERSION
	$(SHELL) configure $(CONFIGURE_ARGS)
	touch $@

install: all install-bin install-man
	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' openvas-server has been sucessfully installed. '
	@echo " Make sure that $(bindir) and $(sbindir) are in your PATH before"
	@echo " you continue."
	@echo " openvasd has been installed into $(sbindir)"
	@echo ' --------------------------------------------------------------'
	@echo

install-bin:
	@test -d $(DESTDIR)${bindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${bindir}
	@test -d $(DESTDIR)${sbindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sbindir}
	@test -d $(DESTDIR)${sysconfdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}
	@test -d $(DESTDIR)${sysconfdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}/openvas
	@test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	@test -d $(DESTDIR)${libdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}/openvas
	@test -d $(DESTDIR)${libdir}/openvas/plugins || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}/openvas/plugins
	@test -d $(DESTDIR)${localstatedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}
	@test -d $(DESTDIR)${localstatedir}/lib || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib
	@test -d $(DESTDIR)${localstatedir}/lib/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas
	@test -d $(DESTDIR)${localstatedir}/lib/openvas/users || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas/users
	@test -d $(DESTDIR)${localstatedir}/lib/openvas/logs || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas/logs
	@test -d $(DESTDIR)${localstatedir}/lib/openvas/tmp || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas/tmp
	@test -d $(DESTDIR)${localstatedir}/lib/openvas/jobs || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas/jobs
	@test -d $(DESTDIR)${localstatedir}/lib/openvas/CA || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/lib/openvas/CA
	@test -d $(DESTDIR)${localstatedir}/log || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/log
	@test -d $(DESTDIR)${localstatedir}/log/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/log/openvas
	@test -d $(DESTDIR)${localstatedir}/run || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/run
	@test -d $(DESTDIR)${includedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}
	@test -d $(DESTDIR)${includedir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}/openvas
	@test -d $(DESTDIR)${sharedstatedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sharedstatedir}
	@test -d $(DESTDIR)${sharedstatedir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${sharedstatedir}/openvas
	@test -d $(DESTDIR)${sharedstatedir}/openvas/CA || $(INSTALL_DIR) -m 755 $(DESTDIR)${sharedstatedir}/openvas/CA
	$(INSTALL) -m 755 openvas-fetch/openvas-fetch $(DESTDIR)${bindir}/openvas-fetch
	$(INSTALL) -m 755 openvas-mkcert-client $(DESTDIR)${bindir}/openvas-mkcert-client
	$(INSTALL) -m 755 openvasd-config $(DESTDIR)${bindir}/openvasd-config
	$(INSTALL) -m 755 ssl/openvas-mkrand $(DESTDIR)${bindir}/openvas-mkrand
	$(INSTALL) -m $(SERVERMODE) openvasd/openvasd $(DESTDIR)${sbindir}/openvasd
	$(INSTALL) -m $(SERVERMODE) openvasd/openvas-check-signature $(DESTDIR)${sbindir}/openvas-check-signature
	$(INSTALL) -m 755 openvas-adduser $(DESTDIR)${sbindir}/openvas-adduser
	$(INSTALL) -m 755 openvas-rmuser $(DESTDIR)${sbindir}/openvas-rmuser
	$(INSTALL) -m 755 openvas-mkcert $(DESTDIR)${sbindir}/openvas-mkcert
	$(INSTALL) -c -m 0444 openvas-services $(DESTDIR)${localstatedir}/lib/openvas/openvas-services
	$(INSTALL) -c -m 0444 include/includes.h $(DESTDIR)${includedir}/openvas/includes.h
	$(INSTALL) -c -m 0444 include/openvas-devel.h $(DESTDIR)${includedir}/openvas/openvas-devel.h
	$(INSTALL) -c -m 0444 include/config.h $(DESTDIR)${includedir}/openvas/config.h
	$(INSTALL) -c -m 0444 include/ntcompat.h $(DESTDIR)${includedir}/openvas/ntcompat.h
	$(INSTALL) -c -m 0444 include/nessusraw.h $(DESTDIR)${includedir}/openvas/nessusraw.h
	$(INSTALL) -c -m 0444 include/nessusip.h $(DESTDIR)${includedir}/openvas/nessusip.h
	$(INSTALL) -c -m 0444 include/nessusicmp.h $(DESTDIR)${includedir}/openvas/nessusicmp.h
	$(INSTALL) -c -m 0444 include/nessustcp.h $(DESTDIR)${includedir}/openvas/nessustcp.h
	$(INSTALL) -c -m 0444 include/nessusudp.h $(DESTDIR)${includedir}/openvas/nessusudp.h
	# The following copy of openvas-services into nessus-services
	# is done due to the fact that the path to this file is
	# hardcoded in nessus-libraries. So, in case nessus-libraries
	# is used, this is mandatory - openvasd would not start otherwise.
	# However, openvas and nessus may mutually overwrite the nesssus-services
	# file - the latest install wins.
	@test -d $(DESTDIR)${localstatedir}/nessus || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/nessus
	$(INSTALL) -c -m 0444 openvas-services $(DESTDIR)${localstatedir}/nessus/nessus-services


install-man:
	@echo installing man pages ...
	@test -d $(DESTDIR)${mandir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}
	@test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}/man1
	@test -d $(DESTDIR)${mandir}/man8 || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}/man8
	$(INSTALL) -c -m 0444 doc/openvas-fetch.1 $(DESTDIR)${mandir}/man1/openvas-fetch.1
	$(INSTALL) -c -m 0444 doc/openvas-check-signature.1 $(DESTDIR)${mandir}/man1/openvas-check-signature.1
	$(INSTALL) -c -m 0444 doc/openvas-mkrand.1 $(DESTDIR)${mandir}/man1/openvas-mkrand.1
	$(INSTALL) -c -m 0444 doc/openvasd.8 $(DESTDIR)${mandir}/man8/openvasd.8
	$(INSTALL) -c -m 0444 doc/openvas-adduser.8 $(DESTDIR)${mandir}/man8/openvas-adduser.8
	$(INSTALL) -c -m 0444 doc/openvas-rmuser.8 $(DESTDIR)${mandir}/man8/openvas-rmuser.8
	$(INSTALL) -c -m 0444 doc/openvas-mkcert.8 $(DESTDIR)${mandir}/man8/openvas-mkcert.8


server : 
	cd openvasd && $(MAKE)

sslstuff : 
	cd ssl && $(MAKE)


fetchtool:
	cd openvas-fetch && $(MAKE)


doc : $(MAN_OPENVASD_8)

$(MAN_OPENVASD_8) : $(MAN_OPENVASD_8).in
	@sed -e 's?@OPENVASD_CONFDIR@?${OPENVASD_CONFDIR}?g;s?@OPENVASD_DATADIR@?${OPENVASD_DATADIR}?g;s?@OPENVASD_PLUGINS@?${OPENVASD_PLUGINS}?g;' $(MAN_OPENVASD_8).in  >$(MAN_OPENVASD_8)


clean:
	cd openvas-fetch && $(MAKE) clean
	cd openvasd && $(MAKE) clean
	cd ssl && $(MAKE) clean

distclean: clean
	[ -z "${rootdir}" ] || rm -f ${rootdir}/include/config.h ${rootdir}/include/corevers.h 
	rm -f openvas.tmpl doc/openvas.1.cat doc/openvasd.8.cat
	[ -z "${make_bindir}" ] || rm -f $(make_bindir)/openvas* 
	rm -f libtool config.cache config.status config.log 
	rm -f openvas-adduser
	rm -f openvas-rmuser
	rm -f openvas-mkcert
	rm -f openvas-mkcert-client
	rm -f openvas-install-cert
	[ -z "${MAN_OPENVASD_8}" ] || rm -f ${MAN_OPENVASD_8} 

dist:
	version="`cat VERSION`"; \
	rm -rf openvas-server-$${version}* ; \
	mkdir openvas-server-$${version} ; \
	tar cf openvas-server-$${version}/x.tar `cat MANIFEST`; \
	( cd openvas-server-$${version} ; tar xf x.tar ; rm -f x.tar ) ; \
	tar cf openvas-server-$${version}.tar openvas-server-$${version} ; \
	gzip -9 openvas-server-$${version}.tar

distcheck:
	find . -type f | sed -e 's/^.\///' -e '/~$$/d' -e '/CVS/d' \
			     -e '/\.o$$/d' -e '/^openvas.tmpl$$/d' \
			     -e '/^libtool$$/d' \
			     -e '/^openvasd\/OBJ\/openvasd$$/d' \
			     -e '/^bin\/openvasd$$/d' \
			     -e '/^config\.cache$$/d' \
			     -e '/^config\.log$$/d' \
			     -e '/^config\.status$$/d' \
			     -e '/^include\/config\.h$$/d' \
		| sort | diff -cb - MANIFEST
