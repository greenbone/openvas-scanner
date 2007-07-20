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

all: $(ALLDEPS) server sslstuff doc


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
	@test -d ${bindir} || $(INSTALL_DIR) -m 755 ${bindir}
	@test -d ${sbindir} || $(INSTALL_DIR) -m 755 ${sbindir}
	@test -d ${sysconfdir} || $(INSTALL_DIR) -m 755 ${sysconfdir}
	@test -d ${sysconfdir}/openvas || $(INSTALL_DIR) -m 755 ${sysconfdir}/openvas
	@test -d ${localstatedir} || $(INSTALL_DIR) -m 755 ${localstatedir}
	@test -d ${localstatedir}/lib || $(INSTALL_DIR) -m 755 ${localstatedir}/lib
	@test -d ${localstatedir}/lib/openvas || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas
	@test -d ${localstatedir}/lib/openvas/users || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas/users
	@test -d ${localstatedir}/lib/openvas/logs || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas/logs
	@test -d ${localstatedir}/lib/openvas/tmp || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas/tmp
	@test -d ${localstatedir}/lib/openvas/jobs || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas/jobs
	@test -d ${localstatedir}/lib/openvas/CA || $(INSTALL_DIR) -m 755 ${localstatedir}/lib/openvas/CA
	@test -d ${localstatedir}/log || $(INSTALL_DIR) -m 755 ${localstatedir}/log
	@test -d ${localstatedir}/log/openvas || $(INSTALL_DIR) -m 755 ${localstatedir}/log/openvas
	@test -d ${localstatedir}/run || $(INSTALL_DIR) -m 755 ${localstatedir}/run
	@test -d ${includedir} || $(INSTALL_DIR) -m 755 ${includedir}
	@test -d ${includedir}/openvas || $(INSTALL_DIR) -m 755 ${includedir}/openvas
	@test -d ${sharedstatedir} || $(INSTALL_DIR) -m 755 ${sharedstatedir}
	@test -d ${sharedstatedir}/openvas || $(INSTALL_DIR) -m 755 ${sharedstatedir}/openvas
	@test -d ${sharedstatedir}/openvas/CA || $(INSTALL_DIR) -m 755 ${sharedstatedir}/openvas/CA
	$(INSTALL) -m 755 openvas-mkcert-client ${bindir}/openvas-mkcert-client
	$(INSTALL) -m 755 openvasd-config ${bindir}/openvasd-config
	$(INSTALL) -m 755 ssl/openvas-mkrand ${bindir}/openvas-mkrand
	$(INSTALL) -m $(SERVERMODE) openvasd/openvasd ${sbindir}/openvasd
	$(INSTALL) -m $(SERVERMODE) openvasd/openvas-check-signature ${sbindir}/openvas-check-signature
	$(INSTALL) -m 755 openvas-adduser ${sbindir}/openvas-adduser
	$(INSTALL) -m 755 openvas-rmuser ${sbindir}/openvas-rmuser
	$(INSTALL) -m 755 openvas-mkcert ${sbindir}/openvas-mkcert
	$(INSTALL) -c -m 0444 openvas-services ${localstatedir}/lib/openvas/openvas-services
	$(INSTALL) -c -m 0444 include/includes.h ${includedir}/openvas/includes.h
	$(INSTALL) -c -m 0444 include/openvas-devel.h ${includedir}/openvas/openvas-devel.h
	$(INSTALL) -c -m 0444 include/config.h ${includedir}/openvas/config.h
	$(INSTALL) -c -m 0444 include/threadcompat.h ${includedir}/openvas/threadcompat.h
	$(INSTALL) -c -m 0444 include/nessusraw.h ${includedir}/openvas/nessusraw.h
	$(INSTALL) -c -m 0444 include/nessusip.h ${includedir}/openvas/nessusip.h
	$(INSTALL) -c -m 0444 include/nessusicmp.h ${includedir}/openvas/nessusicmp.h
	$(INSTALL) -c -m 0444 include/nessustcp.h ${includedir}/openvas/nessustcp.h
	$(INSTALL) -c -m 0444 include/nessusudp.h ${includedir}/openvas/nessusudp.h


install-man:
	@echo installing man pages ...
	@test -d ${mandir} || $(INSTALL_DIR) -m 755 ${mandir}
	@test -d ${mandir}/man1 || $(INSTALL_DIR) -m 755 ${mandir}/man1
	@test -d ${mandir}/man8 || $(INSTALL_DIR) -m 755 ${mandir}/man8
	$(INSTALL) -c -m 0444 doc/openvas-check-signature.1 ${mandir}/man1/openvas-check-signature.1
	$(INSTALL) -c -m 0444 doc/openvas-mkrand.1 ${mandir}/man1/openvas-mkrand.1
	$(INSTALL) -c -m 0444 doc/openvasd.8 ${mandir}/man8/openvasd.8
	$(INSTALL) -c -m 0444 doc/openvas-adduser.8 ${mandir}/man8/openvas-adduser.8
	$(INSTALL) -c -m 0444 doc/openvas-rmuser.8 ${mandir}/man8/openvas-rmuser.8
	$(INSTALL) -c -m 0444 doc/openvas-mkcert.8 ${mandir}/man8/openvas-mkcert.8


server : 
	cd openvasd && $(MAKE)

sslstuff : 
	cd ssl && $(MAKE)


doc : $(MAN_OPENVASD_8)

$(MAN_OPENVASD_8) : $(MAN_OPENVASD_8).in
	@sed -e 's?@OPENVASD_CONFDIR@?${OPENVASD_CONFDIR}?g;s?@OPENVASD_DATADIR@?${OPENVASD_DATADIR}?g;s?@OPENVASD_PLUGINS@?${OPENVASD_PLUGINS}?g;' $(MAN_OPENVASD_8).in  >$(MAN_OPENVASD_8)


clean:
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
