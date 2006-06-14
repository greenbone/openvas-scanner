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
	test -d $(DESTDIR)${bindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${bindir}
	test -d $(DESTDIR)${sbindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sbindir}
	test -d $(DESTDIR)${sysconfdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}
	test -d $(DESTDIR)${sysconfdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}/openvas	
	test -d $(DESTDIR)${OPENVASD_DATADIR} || \
		$(INSTALL_DIR) -m $(PLUGINSDIRMODE) $(DESTDIR)${OPENVASD_DATADIR}
	test -d $(DESTDIR)$(OPENVASD_PLUGINS) || \
		$(INSTALL_DIR) -m $(PLUGINSDIRMODE) $(DESTDIR)$(OPENVASD_PLUGINS)
	test -d $(DESTDIR)${localstatedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}
	test -d $(DESTDIR)${OPENVASD_STATEDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}
	test -d $(DESTDIR)${OPENVASD_STATEDIR}/users || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}/users
	test -d $(DESTDIR)${OPENVASD_STATEDIR}/logs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}/logs
	test -d $(DESTDIR)${OPENVASD_STATEDIR}/tmp || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}/tmp
	test -d $(DESTDIR)${OPENVASD_STATEDIR}/jobs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}/jobs
	test -d $(DESTDIR)${OPENVASD_LOGDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_LOGDIR}
	test -d $(DESTDIR)${includedir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 755 openvas-fetch/openvas-fetch $(DESTDIR)${bindir}
	$(INSTALL) -m 755 openvas-mkcert-client $(DESTDIR)${bindir}
	$(INSTALL) -m 755 openvasd-config $(DESTDIR)${bindir}
	$(INSTALL) -m 755 ssl/openvas-mkrand $(DESTDIR)${bindir}
	$(INSTALL) -m $(SERVERMODE)  ${make_bindir}/openvasd $(DESTDIR)${sbindir}
	$(INSTALL) -m $(SERVERMODE) ${make_bindir}/openvas-check-signature $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-adduser $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-rmuser $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-mkcert $(DESTDIR)${sbindir}
	$(INSTALL) -c -m 0444 include/includes.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/openvas-devel.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/config.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/ntcompat.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/nessusraw.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/nessusip.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/nessusicmp.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/nessustcp.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 include/nessusudp.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -c -m 0444 openvas-services $(DESTDIR)${OPENVASD_STATEDIR}/
	# The following copy of openvas-services into nessus-services
	# is done due to the fact that the path to this file is
	# hardcoded in nessus-libraries. So, in case nessus-libraries
	# is used, this is mandatory - openvasd would not start otherwise.
	# However, openvas and nessus may mutually overwrite the nesssus-services
	# file - the latest install wins.
	test -d $(DESTDIR)${OPENVASD_STATEDIR}/../../nessus || $(INSTALL_DIR) -m 755 $(DESTDIR)${OPENVASD_STATEDIR}/../../nessus
	$(INSTALL) -c -m 0444 openvas-services $(DESTDIR)${OPENVASD_STATEDIR}/../../nessus/nessus-services



install-man:
	@echo installing man pages ...
	@test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) $(DESTDIR)${mandir}/man1
	@test -d $(DESTDIR)${mandir}/man8 || $(INSTALL_DIR) $(DESTDIR)${mandir}/man8

	$(INSTALL) -c -m 0444 doc/openvas-fetch.1 $(DESTDIR)${mandir}/man1/openvas-fetch.1
	$(INSTALL) -c -m 0444 doc/openvas-check-signature.1 $(DESTDIR)${mandir}/man1/openvas-check-signature.1
	$(INSTALL) -c -m 0444 ${MAN_OPENVASD_8} $(DESTDIR)${mandir}/man8/openvasd.8
	$(INSTALL) -c -m 0444 doc/openvas-adduser.8 $(DESTDIR)${mandir}/man8/openvas-adduser.8
	$(INSTALL) -c -m 0444 doc/openvas-rmuser.8 $(DESTDIR)${mandir}/man8/openvas-rmuser.8
	$(INSTALL) -c -m 0444 doc/openvas-mkcert.8 $(DESTDIR)${mandir}/man8/openvas-mkcert.8
#	$(INSTALL) -c -m 0444 doc/openvas-mkcert-client.1 \
                              $(DESTDIR)${mandir}/man1/openvas-mkcert-client.1
	$(INSTALL) -c -m 0444 doc/openvas-mkrand.1 $(DESTDIR)${mandir}/man1/openvas-mkrand.1

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
