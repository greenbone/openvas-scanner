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
	test -d $(DESTDIR)${sbindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sbindir}
	$(INSTALL) -m $(SERVERMODE)  ${make_bindir}/openvasd $(DESTDIR)${sbindir}
	$(INSTALL) -m $(SERVERMODE) ${make_bindir}/openvas-check-signature $(DESTDIR)${sbindir}
	test -d $(DESTDIR)${sysconfdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}
	test -d $(DESTDIR)${sysconfdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${sysconfdir}/openvas	
	test -d $(DESTDIR)${NESSUSD_DATADIR} || \
		$(INSTALL_DIR) -m $(PLUGINSDIRMODE) $(DESTDIR)${NESSUSD_DATADIR}
	test -d $(DESTDIR)$(NESSUSD_PLUGINS) || \
		$(INSTALL_DIR) -m $(PLUGINSDIRMODE) $(DESTDIR)$(NESSUSD_PLUGINS)
	test -d $(DESTDIR)${localstatedir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}
	test -d $(DESTDIR)${NESSUSD_STATEDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_STATEDIR}
	test -d $(DESTDIR)${NESSUSD_STATEDIR}/users || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_STATEDIR}/users
	test -d $(DESTDIR)${NESSUSD_STATEDIR}/logs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_STATEDIR}/logs
	test -d $(DESTDIR)${NESSUSD_STATEDIR}/tmp || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_STATEDIR}/tmp
	test -d $(DESTDIR)${NESSUSD_STATEDIR}/jobs  || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_STATEDIR}/jobs
	test -d $(DESTDIR)${NESSUSD_LOGDIR} || $(INSTALL_DIR) -m 755 $(DESTDIR)${NESSUSD_LOGDIR}
	$(INSTALL) -c -m 0444 openvas-services $(DESTDIR)${NESSUSD_STATEDIR}/
	$(INSTALL) -m 755 openvas-fetch/openvas-fetch $(DESTDIR)${bindir}
	$(INSTALL) -m 755 openvas-adduser $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-rmuser $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-mkcert $(DESTDIR)${sbindir}
	$(INSTALL) -m 755 openvas-mkcert-client $(DESTDIR)${bindir}
	$(INSTALL) -m 755 ssl/openvas-mkrand $(DESTDIR)${bindir}


install-man:
	@echo installing man pages ...
	@test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) $(DESTDIR)${mandir}/man1
	@test -d $(DESTDIR)${mandir}/man8 || $(INSTALL_DIR) $(DESTDIR)${mandir}/man8

	$(INSTALL) -c -m 0444 doc/openvas-fetch.1 $(DESTDIR)${mandir}/man1/openvas-fetch.1
	$(INSTALL) -c -m 0444 doc/openvas-check-signature.1 $(DESTDIR)${mandir}/man1/openvas-check-signature.1
	$(INSTALL) -c -m 0444 ${MAN_NESSUSD_8} $(DESTDIR)${mandir}/man8/openvasd.8
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


doc : $(MAN_NESSUSD_8)

$(MAN_NESSUSD_8) : $(MAN_NESSUSD_8).in
	@sed -e 's?@NESSUSD_CONFDIR@?${NESSUSD_CONFDIR}?g;s?@NESSUSD_DATADIR@?${NESSUSD_DATADIR}?g;s?@NESSUSD_PLUGINS@?${NESSUSD_PLUGINS}?g;' $(MAN_NESSUSD_8).in  >$(MAN_NESSUSD_8)


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
	[ -z "${MAN_NESSUSD_8}" ] || rm -f ${MAN_NESSUSD_8} 

dist:
	version="`date +%Y%m%d`"; \
	cd ..; \
	tar cf openvas-server-$${version}.tar \
		`cat openvas-server/MANIFEST | sed 's/^/openvas-server\//'`; \
	rm -f openvas-server-$${version}.tar.gz; \
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
