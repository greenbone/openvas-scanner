# Handcrafted to just get the scripts gmo installed.
# 2006-03-29 Jan-Oliver Wagner <jan@intevation.de>

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
