include ../../openvas.tmpl

PLUGNAME=ssl_ciphers

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) --mode=compile --tag CC $(CC) $(DEFS) $(include) -c  $(PLUGNAME).c
	$(LIBTOOL) --mode=link --tag CC $(CC) $(LDFLAGS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
