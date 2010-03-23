include ../../openvas.tmpl

OPENVAS_INCLUDE=$(include) $(GLIB_CFLAGS) $(OPENVAS_CFLAGS)

PLUGNAME=find_service

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) --mode=compile --tag CC $(CC) $(OPENVAS_INCLUDE) -c  $(PLUGNAME).c
	$(LIBTOOL) --mode=link --tag CC $(CC) $(OPENVAS_INCLUDE) $(LDFLAGS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) $(GLIB_LIBS) \
	-rpath $(rootdir)/cnvts/$(PLUGNAME)
	../install_plug $(PLUGNAME)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
