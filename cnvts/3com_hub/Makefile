include ../../openvas.tmpl

OPENVAS_INCLUDE=$(include) $(GLIB_CFLAGS) $(OPENVAS_CFLAGS)

PLUGNAME=3com_hub

all : $(PLUGNAME).nes
	
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) --mode=compile --tag CC $(CC) $(OPENVAS_INCLUDE) -I/usr/local/include `libnet-config --defines --cflags` -c  $(PLUGNAME).c
	$(LIBTOOL) --mode=link --tag CC $(CC) $(OPENVAS_INCLUDE) $(LDFLAGS) -o lib$(PLUGNAME).la $(PLUGNAME).lo `libnet-config --defines --libs` -L/usr/local/lib $(LIBS) $(GLIB_LIBS) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
