include ../../openvas.tmpl

PLUGNAME=3com_hub

all : $(PLUGNAME).nes
	
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) --mode=compile --tag CC $(CC) $(DEFS) $(include)  -I/usr/local/include `libnet-config --defines --cflags` -c  $(PLUGNAME).c
	$(LIBTOOL) --mode=link --tag CC $(CC) $(DEFS) $(LDFLAGS) -o lib$(PLUGNAME).la $(PLUGNAME).lo `libnet-config --defines --libs` -L/usr/local/lib $(LIBS) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
