include ../../openvas.tmpl

PLUGNAME=openvas_tcp_scanner

# If you compile this plugin with -DSTATISTICS or -DCOMPUTE_RTT, 
# add -lm after $LIBS

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c 
	$(LIBTOOL) --mode=compile --tag CC $(CC) $(DEFS) $(include) -c  $(PLUGNAME).c
	$(LIBTOOL) --mode=link --tag CC $(CC) $(DEFS) $(LDFLAGS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) -lm $(LIBUTIL) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
