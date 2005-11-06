include ../nessus.tmpl

LIBS =  `$(NASLCONFIG) --libs` `$(NESSUSCONFIG) --libs`  \
	$(W_STATIC)  $(W_DYNAMIC) \
	$(DL_LIB)  \
	$(COMPAT_LIB) $(LIBWRAP)
NESSUS_INCLUDE=`sh ./cflags` 
OBJS = auth.o \
       attack.o \
       comm.o \
       log.o \
       rules.o \
       sighand.o \
       processes.o \
       users.o \
       utils.o \
       ntp_10.o \
       ntp_11.o \
       parser.o \
       hosts.o \
       preferences.o \
       piic.o \
       pluginload.o \
       nasl_plugins.o \
       nes_plugins.o \
       plugs_req.o \
       nessusd.o \
       save_tests.o \
       save_kb.o \
       detached.o \
       pluginlaunch.o \
       locks.o \
       dirutils.o \
       md5.o \
       plugs_hash.o \
       pluginupload.o \
       pluginscheduler.o \
       shared_socket.o 

all : ${make_bindir}/nessusd ${make_bindir}/nessus-check-signature

cflags : ../nessus.tmpl
	@echo "$(NESSUS_CFLAGS) ${include} $(DEFS) $(NESSUS_DEFS)"  | sed 's/\"/\\\"/g' > cflags.tmp
	@echo "echo \"`cat cflags.tmp`\"" > cflags
	@rm cflags.tmp
	@chmod +x cflags
${make_bindir}/nessusd : nessusd
	test -d ${make_bindir} || mkdir ${make_bindir}
	cp nessusd ${make_bindir}/nessusd

${make_bindir}/nessus-check-signature: nessus-check-signature
	test -d ${make_bindir} || mkdir ${make_bindir}
	cp nessus-check-signature ${make_bindir}/nessus-check-signature

nessusd : cflags $(OBJS)
	$(CC) $(LDFLAGS) $(NESSUS_INCLUDE) $(OBJS)  -o nessusd $(LIBS)

nessus-check-signature : cflags nessus-check-signature.o
	$(CC) $(LDFLAGS) $(NESSUS_INCLUDE) nessus-check-signature.o  -o nessus-check-signature $(LIBS)

nessus-check-signature.o: nessus-check-signature.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nessus-check-signature.c 

users.o : cflags users.c users.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c users.c 

processes.o : cflags processes.c processes.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c processes.c 

rules.o : cflags rules.c rules.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c rules.c 

preferences.o : cflags preferences.c preferences.h 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c preferences.c 

pluginload.o : cflags pluginload.h pluginload.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c pluginload.c 

nessusd.o : cflags nessusd.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nessusd.c 

auth.o : cflags auth.c auth.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c auth.c 

attack.o : cflags attack.c attack.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c attack.c 

comm.o : cflags comm.c comm.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c comm.c 

utils.o : cflags utils.c utils.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c utils.c 

log.o : cflags log.c log.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c log.c 

sighand.o : cflags sighand.c sighand.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c sighand.c 

ntp_10.o  : cflags ntp_10.c ntp_10.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c ntp_10.c 

ntp_11.o  : cflags ntp_11.c ntp_11.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c ntp_11.c 

parser.o : cflags parser.c parser.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c parser.c 

piic.o : cflags piic.c piic.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c piic.c 

nasl_plugins.o : cflags nasl_plugins.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nasl_plugins.c 

nes_plugins.o : cflags nes_plugins.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nes_plugins.c 

plugs_req.o : cflags plugs_req.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c plugs_req.c 

save_tests.o : cflags save_tests.c save_tests.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c save_tests.c	

save_kb.o : cflags save_kb.c save_kb.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c save_kb.c

detached.o : cflags detached.c detached.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c detached.c

pluginlaunch.o : cflags pluginlaunch.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c pluginlaunch.c

locks.o : cflags locks.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c locks.c


dirutils.o : cflags dirutils.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c dirutils.c


md5.o : cflags md5.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c md5.c

plugs_hash.o : cflags plugs_hash.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c plugs_hash.c

pluginupload.o : cflags pluginupload.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c pluginupload.c

pluginscheduler.o : cflags pluginscheduler.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c pluginscheduler.c

hosts.o : cflags hosts.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c hosts.c

shared_socket.o : cflags shared_socket.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c shared_socket.c
clean :
	rm -f *.o nessusd nessus-check-signature *~ cflags

