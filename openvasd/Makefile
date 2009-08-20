include ../openvas.tmpl

LIBS =  `$(OPENVASLIBNASLCONFIG) --libs` `$(LIBOPENVASCONFIG) --libs`  \
	$(W_STATIC)  $(W_DYNAMIC) \
	$(DL_LIB)  \
	$(COMPAT_LIB) $(LIBWRAP) $(GLIB_LIBS) \
	$(RUN_LIBS)
OPENVAS_INCLUDE=$(include) $(GLIB_CFLAGS) $(DEFS)
OBJS = auth.o \
       attack.o \
       comm.o \
       log.o \
       rules.o \
       sighand.o \
       processes.o \
       users.o \
       utils.o \
       ntp_11.o \
       otp_1_0.o \
       parser.o \
       hosts.o \
       preferences.o \
       piic.o \
       pluginload.o \
       nasl_plugins.o \
       nes_plugins.o \
       oval_plugins.o \
       plugs_req.o \
       openvasd.o \
       save_tests.o \
       save_kb.o \
       pluginlaunch.o \
       locks.o \
       plugs_hash.o \
       pluginscheduler.o \
       shared_socket.o 

all : openvasd

openvasd : $(OBJS)
	$(CC) $(LDFLAGS) $(OPENVAS_INCLUDE) $(OBJS)  -o openvasd $(LIBS)

users.o : users.c users.h rules.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c users.c 

processes.o : processes.c processes.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c processes.c 

rules.o : rules.c rules.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c rules.c 

preferences.o : preferences.c preferences.h 
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c preferences.c 

pluginload.o : pluginload.h pluginload.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c pluginload.c 

openvasd.o : openvasd.c rules.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c openvasd.c 

auth.o : auth.c auth.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c auth.c 

attack.o : attack.c attack.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c attack.c 

comm.o : comm.c comm.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c comm.c 

utils.o : utils.c utils.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c utils.c 

log.o : log.c log.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c log.c 

sighand.o : sighand.c sighand.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c sighand.c 

ntp_11.o  : ntp_11.c ntp_11.h rules.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c ntp_11.c 

otp_1_0.o: otp_1_0.c otp_1_0.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c otp_1_0.c

parser.o : parser.c parser.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c parser.c 

piic.o : piic.c piic.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c piic.c 

nasl_plugins.o : nasl_plugins.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c nasl_plugins.c 

nes_plugins.o : nes_plugins.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c nes_plugins.c 

oval_plugins.o : oval_plugins.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c oval_plugins.c 

plugs_req.o : plugs_req.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c plugs_req.c 

save_tests.o : save_tests.c save_tests.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c save_tests.c	

save_kb.o : save_kb.c save_kb.h
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c save_kb.c

pluginlaunch.o : pluginlaunch.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c pluginlaunch.c

locks.o : locks.c 
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c locks.c


plugs_hash.o : plugs_hash.c 
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c plugs_hash.c

pluginscheduler.o : pluginscheduler.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c pluginscheduler.c

hosts.o : hosts.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c hosts.c

shared_socket.o : shared_socket.c
	$(CC) $(OPENVAS_CFLAGS) $(OPENVAS_INCLUDE) -c shared_socket.c
clean :
	rm -f openvasd *.o *~

