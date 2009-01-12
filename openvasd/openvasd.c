/* OpenVAS
* $Id$
* Description: Runs the OpenVAS-server.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/ 

#include <includes.h>
#include <harglists.h>
#include <nasl.h>
#include <hosts_gatherer.h>

#ifdef USE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>

int deny_severity = LOG_WARNING;
int allow_severity = LOG_NOTICE;

#endif

#include <glib.h>


#include "pluginload.h"
#include "preferences.h"
#include "auth.h"
#include "rules.h"
#include "comm.h"
#include "attack.h"
#include "sighand.h"
#include "log.h"
#include "processes.h"
#include "users.h"
#include "ntp.h"
#include "ntp_11.h"
#include "utils.h"
#include "corevers.h"
#include "pluginscheduler.h"
#include "pluginlaunch.h"


#ifndef HAVE_SETSID
#define setsid() setpgrp()
#endif

extern char * nasl_version();
extern char * nessuslib_version();
/*
 * Globals that should not be touched
 */
int g_max_hosts = 15;
int g_max_checks  = 10;
struct arglist * g_options = NULL;

pid_t bpf_server_pid;
pid_t nasl_server_pid;

int g_iana_socket;
struct arglist * g_plugins;
struct arglist * g_preferences;
struct openvas_rules * g_rules;


static char * orig_argv[64];
static int restart = 0;


/*
 * Functions prototypes
 */
static void main_loop();
static int init_openvasd (struct arglist *, int, int, int);
static int init_network(int, int *, struct in_addr);
static void server_thread (struct arglist *);




static struct in_addr * convert_ip_addresses(char * ips)
{
 char * t;
 struct in_addr addr;
 struct in_addr * ret;
 int num = 0;
 int num_allocated = 256;
 char * orig;
 
 ips = orig = estrdup(ips);
 
 ret = emalloc((num_allocated + 1) * sizeof(struct in_addr));
 
 
 while ( ( t = strchr(ips, ',')) != NULL )
 {
  t[0] = '\0';
  while (ips[0] == ' ')ips ++;
  if( inet_aton(ips, &addr) ==  0) 
  {
   fprintf(stderr, "Could not convert %s\n", ips);
  }
  else
  {
   ret[num] = addr;
   num ++;
  }
  
  if( num >= num_allocated )
  {
   num_allocated *= 2;
   ret = erealloc(ret, (num_allocated + 1) * sizeof(struct in_addr));
  }
  
  ips = t + 1;
 }
 
 while(ips[0] == ' ')ips++;
 
 if( inet_aton(ips, &addr) ==  0) 
  {
   fprintf(stderr, "Could not convert %s\n", ips);
  }
  else {
   ret[num] = addr;
   num ++;
   }
  if( num >= num_allocated )
  {
   num_allocated ++;
   ret = erealloc(ret, (num_allocated + 1) * sizeof(struct in_addr));
  }
 
 
 
 ret[num].s_addr = 0;
 ret = erealloc(ret, ( num + 1 ) * sizeof(struct in_addr));
 efree(&orig);
 return ret;
} 
  
  
  




static void
dump_cfg_specs
  (struct arglist *prefs)
{
 while(prefs && prefs->next)
 {
	 printf("%s = %s\n", prefs->name, (char*)prefs->value);
	 prefs = prefs->next;
 }
}

static void
arg_replace_value(arglist, name, type, length, value)
 struct arglist * arglist;
 char * name;
 int type;
 int length;
 void * value;
{
 if(arg_get_type(arglist, name)<0)
  arg_add_value(arglist, name, type, length, value);
 else  
  arg_set_value(arglist, name, length, value);
}


static void
start_daemon_mode
  (void)
{
  char *s;
  int fd;


  /* do not block the listener port for sub sequent servers */
  close (g_iana_socket);

  /* become process group leader */
  if (setsid () < 0) {
    log_write 
      ("Warning: Cannot set process group leader (%s)\n", strerror (errno));
  }

  if ((fd = open ("/dev/tty", O_RDWR)) >= 0) {
    /* detach from any controlling terminal */
#ifdef TIOCNOTTY    
    ioctl (fd, TIOCNOTTY) ;
#endif
    close (fd);
  }
  
  /* no input, anymore: provide an empty-file substitute */
  if ((fd = open ("/dev/null", O_RDONLY)) < 0) {
    log_write ("Cannot open /dev/null (%s) -- aborting\n",strerror (errno));
    exit (0);
  }

  dup2 (fd, 0);
  close (fd);

  /* provide a dump file to collect stdout and stderr */
  if ((s = arg_get_value (g_preferences, "dumpfile")) == 0)
    s = OPENVASD_DEBUGMSG ;
  /* setting "-" denotes terminal mode */
  if (strcmp(s, "-") == 0)
    return;

  fflush(stdout);
  fflush(stderr);

    if ((fd = open (s, O_WRONLY|O_CREAT|O_APPEND
#ifdef O_LARGEFILE
	| O_LARGEFILE
#endif
	, 0600)) < 0) {
      log_write ("Cannot create a new dumpfile %s (%s)-- aborting\n",
		 s, strerror (errno));
      exit (2);
    }

    dup2 (fd, 1);
    dup2 (fd, 2);
    close (fd);
#ifdef _IOLBF
    /* I don't know if setlinebuf() is available on all systems */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
#endif
}


static void
end_daemon_mode
  (void)
{

  /* clean up all processes the process group */
  make_em_die (SIGTERM);
}

static void restart_openvasd()
{
 char * path;
 char fpath[1024];

 close(g_iana_socket);
 delete_pid_file();
 if(fork () == 0)
 {
  if(strchr(orig_argv[0], '/') != NULL )
  path = orig_argv[0];
 else 
  {
  path = find_in_path("openvasd", 0);
  if( path == NULL ) 
  {
  	log_write("Could not re-start openvasd - not found\n");
	_exit(1);
   }
  else {
  	strncpy(fpath, path, sizeof(fpath) - strlen("openvasd") - 2);
	strcat(fpath, "/");
	strcat(fpath, "openvasd");
	path = fpath;
	}
  }
 if(execv(path, orig_argv) < 0)
  log_write("Could not start %s - %s", path, strerror(errno));
 }
 _exit(0);
}

static void
sighup(i)
 int i;
{
  log_write("Caught HUP signal - reconfiguring openvasd\n");
  restart = 1;
}



/*
 * SSL context may be kept once it is inited.
 */
static ovas_server_context_t ovas_server_ctx = NULL;

static void
server_thread(struct arglist * globals)
{
 struct sockaddr_in * address = arg_get_value(globals, "client_address");
 struct arglist * plugins = arg_get_value(globals, "plugins");
 struct arglist * prefs = arg_get_value (globals, "preferences") ;
 int soc = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
 struct openvas_rules* perms;
 char * asciiaddr;
 struct openvas_rules * rules = arg_get_value(globals, "rules");
 ntp_caps* caps;
 int e;
 int opt = 1;

 char		x509_dname[256];
 int		soc2 = -1;
 
 
#ifdef USE_PTHREADS
 int off = 0;
 ioctl(soc, FIONBIO, &off);
#endif

 setproctitle("serving %s", inet_ntoa(address->sin_addr));

 *x509_dname = '\0';
 
 /*
  * Everyone runs with a nicelevel of 10
  */
if(preferences_benice(prefs))nice(10); 
  	
 nessus_signal(SIGCHLD, sighand_chld);
#if 1
 /* To let some time to attach a debugger to the child process */
 {
   char	* p = getenv("OPENVAS_WAIT_AFTER_FORK");
   int	x = p == NULL ? 0 : atoi(p);
   if (x > 0)
     fprintf(stderr, "server_thread is starting. Sleeping %d s. PID = %d\n",
	     x, getpid());
   sleep(x);
 }
#endif

	
 /*
  * Close the server thread - it is useless for us now
  */
 close (g_iana_socket);
 
 if (ovas_server_ctx != NULL)		/* ssl_ver !=  "NONE" */
   {
     soc2 = ovas_server_context_attach(ovas_server_ctx, soc);
     if (soc2 < 0)
       goto shutdown_and_exit;

     /* FIXME: The pre-gnutls code optionally printed information about
      * the peer's certificate at this point.
      */
   }

 setsockopt(soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
 /* arg_set_value *replaces* an existing value, but it shouldn't fail here */
 (void) arg_set_value(globals, "global_socket", -1, GSIZE_TO_POINTER(soc2));

#ifdef HAVE_ADDR2ASCII
 asciiaddr = emalloc(20);
 addr2ascii(AF_INET, &address->sin_addr, sizeof(struct in_addr), asciiaddr);
#elif defined(HAVE_INET_NETA)
 asciiaddr = emalloc(20);
 inet_neta(ntohl(address->sin_addr.s_addr), asciiaddr, 20);
#else
 asciiaddr = estrdup(inet_ntoa(address->sin_addr));
#endif
 caps = comm_init(soc2);
 if(!caps)
 {
  log_write("New connection timeout -- closing the socket\n");
  close_stream_connection(soc);
  EXIT(0);
 }
 arg_add_value(globals, "ntp_caps", ARG_STRUCT, sizeof(*caps), caps);

 
 if(((perms = auth_check_user(globals, asciiaddr, x509_dname))==BAD_LOGIN_ATTEMPT)||
   !perms)
 {
   auth_printf(globals, "Bad login attempt !\n"); 
   log_write("bad login attempt from %s\n", 
			asciiaddr);
   efree(&asciiaddr);			
   goto shutdown_and_exit;
 }
  else {
   efree(&asciiaddr);
   if(perms){
     	rules_add(&rules, &perms, NULL);
	rules_set_client_ip(rules, address->sin_addr);
#ifdef DEBUG_RULES
	printf("Rules have been added : \n");
	rules_dump(rules);
#endif	
	arg_set_value(globals, "rules", -1, rules);
   }

   plugins = plugins_reload_user(globals, prefs, plugins);

   arg_set_value(globals, "plugins", -1, plugins);

   comm_send_md5_plugins(globals);
   comm_send_preferences(globals);
   comm_send_rules(globals);
   ntp_1x_send_dependencies(globals);

   /* become process group leader and the like ... */
   start_daemon_mode();
wait :   
#ifdef ENABLE_SAVE_TESTS
   if(arg_get_value(globals, "RESTORE-SESSION"))
     arg_set_value(globals, "RESTORE-SESSION", sizeof(int),(void*)2);
   else
     arg_add_value(globals, "RESTORE-SESSION", ARG_INT, sizeof(int),(void*)2); 
#endif       
   comm_wait_order(globals);
   preferences_reset_cache();
   plugins_set_ntp_caps(plugins, arg_get_value(globals, "ntp_caps"));
   rules = arg_get_value(globals, "rules");
   ntp_1x_timestamp_scan_starts(globals);
   e = attack_network(globals);
   ntp_1x_timestamp_scan_ends(globals);
   if(e < 0)
   	EXIT(0);
   comm_terminate(globals);
   if(arg_get_value(prefs, "ntp_keep_communication_alive"))
    {
   	log_write("user %s : Kept alive connection",
			(char*)arg_get_value(globals, "user"));
   	goto wait;
    } 
  }

 shutdown_and_exit:
 if (soc2 >= 0)
   close_stream_connection(soc2);
 else
   {
 shutdown(soc, 2);
 close(soc);
   }

 /* kill left overs */
 end_daemon_mode();
 EXIT(0);
}


static void 
main_loop()
{
  char		*cert, *key, *passwd, *ca_file, *s, *ssl_ver;
  int force_pubkey_auth;
  char *old_addr = 0, *asciiaddr = 0;
  time_t last = 0;
  int count = 0;
  
  setproctitle("waiting for incoming connections");
  /* catch dead children */
  nessus_signal(SIGCHLD, sighand_chld);

#if DEBUG_SSL > 1
  fprintf(stderr, "**** in main_loop ****\n");
#endif

  nessus_init_random();

#define SSL_VER_DEF_NAME	"TLSv1"
#define SSL_VER_DEF_ENCAPS	NESSUS_ENCAPS_TLSv1
  ssl_ver = preferences_get_string(g_preferences, "ssl_version");
  if (ssl_ver == NULL || *ssl_ver == '\0')
    ssl_ver = SSL_VER_DEF_NAME;
    
  if (strcasecmp(ssl_ver, "NONE") != 0)
    {
      if (nessus_SSL_init(NULL) < 0)
	{
	  fprintf(stderr, "Could not initialize openvas SSL!\n");
	  exit(1);
	}
      /*
       * In case the code is changed and main_loop is called several time, 
       * we initialize ssl_ctx only once
       */

      if (ovas_server_ctx == NULL)
	{
	  int encaps = -1;

	  if (strcasecmp(ssl_ver, "SSLv2") == 0)
	    {
	      fprintf(stderr, "SSL version 2 is not supported anymore!\n");
	      exit(1);
	    }
	  else if (strcasecmp(ssl_ver, "SSLv3") == 0)
	    encaps = NESSUS_ENCAPS_SSLv3;
	  else if (strcasecmp(ssl_ver, "SSLv23") == 0)
	    encaps = NESSUS_ENCAPS_SSLv23;
	  else if (strcasecmp(ssl_ver, "TLSv1") == 0)
	    encaps = NESSUS_ENCAPS_TLSv1;
	  else
	    {
	      fprintf(stderr, "Unknown SSL version \"%s\"\nSwitching to default " SSL_VER_DEF_NAME "\n", ssl_ver);
	      encaps = SSL_VER_DEF_ENCAPS;
	    }


	  ca_file = preferences_get_string(g_preferences, "ca_file");
	  if (ca_file == NULL)
	    {
	      fprintf(stderr,
		      "*** 'ca_file' is not set - did you run openvas-mkcert?\n");
	      exit(1);
	    }

	  passwd = preferences_get_string(g_preferences, "pem_password");
	  cert = preferences_get_string(g_preferences, "cert_file");
	  key = preferences_get_string(g_preferences, "key_file");

	  if (cert == NULL)
	    {
	      fprintf(stderr,
		      "*** 'cert_file' is not set - did you run openvas-mkcert?\n");
	      exit (1);
	    }
  
	  if (key == NULL)
	    {
	      fprintf(stderr,
		      "*** 'key_file' is not set - did you run openvas-mkcert?\n");
	      exit (1);
	    }

	  s = arg_get_value(g_preferences, "force_pubkey_auth");
	  force_pubkey_auth = s != NULL && strcmp(s, "no") != 0;
	  ovas_server_ctx = ovas_server_context_new(encaps, cert, key, passwd,
						    ca_file, force_pubkey_auth);
	  if (!ovas_server_ctx)
	    {
	      fprintf(stderr, "Could not create ovas_server_ctx\n");
	      exit (1);
	    }
	}
    } /* ssl_ver != "NONE" */


  log_write("openvasd %s started\n", OPENVAS_FULL_VERSION);
  for(;;)
    {
      int soc;
      unsigned int lg_address = sizeof(struct sockaddr_in);
      struct sockaddr_in address;
      struct sockaddr_in * p_addr;

      struct arglist * globals;
      struct arglist * my_plugins, * my_preferences;
      struct openvas_rules * my_rules;
      
      if(restart != 0) restart_openvasd(); 

      wait_for_children1();
      /* prevent from an io table overflow attack against nessus */
      if (asciiaddr != 0) {
	time_t now = time (0);

	/* did we reach the max nums of connect/secs ? */
	if (last == now) {
	  if (++ count > OPENVASD_CONNECT_RATE) {
	    sleep (OPENVASD_CONNECT_BLOCKER);
	    last = 0 ;
	  }
	} else {
	  count = 0 ;
	  last = now ;
	}
	
	if (old_addr != 0) {
	  /* detect whether sombody logs in more than once in a row */
	  if (strcmp (old_addr, asciiaddr) == 0 &&
	      now < last + OPENVASD_CONNECT_RATE) {
	    sleep (1);
	  }
	  efree (&old_addr);
	  old_addr = 0 ; /* currently done by efree, as well */
	}
      }
      old_addr = asciiaddr ;
      asciiaddr = 0 ;

      soc = accept(g_iana_socket, (struct sockaddr *)(&address), &lg_address);
      if(soc == -1)continue;

      asciiaddr = estrdup(inet_ntoa(address.sin_addr));
#ifdef USE_LIBWRAP      
      {
       char host_name[1024];
        
      hg_get_name_from_ip(address.sin_addr, host_name, sizeof(host_name));
      if(!(hosts_ctl("openvasd", host_name, asciiaddr, STRING_UNKNOWN)))
      {
       shutdown(soc, 2);
       close(soc);
       log_write("Connection from %s rejected by libwrap", asciiaddr);
       continue;
      }
      }
#endif      
      log_write("connection from %s\n", (char *)asciiaddr);

      /* efree(&asciiaddr); */

      /* 
       * duplicate everything so that the threads don't share the
       * same variables.
       *
       * Useless when fork is used, necessary for the pthreads 
       *
       * MA: you cannot share an open SSL connection through fork/multithread
       * The SSL connection shall be open _after_ the fork
       */
      globals = emalloc(sizeof(struct arglist));
      arg_add_value(globals, "global_socket", ARG_INT, -1, GSIZE_TO_POINTER(soc));

      my_plugins = g_plugins;
      arg_add_value(globals, "plugins", ARG_ARGLIST, -1, my_plugins);

      my_preferences = g_preferences;
      arg_add_value(globals, "preferences", ARG_ARGLIST, -1, my_preferences);
      
      my_rules = /*rules_dup*/(g_rules);

      p_addr = emalloc(sizeof(struct sockaddr_in));
      *p_addr = address;
      arg_add_value(globals, "client_address", ARG_PTR, -1, p_addr);

      arg_add_value(globals, "rules", ARG_PTR, -1, my_rules);
      
      /* we do not want to create an io thread, yet so the last argument is -1 */
  
      if(create_process((process_func_t)server_thread, globals) < 0)
      {
        log_write("Could not fork - client won't be served");
	sleep (2);
      }
      close(soc);
      arg_free(globals);
    }
}


/*
 * Initialization of the network : 
 * we setup the socket that will listen for incoming connections on port <port>
 * on address <addr> (which are set to OPENVAS_IANA_OTP_PORT and INADDR_ANY by
 * default)
 */ 
static int 
init_network(port, sock, addr)
     int port;
     int * sock;
     struct in_addr addr;
{
  int option = 1;

  struct sockaddr_in address;

  if((*sock = socket(AF_INET, SOCK_STREAM, 0))==-1)
    {
	int ec = errno;
      log_write("socket(AF_INET): %s (errno = %d)\n", strerror(ec), ec);
      DO_EXIT(1);
    }
  bzero(&address, sizeof(struct sockaddr_in));
  address.sin_family = AF_INET;
  address.sin_addr = addr;
  address.sin_port = htons((unsigned short)port);

  setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));
  if(bind(*sock, (struct sockaddr *)(&address), sizeof(address))==-1)
    {
      fprintf(stderr, "bind() failed : %s\n", strerror(errno));      
      DO_EXIT(1);
    }

  if(listen(*sock, 10)==-1)
    {
      fprintf(stderr, "listen() failed : %s\n", strerror(errno));      
      shutdown(*sock, 2);
      close(*sock);
      DO_EXIT(1);
    }
  return(0);
}

/*
 * Initialize everything
 */
static int 
init_openvasd (options, first_pass, stop_early, be_quiet)
     struct arglist * options;    
     int first_pass;
     int stop_early; /* 1: do some initialization, 2: no initialization */
     int be_quiet;
{
  int  isck = -1;
  struct arglist * plugins = NULL;
  struct arglist * preferences = NULL;
  struct openvas_rules * rules = NULL;
  int iana_port = GPOINTER_TO_SIZE(arg_get_value(options, "iana_port"));
  char * config_file = arg_get_value(options, "config_file");
  struct in_addr * addr = arg_get_value(options, "addr");
  char * str;
  
  preferences_init(config_file, &preferences);
  
  if((str = arg_get_value(preferences, "max_hosts")) != NULL)
  {
    g_max_hosts = atoi(str);
    if( g_max_hosts <= 0 ) g_max_hosts = 15;
  } 
   
  if((str = arg_get_value(preferences, "max_checks")) != NULL)
  {
    g_max_checks = atoi(str);
    if( g_max_checks <= 0 )g_max_checks = 10;
  }
  
  
  
  arg_add_value(preferences, "config_file", ARG_STRING, strlen(config_file), estrdup(config_file));
  log_init(arg_get_value(preferences, "logfile"));
  
  rules_init(&rules, preferences);
#ifdef DEBUG_RULES
  rules_dump(rules);
#endif


  if ( stop_early == 0 ) {
    char * dir;

    dir = arg_get_value(preferences, "plugins_folder");

    store_init_sys(arg_get_value(preferences, "plugins_folder"));
    plugins = plugins_init(preferences, be_quiet);

    if ( first_pass != 0 )
      init_network(iana_port, &isck, *addr);
  }
  
  if(first_pass && !stop_early)
  {
    nessus_signal(SIGSEGV, sighandler);
    nessus_signal(SIGCHLD, sighand_chld);
    nessus_signal(SIGTERM, sighandler);
    nessus_signal(SIGINT, sighandler);
    nessus_signal(SIGHUP, sighup);
    nessus_signal(SIGUSR1, sighandler); /* openvasd dies, not its sons */
    nessus_signal(SIGPIPE, SIG_IGN);
  }

  arg_replace_value(options, "isck", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(isck));
  arg_replace_value(options, "plugins", ARG_ARGLIST, -1, plugins);
  arg_replace_value(options, "rules", ARG_PTR, -1, rules);
  arg_replace_value(options, "preferences", ARG_ARGLIST, -1, preferences);

  return(0);
}

int 
main(int argc, char * argv[], char * envp[])
{
  int exit_early = 0;
  int iana_port = -1;
  char * myself;
  struct in_addr addr; 
  struct in_addr * src_addrs = NULL;
  struct arglist * options = emalloc(sizeof(struct arglist));
  int i;
  int be_quiet = 0;
  int flag = 0;

  bzero(orig_argv, sizeof(orig_argv));
  for(i=0; i < argc; i++)
  {
    if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
      flag ++;
    orig_argv[i] = estrdup(argv[i]);
  }

  if (flag == 0)
  {
    orig_argv[argc] = estrdup("-q");
  }

  initsetproctitle(argc, argv, envp);

  if ((myself = strrchr (*argv, '/')) == 0) 
    myself = *argv ;
  else
    myself ++ ;

  addr.s_addr = htonl(INADDR_ANY);
#ifdef USE_PTHREADS
  /* pull in library symbols - otherwise abort */
  nessuslib_pthreads_enabled ();
#endif

  static gboolean display_version = FALSE;
  static gboolean do_fork = FALSE;
  static gchar *address = NULL;
  static gchar *src_ip = NULL;
  static gchar *port = NULL;
  static gchar *config_file = NULL;
  static gboolean quiet = FALSE;
  static gboolean dump_cfg = FALSE;
  static gboolean print_specs = FALSE;
  static gboolean gen_config = FALSE;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = 
  {
    { "version", 'v', 0, G_OPTION_ARG_NONE, &display_version, "Display version information", NULL },
    { "background", 'D', 0, G_OPTION_ARG_NONE, &do_fork, "Run in daemon mode", NULL },
    { "listen", 'a', 0, G_OPTION_ARG_STRING, &address, "Listen on <address>", "<address>" },
    { "src-ip", 'S', 0, G_OPTION_ARG_STRING, &src_ip, "Send packets with a source IP of <ip[,ip...]>", "<ip[,ip...]>" },
    { "port", 'p', 0, G_OPTION_ARG_STRING, &port, "Use port number <number>", "<number>" },
    { "config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file, "Configuration file", "<.rcfile>" },
    { "dump-cfg", 'd', 0, G_OPTION_ARG_NONE, &dump_cfg, "Dump the openvasd compilation options", NULL },
    { "quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet, "Quiet (do not issue any messages to stdout)", NULL },
    { "cfg-specs", 's', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &print_specs, "", NULL },
    { "gen-config", 'g', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &gen_config, "", NULL },
    { NULL }
  };

  option_context = g_option_context_new("- server for the OpenVAS security scanner");
  g_option_context_add_main_entries(option_context, entries, NULL);
  if (!g_option_context_parse(option_context, &argc, &argv, &error))
  {
    g_print("%s\n\n", error->message);
    exit (0);
  }

  if (quiet)
    be_quiet = 1;

  if (gen_config)
    exit_early = 1; /* allow cipher initalization */

  if (print_specs)
  {
    exit_early  = 2; /* no cipher initialization */
      char *s = getenv ("OPENVASUSER");
      if (s != 0)
        arg_add_value(options, "user", ARG_STRING, strlen(s), s);
  }

  if (address != NULL)
  {
    if (!inet_aton(address, &addr))
    {
      printf("Invalid IP address.\n");
      printf("Please use %s --help for more information.\n", myself);
      DO_EXIT(0);
    }
  }

  if (port != NULL)
  {
    iana_port = atoi(port);
    if ((iana_port <= 0) || (iana_port >= 65536))
    {
      printf("Invalid port specification.\n");
      printf("Please use %s --help for more information.\n", myself);
      DO_EXIT(1);
    }
  }

  if (display_version)
  {
    printf("openvasd (%s) %s for %s\n\n", PROGNAME, OPENVAS_VERSION, OVS_OS_NAME);
    printf("Nessusd origin: (C) 1998 - 2004 Renaud Deraison <deraison@nessus.org>\n");
    printf("New code since openvasd: (C) 2007, 2008 Intevation GmbH\n");
    printf("\n");
    DO_EXIT(0);
  }

  if (config_file != NULL)
  {
    arg_add_value (options, "acc_hint", ARG_INT, sizeof(int), (void*)1);
  }

  if (src_ip != NULL)
  {
    src_addrs = (struct in_addr* )convert_ip_addresses(src_ip);
    socket_source_init(src_addrs);
  }

  if (dump_cfg)
  {
    printf("This is OpenVAS %s for %s %s\n", OPENVAS_VERSION, OVS_OS_NAME, OVS_OS_VERSION);
    printf("compiled with %s\n", OVS_COMPILER);
    printf("Current setup :\n");
    printf("\topenvas-libnasl                : %s\n", nasl_version());
    printf("\topenvas-libraries              : %s\n", nessuslib_version());
    printf("\tSSL is used for client / server communication\n");
    printf("\tRunning as euid                : %d\n", geteuid());
#ifdef USE_LIBWRAP
    printf("\tCompiled with tcpwrappers support\n");
#endif
    printf("\n\nInclude these infos in your bug reports\n");
    DO_EXIT(0);
  }

  if(exit_early == 0)
    bpf_server_pid = bpf_server();


  if(iana_port == -1)iana_port = OPENVAS_IANA_OTP_PORT;
  if (!config_file)
  {
    config_file = emalloc(strlen(OPENVASD_CONF) + 1);
    strncpy(config_file, OPENVASD_CONF, strlen(OPENVASD_CONF));
  }

  arg_add_value(options, "iana_port", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(iana_port));
  arg_add_value(options, "config_file", ARG_STRING, strlen(config_file), config_file);
  arg_add_value(options, "addr", ARG_PTR, -1, &addr);

  init_openvasd (options, 1, exit_early, be_quiet);
  g_options = options;
  g_iana_socket = GPOINTER_TO_SIZE(arg_get_value(options, "isck"));
  g_plugins = arg_get_value(options, "plugins");
  g_preferences = arg_get_value(options, "preferences");
  g_rules = arg_get_value(options, "rules");

  /* special treatment */
  if (print_specs)
    dump_cfg_specs (g_preferences) ;
  if (exit_early)
    exit (0);

  nessus_init_svc();

  if(do_fork)
  {
    /*
    * Close stdin, stdout and stderr 
    */
    i = open("/dev/null", O_RDONLY, 0640); 
    if (dup2(i, STDIN_FILENO) != STDIN_FILENO)
      fprintf(stderr, "Could not redirect stdin to /dev/null: %s\n", strerror(errno));
    if (dup2(i, STDOUT_FILENO) != STDOUT_FILENO)
      fprintf(stderr, "Could not redirect stdout to /dev/null: %s\n", strerror(errno));
    if (dup2(i, STDERR_FILENO) != STDERR_FILENO)
      fprintf(stderr, "Could not redirect stderr to /dev/null: %s\n", strerror(errno));
    close(i);
    if(!fork())
    {
      setsid();
      create_pid_file();
      main_loop();
    }
  }
  else
  {
    create_pid_file();
    main_loop();
  }
  DO_EXIT(0);
  return(0);
}
