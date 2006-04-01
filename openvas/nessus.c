/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */

#include <includes.h>
#include "password_dialog.h"

#include "read_target_file.h"
#include "comm.h"
#include "auth.h"
#include "nessus.h"
#include "attack.h"
#include "report.h"
#include "parser.h"
#include "sighand.h"
#include "preferences.h"
#include "globals.h"
#include "corevers.h"
#include <getopt.h>
#include "password_dialog.h"
#include "filter.h"

#include "backend.h"
#include "nbe_output.h"
#include "nsr_output.h"
#include "html_output.h"
#include "html_graph_output.h"
#include "latex_output.h"
#include "text_output.h"
#include "xml_output.h"
#include "xml_output_ng.h"



#include "cli.h"

#ifdef HAVE_SSL
#include <openssl/x509v3.h>
#endif

#ifdef USE_AF_UNIX
#undef NESSUS_ON_SSL
#endif

#ifdef NESSUS_ON_SSL
#include "sslui.h"
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xFFFFFFFF
#endif

#ifndef inc_optind
#define inc_optind() (optind++)
#endif

struct arglist * Plugins  = NULL;
struct arglist * Scanners = NULL;
struct arglist * Dependencies = NULL;
struct arglist * Upload   = NULL;
#ifdef ENABLE_SAVE_TESTS
harglst * Sessions = NULL;
int Sessions_saved = 0;
int Detached_sessions_saved = 0;
#endif
#ifdef ENABLE_SAVE_KB
int DetachedMode = 0;
#endif

int PluginsNum;
int ScannersNum;
struct arglist * Prefs;
struct arglist * MainDialog;
struct arglist * ArgSock;
char * Alt_rcfile = NULL;
struct plugin_filter Filter;
int GlobalSocket;
char * stored_pwd = NULL;
int DontCheckServerCert = 0;
int F_show_pixmaps;
int F_quiet_mode;
int F_openvasd_running;
int First_time = 0;
int ListOnly = 0;

#ifndef USE_AF_INET      
#undef ENABLE_CRYPTO_LAYER
#endif


void init_globals();



#ifdef NESSUS_ON_SSL
#define CLN_AUTH_SRV 1

static int
verify_callback(preverify_ok, ctx)
     int		preverify_ok;
     X509_STORE_CTX	*ctx;
{
#if DEBUG_SSL > 1
  fprintf(stderr, "verify_callback> preverify_ok=%d\n", preverify_ok);
#endif
  return preverify_ok;
}
#endif



#ifdef CLN_AUTH_SRV

/*
 * split a line "var=value" into two components
 * returns 0 if = was not found, 1 if line looks like "var=", 2 if OK
 */
static int
split_var_val(line, var, val)
     const	char	*line;
     char	*var, *val;
{
  const char	*p;
  char	*q;

  for (p = line, q = var; *p != '=' && *p != '\0' && *p != '\n'; p ++, q ++)
    *q = *p;
  *q = '\0';
  if (*p == '\0')
    return 0;
  
  for (q = val, p ++; *p != '\0' && *p != '\n'; p ++, q ++)
    *q = *p;
  *q = '\0';
  return q == line ? 1 : 2;
}

/* 
 * Returns -1 if error, 0 if hash not found, 1 if found
 */
static int
get_server_cert_hash(sname, hash)
     const char		*sname;
     unsigned char	*hash;
{
  char	*fname;
  FILE	*fp;
  char	line[1024];
  char	ho[1024], ha[1024];
  int	i, x;


  if ((fname = preferences_get_altname("cert")) == NULL)
    return -1;

  fp = fopen(fname, "r");
  efree(&fname);
  if (fp == NULL)
    {
      if (errno == ENOENT)
	return 0;
      else
	return -1;
    }

  while (fgets(line, sizeof(line), fp) != NULL)
    {
      if (split_var_val(line, ho, ha) == 2)
	{
	  if (strcmp(ho, sname) == 0 && strlen(ha) == SHA_DIGEST_LENGTH * 2)
	    {
	      for (i = 0; i < SHA_DIGEST_LENGTH; i ++)
		{
		  (void) sscanf(ha + 2 * i, "%2x", &x);
		  hash[i] = x;
		}
	      fclose(fp);
	      return 1;
	    }
	}
    }

  if (ferror(fp))
    return -1;
  else
    return 0;
}

static void
print_hash(hash_str, hash)
     char	*hash_str;
     const unsigned char	*hash;
{
  int	i;

  for (i = 0; i < SHA_DIGEST_LENGTH; i ++)
    sprintf(hash_str + 2 * i, "%02x", hash[i]);
}

static int
set_server_cert_hash(sname, hash)
     const char		*sname;
     unsigned char	*hash;
{
  char	ho[1024], ha[1024];
  char	*fname = NULL;
  FILE	*fp1 = NULL, *fp2 = NULL;
  char	line[1024];
  int	x;
  int	found;

  if ((fname = preferences_get_altname("cert")) == NULL)
    return -1;
  
  if ((fp2 = tmpfile()) == NULL)
    goto error;
  
  fp1 = fopen(fname, "r");
  if (fp1 == NULL && errno != ENOENT)
    goto error;

  found = 0;
  if (fp1 != NULL)
    {
      while (fgets(line, sizeof(line), fp1) != NULL)
	{
	  x = strlen(line);
	  if (x > 0 && line[x - 1] != '\n') /* invalid line */
	    continue;

	  if (split_var_val(line, ho, ha) == 2)
	    {
	      if (strcmp(ho, sname) == 0)
	      {
		if (found) /* multiple lines */
		  continue;
		else
		  {
		    print_hash(ha, hash);
		    sprintf(line, "%s=%s\n", ho, ha);
		    found = 1;
		  }
	      }
	    }
	  if (fputs(line, fp2) < 0)
	    goto	error;
	}
      (void) fclose(fp1);
    }

  if (! found)
    {
      print_hash(ha, hash);
      sprintf(line, "%s=%s\n", sname, ha);
      if (fputs(line, fp2) < 0)
	goto error;
    }

  rewind(fp2);
  if ((fp1 = fopen(fname, "w")) == NULL)
    goto error;

  while (fgets(line, sizeof(line), fp2) != NULL)
    (void) fputs(line, fp1);

  if (ferror(fp1) || fclose(fp1) < 0)
    goto error;
  (void) fclose(fp2);		/* auto delete */
  efree(&fname);
  return 0;

 error:
  if (fp1 != NULL)
    fclose(fp1);
  if (fp2 != NULL)
    fclose(fp2);
  if (fname != NULL)
    efree(&fname);
    
  return -1;  
}
#endif


/*
 * connect_to_openvasd
 *
 * This function establishes the connection between
 * nessus and openvasd, logs in and reads the plugin
 * list from the server.
 *
 */
char *
connect_to_openvasd(hostname, port, login, pass)
	char * hostname;
	int port;
	char * login;
	char * pass; /* is a cipher in case of the crypto layer */
{
#ifdef CLN_AUTH_SRV
  int	paranoia_level;
  /*
   * 0: not initialised.
   * 1: remember certificate
   * 2: trust CA
   * 3: trust CA & check certificate
   */      
#endif
#ifdef NESSUS_ON_SSL
  static SSL_CTX	*ssl_ctx = NULL;
  static SSL_METHOD	*ssl_mt = NULL;
  SSL		*ssl = NULL;
  char		*cert, *key, *client_ca, *trusted_ca, *ssl_ver;
  char		*ssl_cipher_list;
  STACK_OF(X509_NAME)	*cert_names;
#endif
  int soc, soc2;
  int opt;
#ifndef USE_AF_INET
  struct sockaddr_un address;
  char * name = AF_UNIX_PATH;
#endif

  init_globals();
  if(arg_get_type(Prefs, "openvasd_host")>=0)
   arg_set_value(Prefs, "openvasd_host", strlen(hostname), strdup(hostname));
  else
   arg_add_value(Prefs, "openvasd_host", ARG_STRING, strlen(hostname),
   		strdup(hostname));
			
  if(arg_get_type(Prefs, "openvasd_user")>=0)
   arg_set_value(Prefs, "openvasd_user", strlen(login), strdup(login));
  else
   arg_add_value(Prefs, "openvasd_user", ARG_STRING, strlen(login),
   		strdup(login));		

#ifdef CLN_AUTH_SRV
  paranoia_level = (int) arg_get_value(Prefs, "paranoia_level");
  if(!paranoia_level && !DontCheckServerCert){
  	paranoia_level = sslui_ask_paranoia_level();
	if(paranoia_level >= 1 && paranoia_level <= 3)
	{
	arg_add_value(Prefs, "paranoia_level", ARG_INT, sizeof(int),(void*)paranoia_level);
	preferences_save(Plugins);
	}
	}	
#endif
   
#ifdef USE_AF_INET
  soc = open_sock_tcp_hn(hostname, port);
  
  
  if(soc<0)
  	{
  	static char err_msg[1024];
  	struct in_addr a = nn_resolve(hostname);
	if(a.s_addr == INADDR_NONE) 
		return("Host not found !");
  	else
		{
		snprintf(err_msg, sizeof(err_msg), "Could not open a connection to %s\n", hostname);
  		return err_msg;
		}
  	}
	
  opt = 1;	
  setsockopt(soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
 
#else
  if((soc = socket(AF_UNIX, SOCK_STREAM,0))==-1){
  	perror("socket ");
  	exit(1);
  	}
  bzero(&address, sizeof(struct sockaddr_un));
  address.sun_family = AF_UNIX;
  bcopy(name, address.sun_path, strlen(name));
  if(connect(soc, (struct sockaddr*)&address, sizeof(address))==-1)
  {
	char * error = emalloc(255+strlen(name)+strlen(strerror(errno)));
	sprintf(error, "Could not connect to %s - %s\n", name, strerror(errno));
	return error;
  }
#endif  

#ifdef NESSUS_ON_SSL
#define SSL_VER_DEF_NAME	"TLSv1"
#define SSL_VER_DEF_METH	TLSv1_client_method
  ssl_ver = arg_get_value(Prefs, "ssl_version");
  if (ssl_ver == NULL || *ssl_ver == '\0')
    ssl_ver = SSL_VER_DEF_NAME;

  if (strcasecmp(ssl_ver, "NONE") != 0)
    {
      if(nessus_SSL_init(NULL) < 0)
	{
	  return("Could not initialize the OpenSSL library !\n\
Please launch openvas-mkrand(1) first !");
	}
      if (ssl_mt == NULL)
	{
	  if (strcasecmp(ssl_ver, "SSLv2") == 0)
	    ssl_mt = SSLv2_client_method();
	  else if (strcasecmp(ssl_ver, "SSLv3") == 0)
	    ssl_mt = SSLv3_client_method();
	  else if (strcasecmp(ssl_ver, "SSLv23") == 0)
	    ssl_mt = SSLv23_client_method();
	  else if (strcasecmp(ssl_ver, "TLSv1") == 0)
	    ssl_mt = TLSv1_client_method();
	  else
	    {
	      fprintf(stderr, "Unknown SSL version \"%s\"\nSwitching to default " SSL_VER_DEF_NAME "\n", ssl_ver);
	      ssl_ver = SSL_VER_DEF_NAME;
	      ssl_mt = SSL_VER_DEF_METH();
	    }
      
	  if (ssl_mt == NULL)
	    {
	      char	s[32];
	      sprintf(s, "%s_client_method", ssl_ver);
	      sslerror(s);
	      return "SSL error";
	    }
	}

      if (ssl_ctx == NULL)
	if ((ssl_ctx = SSL_CTX_new(ssl_mt)) == NULL)
	  {
	    sslerror("SSL_CTX_new");
	    return "SSL error";
	  }

      if (SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL) < 0)
	sslerror("SSL_CTX_set_options(SSL_OP_ALL)");

#define NOEXP_CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5:RC4-64-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5"
#define STRONG_CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"
#define EDH_CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DHE-DSS-RC4-SHA"
      ssl_cipher_list = arg_get_value(Prefs, "ssl_cipher_list");
      if (ssl_cipher_list != NULL && *ssl_cipher_list != '\0' )
	{
	  if (strcmp(ssl_cipher_list, "noexp") == 0)
	    ssl_cipher_list = NOEXP_CIPHER_LIST;
	  else if (strcmp(ssl_cipher_list, "strong") == 0)
	    ssl_cipher_list = STRONG_CIPHER_LIST;
	  else if (strcmp(ssl_cipher_list, "edh") == 0)
	    ssl_cipher_list = EDH_CIPHER_LIST;
	  
	  if (! SSL_CTX_set_cipher_list(ssl_ctx, ssl_cipher_list))
	    sslerror("SSL_CTX_set_cipher_list");
	}

      if ((ssl = SSL_new(ssl_ctx)) == NULL)
	{
	  sslerror("SSL_new");
	  return "SSL_error";
	}
      cert = arg_get_value(Prefs, "cert_file");
      key = arg_get_value(Prefs, "key_file");
      client_ca = arg_get_value(Prefs, "client_ca");

      if (pass != NULL && key != NULL)
	{
	  nessus_install_passwd_cb(ssl_ctx, pass);
	 /*  pass = "*"; */	/* So that we do not send it over the network */
	}

      if (cert != NULL)
	SSL_use_certificate_file(ssl, cert, SSL_FILETYPE_PEM);
      if (key != NULL)
	SSL_use_PrivateKey_file(ssl, key, SSL_FILETYPE_PEM);

      if (client_ca != NULL)
	{
	  cert_names = SSL_load_client_CA_file(client_ca);
	  if (cert_names != NULL)
	    SSL_CTX_set_client_CA_list(ssl_ctx, cert_names);
	  else
	    sslerror("SSL_load_client_CA_file");
	}
#ifdef CLN_AUTH_SRV
      if (paranoia_level == 2 || paranoia_level == 3)
	{
	  trusted_ca = arg_get_value(Prefs, "trusted_ca");
	  if (trusted_ca == NULL)
	    {
	      fprintf(stderr, "paranoia_level=%d but \"trusted_ca\"not set\n", 
		      paranoia_level);
	      paranoia_level = 1;
	    }
	  else
	    {
	      SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
#if 0
	      if (SSL_CTX_set_default_verify_paths(ssl_ctx) <= 0)
		sslerror("SSL_CTX_set_default_verify_paths");
#endif  
	      if (! SSL_CTX_load_verify_locations(ssl_ctx, trusted_ca, NULL))
		sslerror("SSL_CTX_load_verify_locations");
	    }
	}
#endif    

      if (! SSL_set_fd(ssl, soc))
	{
	  sslerror("SSL_set_fd");
	  return "SSL error";
	}

  
      if (SSL_connect(ssl) <= 0)
	{
	  sslerror("SSL_connect");
	  return "SSL error";
	}

#if DEBUG_SSL > 1
      {
	char	*p = SSL_get_cipher(ssl);
	if (p != NULL) 
	  fprintf(stderr, "SSL_get_cipher = %s\n", p);
      }
#endif

#ifdef CLN_AUTH_SRV
      if (DontCheckServerCert == 0 && (paranoia_level == 1 || paranoia_level == 3))
	{
	  X509	*cert = SSL_get_peer_certificate(ssl);
	  char	stored_hash[SHA_DIGEST_LENGTH];
      
	  if (get_server_cert_hash(hostname, stored_hash) <= 0)
	    memset(stored_hash, 0, sizeof(stored_hash));

	  if(cert == NULL)
	    {
	      sslerror("SSL_get_peer_certificate");
	      return "SSL error: cannot get server certificate";
	    }
	  X509_check_purpose(cert, -1, 0); /* Make sure hash is correct */
	  if (memcmp(cert->sha1_hash, stored_hash, SHA_DIGEST_LENGTH) != 0)
	    {
	      int x = sslui_check_cert(ssl);
	      if(x < 0)return "Invalid server certificate";

	      if (set_server_cert_hash(hostname, cert->sha1_hash) < 0)
		perror("Could not save server certificate");
	    }
	}
#endif
    } /* ssl_ver != "NONE" */

  if ((soc2 = nessus_register_connection(soc, ssl)) <0)
    {
      shutdown(soc, 2);
      return "Could not register the connection";
    }
  stream_set_buffer(soc2, 1024 * 1024);
  soc = soc2;
  
#else 
  if((soc2 = nessus_register_connection(soc, NULL)) < 0)
   {
    return "Could not register the connection";
   }
  stream_set_buffer(soc2, 1024 * 1024);
   soc = soc2;
#endif 
  GlobalSocket = soc;
  ArgSock = emalloc(sizeof(struct arglist));
  arg_add_value(ArgSock, "global_socket", ARG_INT, -1, (void *)GlobalSocket);


  if(comm_init(soc,PROTO_NAME) || (auth_login(login, pass)))
    {
#ifdef NESSUS_ON_SSL
      close_stream_connection(GlobalSocket);
#else
      shutdown(soc, 2);
#endif
      return("Remote host is not using the good version of the Nessus communication protocol (1.2) or is tcpwrapped");
    }
  if(comm_get_plugins())return("Login failed");
  if(F_quiet_mode)
  {
  	cli_comm_get_preferences(Prefs);
	comm_get_rules(Prefs);
	comm_get_dependencies();
  }
  else
  {
  if(!First_time){
	comm_get_preferences(Prefs);
  	comm_get_rules(Prefs);	
	comm_get_dependencies();
	}
  else
  	{
	/*
	 * Ignore the server preferences if we already logged in
	 */
	struct arglist * devnull = emalloc(sizeof(*devnull));
	comm_get_preferences(devnull);
	comm_get_rules(devnull);
	arg_free(devnull);
	}
  }

	if(comm_server_restores_sessions(Prefs))
	  {
	  Sessions = comm_get_sessions();
	 }

 
  	
  prefs_check_defaults(Prefs);

  return(NULL);
}

/*
 * init_globals
 *
 * initializes two main global variables : plugins and
 * scanners
 *
 */
void 
init_globals()
{
  if(!Plugins)Plugins = emalloc(sizeof(struct arglist));
  if(!Scanners)Scanners = emalloc(sizeof(struct arglist));
}


void 
display_help 
  (char *pname)
{
  
 printf("%s, version %s\n", pname, NESSUS_FULL_VERSION);
#ifdef USE_AF_INET
 printf("\nCommon options :\n %s [-vnh] [-c .rcfile] [-V] [-T <format>]",pname);
 printf("\nBatch-mode scan:\n %s -q [-pPS] <host> <port> <user> <pass> <targets-file> <result-file>",pname);
 printf("\nList sessions  :\n %s -s -q <host> <port> <user> <pass> ",pname);
 printf("\nRestore session:\n %s -R <sessionid> -q <host> <port> <user> <pass> <result-file> ",pname);
#else /* AF_UNIX */
 printf("\nBatch-mode scan:\n %s -q [-pPS] <user> <pass> <targets-file> <result-file>",pname);
 printf("\nList sessions  :\n %s -s -q <user> <pass> ",pname);
 printf("\nRestore session:\n %s -R <sessionid> -q <user> <pass> <result-file> ",pname);
#endif
 printf("\nReport conversion :\n %s -i in.[nsr|nbe] -o out.[html|xml|nsr|nbe]\n\n", pname);
 printf("General options :\n");
 printf("\t-v : shows version number\n");
 printf("\t-h : shows this help\n"); 
 printf("\t-n : No pixmaps\n");
 printf("\t-T : Output format: 'nbe', 'html', 'html_graph', 'text', 'xml',\n");
 printf("\t    'old-xml' 'tex' or 'nsr'\n");
 printf("\t-V : make the batch mode display status messages\n");
 printf("\t    to the screen.\n");
 printf("\t-x : override SSL \"paranoia\" question preventing nessus from\n");
 printf("\t    checking certificates.\n\n");
 
 printf("The batch mode (-q) arguments are :\n");
#ifdef USE_AF_INET
 printf("\thost     : openvasd host\n");
 printf("\tport     : openvasd host port\n");
#endif
 printf("\tuser     : user name\n");
 printf("\tpass     : password\n");
 printf("\ttargets  : file containing the list of targets\n");
 printf("\tresult   : name of the file where \n\t\t   nessus will store the results\n");
 printf("\t-p       : obtain list of plugins installed on the server.\n");
 printf("\t-P       : obtain list of server and plugin preferences.\n");
 printf("\t-S       : issue SQL output for -p and -P (experimental).\n");
 /* TODO: The following options are not described yet: -m  (jfs) */
}
 
/*
 * version check (for libraries)
 *
 * Returns 0  if versions are equal
 * Returns 1 if the fist version is newer than the second 
 * Return -1 if the first version is older than the second
 *
 */
static int 
version_check(a,b)
 char * a, *b;
{
 int major_a = 0, minor_a = 0, patch_a = 0;
 int major_b = 0, minor_b = 0, patch_b = 0;
 
 
 major_a = atoi(a);
 a = strchr(a, '.');
 if(a)
 {
  minor_a = atoi(a+sizeof(char));
  a = strchr(a+sizeof(char), '.');
  if(a)patch_a = atoi(a+sizeof(char));
 }
 
 major_b = atoi(b);
 b = strchr(b, '.');
 if(b)
 {
  minor_b = atoi(b+sizeof(char));
  b = strchr(b+sizeof(char), '.');
  if(b)patch_b = atoi(b+sizeof(char));
 }
 
 if(major_a < major_b)return -1;
 if(major_a > major_b)return 1;
 
 /* major are the same */
 if(minor_a < minor_b)return -1;
 if(minor_a > minor_b)return 1;
 
 /* minor are the sames */
 if(patch_a < patch_b)return -1;
 if(patch_a > patch_b)return 1;
 
 return 0;
}

	
	




 
int main(int argc, char * argv[])
{
  int i, xac;
  char *myself, **xav;
  int gui = 1;
  char * output_type = NULL;
  int opt_m = 0;
  int list_sessions = 0;
  int list_plugins = 0;
  int list_prefs  = 0;
  int sqlize_output = 0;
  int restore_session = 0;
  char * session_id = NULL;
  char * arg = NULL;
  int opt_V= 0;
  int opt_i= 0;
  int opt_o= 0;
  char * inf = NULL, *outf = NULL;

  /*
   * Version check
   */
   
 

  if(version_check(NESSUS_VERSION, nessuslib_version())>0)
  {
   fprintf(stderr, 
"Error : we are linked against nessus-libraries %s. \n\
Install nessus-libraries %s or make sure that\n\
you have deleted older versions nessus libraries from your system\n",
        nessuslib_version(), NESSUS_VERSION);
  }

  

  
  if ((myself = strrchr (*argv, '/')) == 0
#ifdef _WIN32
      && (myself = strrchr (*argv, '\\')) == 0
#endif
      ) myself = *argv ;
  else
    myself ++ ;

  PluginsNum = 0;
  ScannersNum = 0;
  Scanners = Plugins = MainDialog = NULL;
  ArgSock = NULL;
  GlobalSocket = -1;

  /* provide a extra acrgc/argv vector for later use */
  xac = 1;
  xav = append_argv (0, myself);
#if 0
  pty_logger ((void(*)(const char*, ...))printf);
#endif
  for (;;) {
    int option_index = 0;
    static struct option long_options[] =
    {
      {"help",                 no_argument, 0, 'h'},
      {"version",              no_argument, 0, 'v'},
      /*
       * Key options should be removed! (MA 2001-11-21)
       */
      {"batch-mode",           no_argument, 0, 'q'},
      {"make-config-file",     no_argument, 0, 'm'},
      {"config-file", 	 required_argument, 0, 'c'},
      {"output-type",	 required_argument, 0, 'T'},
      {"verbose",		no_argument,0, 'V'},
      {"list-plugins",		no_argument,0, 'p'},
      {"list-prefs",		no_argument,0, 'P'},
      {"in-report",	required_argument, 0, 'i'},
      {"out-report",	required_argument, 0, 'o'},
      {"dont-check-ssl-cert", no_argument,	0,  'x'},
      {"sqlize-output", no_argument, 0, 'S'},
#ifdef ENABLE_SAVE_TESTS      
      {"list-sessions",        no_argument, 0, 's'},
      {"restore-session",required_argument, 0, 'R'},
#endif      
      {0, 0, 0, 0}
    };

    if ((i = getopt_long 
	 (argc, argv, "Ppc:T:Vvhqn?r:01sR:Smi:o:x", long_options, &option_index)) == EOF)
      break;
     else
      
    switch(i) {
    case 'x' :
    	DontCheckServerCert++;
	break;
     case 'i': 
     	opt_i++;
	if(!optarg)
	{ 
	 display_help("nessus");
	 exit(1);
	}
	inf = estrdup(optarg);
	break;
   case 'o':
   	opt_o++;
   	if(!optarg)
	{
	 display_help("nessus");
	 exit(1);
	}
	outf = estrdup(optarg);
	break;
     case 'T' :
       if(!optarg)
       {
        display_help("nessus");
	exit (1);
       }
        if(optarg[0]=='=')inc_optind(); /* no optind++ on Win32 -- jordan */
	output_type = optarg;
	break;    
     case 'c' :
       if(!optarg)
       {
        display_help("nessus");
	exit (1);
       }
       else Alt_rcfile = estrdup(optarg);
       break;

    case 'V':
      	 opt_V++;
	 break;
    case 'v' :
    	printf("nessus (%s) %s for %s\n\n(C) 1998 - 2003 Renaud Deraison <deraison@nessus.org>\n", 
    			PROGNAME,NESSUS_VERSION, NESS_OS_NAME);
#ifdef NESSUS_ON_SSL
	printf("\tSSL used for client - server communication\n");
#else
	printf("\tclient - server communication is done in PLAIN TEXT\n");
#endif					
	printf ("\n");
    	exit(0);
    	break;

    case 'm' :
      opt_m ++;
      break;
    case 'q' :
      gui = 0; 
      F_quiet_mode ++ ;
      break;
    case 'P':
     list_prefs++;
     ListOnly = 1;
     break;
    case 'p' :
     list_plugins ++;
      break;
      
     case 'S': 
    	sqlize_output++;
	break;  
      
#ifdef ENABLE_SAVE_TESTS
    case 's' :
      list_sessions ++;
      break;
   
    case 'R' :
      restore_session ++;
      if(optarg)session_id = strdup(optarg);
      else {
      	display_help(myself);
	exit(1);
	}
       break;	
#endif
    default:
      display_help (myself);
      exit (0);
    }
  }
  
 if(opt_i || opt_o)
 {
  int be;
  preferences_init(&Prefs);
  if(!(opt_i && opt_o))
   {
    display_help("nessus");
    exit(1);
   }
  F_quiet_mode = 1;
  be = backend_import_report(inf);
  if(be >= 0)
  {
   char * type;
   if(!output_type)
    {
     type = strrchr(outf, '.');
     if(type != NULL)type++;
     else type = "nbe";
    }
   else {
    type = output_type;
    }
   if(!strcmp(type, "tex") ||
      !strcmp(type, "latex"))
      	arglist_to_latex(backend_convert(be), outf);
   else if(!strcmp(type, "txt") ||
   	   !strcmp(type, "text"))
	arglist_to_text(backend_convert(be), outf);
   else if(!strcmp(type, "nsr"))
   	backend_to_nsr(be, outf);
   else if(!strcmp(type, "html"))
   	arglist_to_html(backend_convert(be), outf);
   else if(!strcmp(type, "html_pie") || !strcmp(type, "html_graph"))
   	arglist_to_html_graph(backend_convert(be), outf);
   else if(!strcmp(type, "nbe"))
   	backend_to_nbe(be, outf);
   else if(!strcmp(type, "old-xml"))
   	arglist_to_xml(backend_convert(be), outf);
   else if(!strcmp(type, "xml"))
   	backend_to_xml_ng(be, outf); 
   else
   	{
	 fprintf(stderr, "Unsupported report type '%s'\n", type);
	 exit(1);
	 }
  backend_close(be);
  exit(0);
  }
  else
  {
   fprintf(stderr, "Could not import '%s' - is it a .nsr or .nbe file ?\n",
   		inf);		
  }
  exit(0);
 }

 if(!gui)F_quiet_mode = 1;
 
 if(opt_m && !F_quiet_mode)
 {
  display_help(myself);
  exit(1);
 }
	
#ifdef USE_AF_INET
#define BATCH_USAGE "-q host port user pass"
#else
#define BATCH_USAGE "-q user pass"
#endif
	
#ifdef ENABLE_SAVE_TESTS
 if(list_sessions && (argc<=optind) && !F_quiet_mode)
 {
  fprintf(stderr, "list-sessions requires %s\n", BATCH_USAGE);
  exit(1);
 }
 
 if(restore_session && (argc<=optind) && !F_quiet_mode)
 {
  fprintf(stderr, "restore-session requires -q %s result\n", BATCH_USAGE);
  exit(1);
 }
 
 if(restore_session && list_sessions)
 {
  fprintf(stderr, "--restore-session and --list-sessions are mutually exclusive\n");
  exit(1);
 }
#endif


 if(argc>optind || F_quiet_mode)
     {
      signal(SIGINT, sighand_exit);
      signal(SIGQUIT, sighand_exit);
      signal(SIGKILL, sighand_exit);
      signal(SIGTERM, sighand_exit);
      
      F_quiet_mode = 1;
     }

  /* system environment set up */
  if(!opt_m)
  {
  if (preferences_init(&Prefs))
    exit (2);
 }
 else
  Prefs = emalloc(sizeof(struct arglist));


  if(opt_V && !F_quiet_mode)
  {
	  fprintf(stderr, "Verbose mode can only be used in batch mode\n");
	  exit(1);
  }
  
  /* do we run in batchmode ? */
  if (argc > optind || F_quiet_mode) {
    struct cli_args * cli;
     
    F_quiet_mode = 1;
    
    cli = cli_args_new();
    cli_args_verbose(cli, opt_V);
    
    /* with, or without ENABLE_CRYPTO_LAYER */
#   define NUM_ARGS 6

#ifndef USE_AF_INET
#   undef  NUM_ARGS
#   define NUM_ARGS 4
#endif
 

#ifndef ENABLE_SAVE_TESTS
    if (argc - optind != NUM_ARGS) {
      if(!((argc - optind == NUM_ARGS - 2) && opt_m))
      {
       display_help(myself);
       exit(0);
       }
    }
#else
 if(list_sessions || opt_m || list_plugins || list_prefs)
  {
  if (argc - optind != NUM_ARGS - 2) {
      fprintf(stderr, "list-sessions only requires " BATCH_USAGE "\n");
      exit(1);
    }
  }
  else if(restore_session)
  {
    if (argc - optind != NUM_ARGS - 1) {
      fprintf(stderr, "restore-session only requires " BATCH_USAGE " <result-file>\n");
      exit(1);
    }
  }
  else
  if (argc - optind != NUM_ARGS) {
      display_help(myself);
      exit(0);
    }

   
#endif    
    

    /* next arguments: SERVER PORT */
#ifdef USE_AF_INET
    cli_args_server(cli, argv[inc_optind()]);
    cli_args_port(cli, atoi(argv[inc_optind()]));
#else
    cli_args_server(cli, "localhost");
    cli_args_port(cli, 0);
#endif

    /* next argument: LOGIN */
    arg = argv[inc_optind()];
    cli_args_login(cli, arg);
    bzero(arg, strlen(arg));

   
    /* next argument: PASSWORD */
    arg = argv[inc_optind()];
    cli_args_password(cli, arg);
    bzero(arg, strlen(arg));

    if(list_prefs)
    {
     First_time = 0;
     if(cli_connect_to_openvasd(cli) < 0)
     {
      fprintf(stderr, "Could not connect to openvasd\n");
      exit(1);
     }
    if(sqlize_output)
    	cli_sql_dump_prefs(cli);
    else
    	cli_dump_prefs(cli);
    cli_close_connection(cli);
    exit(0);
    }
    if(list_plugins)
    {
     First_time = 0;
     if(cli_connect_to_openvasd(cli) < 0)
      {
       fprintf(stderr, "Could not connect to openvasd\n");
       exit(1);
       }
      if(sqlize_output)
        cli_sql_dump_plugins(cli);
      else 
      	cli_dump_plugins(cli);
	
      cli_close_connection(cli);
      exit(0);
    }
    
    

   if(!opt_m)
   {
   if(restore_session)
   {
     cli_args_results(cli,  argv[inc_optind()]);
   }
   else
    if(!list_sessions)
     {
      char * t = argv[inc_optind()];
      if(t)cli_args_target(cli, t);
      else {
	      fprintf(stderr, "Missing parameter\n");
	      display_help(myself);
      }
      t = argv[inc_optind()];
      if(t) cli_args_results(cli,  t);
      else {
	      fprintf(stderr, "Missing parameter\n");
	      display_help(myself);
      }
     }
   }
   
    cli_args_output(cli, output_type);
    
    
    /* login now */
    if((cli_connect_to_openvasd(cli))<0)
	nessus_exit(1);
#ifdef ENABLE_SAVE_TESTS
    if(list_sessions){
    	cli_list_sessions(cli);
#ifdef NESSUS_ON_SSL
	close_stream_connection(GlobalSocket);
#else
	shutdown(GlobalSocket,2);
	closesocket(GlobalSocket);
#endif
	GlobalSocket = -1;
	nessus_exit(0);
	}
    else if(restore_session) {
    	cli_restore_session(cli, session_id);
	}
   else	
#endif    	
    if(opt_m){
    	if(!preferences_generate_new_file())
	 printf("A new nessusrc file has been saved\n");
	}
    else
     {
     cli_test_network(cli);
     cli_report(cli);
    }
    /* end, exit */
    nessus_exit(0);
  }
 
  F_openvasd_running = 0;
  
  /*
   * Set up the main window
   */

#if 0
  paranoia_level = arg_get_value(Prefs, "paranoia_level");
  if (paranoia_level == 0)
   
    {
        paranoia_level = sslui_ask_paranoia_level();
	if(paranoia_level > 0)
 	 arg_add_value(Prefs, "paranoia_level", ARG_INT, -1, (void*)paranoia_level);
    }
#endif    
  printf("\nOoops ...\n\
  This nessus version has no gui support.  You need to give nessus the\n\
  arguments SERVER PORT LOGIN TRG RESULT as explained in more detail\n\
  using the --help option.\n");
  exit (1);
}

#ifdef NESSUSNT
int WINAPI WinMain(HINSTANCE hThisInst, HINSTANCE hPrevInst,
    		   LPSTR lpszArgs, int nWinMode)
{
/*
 * Initialize WinSock and jump into the regular 'main'
 */
  WSADATA winSockData;
  WSAStartup(0x0101, &winSockData);
  main(__argc, __argv);
  WSACleanup();
  return 0;
}
 
#endif
