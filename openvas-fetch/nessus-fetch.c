/*
 * Nessus-Fetch
 *
 * (C) Tenable Network Security
 * (C) Tim Brown
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
 * 
 *
 *
 * nessus-fetch is a simple utility to retrieve Nessus plugins from nessus.org
 * $Id$
 */
#include <includes.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define MAX_SIZE (40*1024*1024)


#define WWW_OPENVAS_ORG "www.openvas.org"
#define PLUGINS_OPENVAS_ORG "plugins.openvas.org" 

#define SOCKET_TIMEOUT 90

#define ERROR_PREFIX "@ERROR@:"
#define SUCCESS_MSG  "@SUCCESS@"
#define CONFIG_FILE "nessus-fetch.rc"

#define SEGSIZE 1024

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif



static int unblock_socket(int soc)
{
  int   flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
{
      perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, O_NONBLOCK | flags) < 0)
    {
      perror("fcntl(F_SETFL,O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static int block_socket(int soc)
{
  int   flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
    {
      perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, (~O_NONBLOCK) & flags) < 0)
    {
      perror("fcntl(F_SETFL,~O_NONBLOCK)");
      return -1;
    }
  return 0;
}

int http_recv_headers(int soc, char ** result, int * len)
{
 char tmp[2048];
 int sz = 4096;
 int n;
 char * buf;
 int lines = 0;
 int num = 0;
 
 *result = NULL;
 *len = 0;
 
 buf = emalloc(sz);
 tmp[ sizeof(tmp) - 1 ] = '\0';

  for(;;)
  {
   n = recv_line(soc, tmp, sizeof(tmp) - 1);
   lines ++;
   if( n <= 0 )break;
   
   if(!strcmp(tmp, "\r\n")||
      !strcmp(tmp, "\n"))break;
   else 
   {
     num  += n;
     if(num < sz)
      strcat(buf, tmp);
     else
     {
      if(sz > 1024 * 1024)
       break;
      else
       sz = (sz * 2) > ( num + 1 ) ? (sz * 2) : (num + 1);
	
      buf = erealloc(buf, sz);
      strcat(buf, tmp);
      if(lines > 100)break;
     }
  }
 }
 
 if(num == 0)
 {
  efree(&buf);
 }
 
 *result = buf;
 *len = num;
 return 0;
}



/*-------------------------------------------------------------------------
 *
 * Taken from ssltunnel, (C) Alain Thivillon and Hervé Schauer Consultants
 *
 *------------------------------------------------------------------------*/
static int ssl_connect_timeout(SSL *ssl, int tmo)
{

  int r=0;
  int rfd, wfd;
  int n,maxfd;
  fd_set rfds, wfds;
  fd_set *prfds;
  struct timeval tv;
  long end;
  int t;
  int errcode;

  rfd = SSL_get_fd(ssl);
  wfd = SSL_get_fd(ssl);
  n = rfd + 1;
  maxfd = (rfd > wfd ? rfd : wfd) + 1;

  prfds = (fd_set *) NULL;
  end = tmo + time( NULL );

  tv.tv_sec = tmo;
  tv.tv_usec = 0;

  FD_ZERO(&wfds);
  FD_SET(wfd,&wfds);

  /* number of descriptors that changes status */
  while (0 < (n = select(n,prfds,&wfds,(fd_set *) 0,&tv)))
  {
    r = SSL_connect(ssl);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    if (r > 0) {
      return r;
    }

    switch (errcode=SSL_get_error(ssl, r))
    {
    case SSL_ERROR_WANT_READ:
      prfds = &rfds;
      FD_ZERO(&rfds);
      FD_SET(rfd,&rfds);
      n = maxfd;
      break;
    case SSL_ERROR_WANT_WRITE:
      prfds = (fd_set *) 0;
      n = wfd + 1;
      break;
    default:
      /* some other error */
      switch (errcode) {
        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
           fprintf(stderr,"ssl_connect : %d", SSL_get_error(ssl, r));
           break;
        default:
           fprintf(stderr,"ssl_connect : %d", SSL_get_error(ssl, r));
           break;
      }
      return -2;
    }

    if ((t = end - time( NULL )) < 0) break;

    tv.tv_sec = t;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(rfd,&rfds);
  }

  return -1;

}

/*--------------------- BASE64 encoding ------------------------------------*/
static void base64_init(void);

static int base64_initialized = 0;
#define BASE64_VALUE_SZ 256
#define BASE64_RESULT_SZ 8192
int base64_value[BASE64_VALUE_SZ];
const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static void
base64_init(void)
{
    int i;

    for (i = 0; i < BASE64_VALUE_SZ; i++)
        base64_value[i] = -1;

    for (i = 0; i < 64; i++)
        base64_value[(int) base64_code[i]] = i;
    base64_value['='] = 0;

    base64_initialized = 1;
}


/* adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments */
const char *
base64_encode(const char *decoded_str)
{
    static char result[BASE64_RESULT_SZ];
    int bits = 0;
    int char_count = 0;
    int out_cnt = 0;
    int c;

    if (!decoded_str)
        return decoded_str;

    if (!base64_initialized)
        base64_init();

    while ((c = (unsigned char) *decoded_str++) && out_cnt < sizeof(result) - 5) {
        bits += c;
        char_count++;
        if (char_count == 3) {
            result[out_cnt++] = base64_code[bits >> 18];
            result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = base64_code[bits & 0x3f];
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 8;
        }
    }
    if (char_count != 0) {
        bits <<= 16 - (8 * char_count);
        result[out_cnt++] = base64_code[bits >> 18];
        result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
        if (char_count == 1) {
            result[out_cnt++] = '=';
            result[out_cnt++] = '=';
        } else {
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = '=';
        }
    }
    result[out_cnt] = '\0';     /* terminate */
    return result;
}


/*--------- Preferences Management -----------------------------------------*/
struct preferences {
	char * login;
	char * password;
	char * proxy;
	char * proxy_port;
	char * proxy_username;
	char * proxy_password;
};

int proxy_connect_method(char * hostname, int port, struct preferences * prefs, struct arglist * hostinfo);
	

static void save_preferences( struct preferences * prefs )
{
 FILE *fp;
 char path[1024];

 snprintf(path, sizeof(path), "%s/nessus/%s", NESSUSD_CONFDIR, CONFIG_FILE);
 fp = fopen(path, "w");
 if ( fp == NULL )
 {
  fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
  exit(1);
 }

 fprintf(fp, "login=%s\npassword=%s\nproxy=%s\nproxy_port=%s\nproxy_username=%s\nproxy_password=%s\n", 
		prefs->login ? prefs->login:"",
		prefs->password ? prefs->password:"",
		prefs->proxy ? prefs->proxy : "",
		prefs->proxy_port ? prefs->proxy_port:"",
		prefs->proxy_username ? prefs->proxy_username:"",
		prefs->proxy_password ? prefs->proxy_password : "");


 fclose(fp);
 chmod(path, 0600);
}

static char * shift_pref(char * ptr, char * name )
{
 if ( strlen(ptr) <= strlen(name) ) 
	return NULL;
 ptr += strlen(name);
 return estrdup(ptr);
}


static int load_preferences( struct preferences * prefs )
{
 FILE *fp;
 char path[1024];
 char buf[1024];

 bzero(prefs, sizeof(*prefs));

 snprintf(path, sizeof(path), "%s/nessus/%s", NESSUSD_CONFDIR, CONFIG_FILE);
 fp = fopen(path, "r");
 if ( fp == NULL )
  return -1;

 buf[sizeof(buf) - 1 ] = '\0';
 while ( fgets(buf, sizeof(buf) - 1, fp ) != NULL )
 {
 if ( buf[0] == '\0' ) return -1;
 buf[strlen(buf) - 1] = '\0';
 if ( strncmp(buf, "login=", strlen("login=") ) == 0 )
 	prefs->login = shift_pref(buf, "login=");

 else if ( strncmp(buf, "password=", strlen("password=") ) == 0 )
 	prefs->password = shift_pref(buf, "password=");

 else if ( strncmp(buf, "proxy=", strlen("proxy=") ) == 0 )
 	prefs->proxy = shift_pref(buf, "proxy=");

 else if ( strncmp(buf, "proxy_port=", strlen("proxy_port=") ) == 0 )
 	prefs->proxy_port = shift_pref(buf, "proxy_port=");

 else if ( strncmp(buf, "proxy_username=", strlen("proxy_username=") ) == 0 )
 	prefs->proxy_username = shift_pref(buf, "proxy_username=");

 else if ( strncmp(buf, "proxy_password=", strlen("proxy_password=") ) == 0 )
 	prefs->proxy_password = shift_pref(buf, "proxy_password=");
 }

 fclose(fp);
 return 0;
}




/*------------------------- HTTP FUNCTIONS ----------------------------------*/
static int extract_content_length(char * headers)
{
 char * str;
 str = strstr(headers, "\nContent-Length: ");
 if( str != NULL )
 {
  str += strlen("\nContent-Length: ");
  return atoi(str);
 }
 
 return -1;
}

static int chunked_encoding(char * headers)
{
 if(strstr(headers, "Transfer-Encoding: chunked") != NULL )
  return 1;
 else 
  return 0;
}


static int recv_chunked_encoding(int fd, char * headers, int hlen, char ** buf, int * len)
{
 int total_len, sz = hlen;
 char tmp[2048];
 char * mybuf = emalloc(hlen);
 

 memcpy(mybuf, headers, hlen);
 for(;;)
 { 
  int n;
  char * end;
  tmp[sizeof(tmp) - 1] = '\0';
  n = recv_line(fd, tmp, sizeof(tmp) - 1);
  if (n <= 0) break;
  total_len = strtol(tmp, &end, 16);
  
  mybuf = erealloc(mybuf, sz + total_len + 2);
  n = 0;
  do {
  int e = 0;
  int l;
  l = total_len + 2 - n > SEGSIZE ? SEGSIZE : total_len + 2 - n;
  e = read_stream_connection_min(fd, mybuf + sz + n, l, 1 );
  if ( e <= 0 ) break;
  n += e;
  } while ( n != total_len + 2);
  
  if( n <= 0 || total_len == 0 || sz > MAX_SIZE)
   {
   if( sz > MAX_SIZE ){
	close_stream_connection ( fd );
	fd = -1;
	}
   break;
   }
    sz += total_len + 2;
  }
  
   *len = sz;
   *buf = mybuf;
   return 0;
}


static char * http_recv(int fd, int * totlen, int * headerslen, int * error_code)
{
 char * headers;
 int headers_len;
 
 *totlen = 0;
 http_recv_headers(fd, &headers, &headers_len);
	
 if(headers_len <= 0 || headers == NULL )
 	return NULL;

 *error_code = atoi(headers + strlen("HTTP/1.1 "));
 if ( *error_code != 200 )
	return NULL;

 *headerslen = headers_len;

 if( headers != NULL  )
 {
  int len = extract_content_length(headers);
  
  if ( len >= 0  )
  {
   char * retbuf;
   int n = 0;
   
   /* Do not allow a too long response. */
   if( len > MAX_SIZE )
    len = MAX_SIZE;
   
   retbuf = emalloc(headers_len + len + 1);
   memcpy(retbuf, headers, headers_len);
   while ( n != len )
   {
   int e;
   int readsz;

   readsz = (len - n)  > SEGSIZE ? SEGSIZE : (len - n);
   e = read_stream_connection_min(fd, retbuf + headers_len + n, readsz, 1);
   if ( e <= 0 ) break;
   else n += e;
  }
   *totlen = len + headers_len;
   efree(&headers);
   retbuf[*totlen] = '\0';
   return retbuf;
  }
  else if (chunked_encoding(headers))
  {
   char * ret_buf;
   int len;

   recv_chunked_encoding(fd, headers, headers_len, &ret_buf, &len);
   *totlen = len;
   efree(&headers);
   ret_buf[len] = '\0';
   return ret_buf;
  }
  else
  {
   int len = headers_len;
   int bufsz = len + SEGSIZE * 5;
   char * buf = emalloc( bufsz );
   int n;
   
   memcpy(buf, headers, headers_len);
   for (n = 0;; )
   {
   int e;
   e = read_stream_connection_min(fd, buf + headers_len + n, SEGSIZE, 1 );
   if ( e <= 0 ) break;
   else { len += e; n += e; }

   if ( len + SEGSIZE >= bufsz )
	{
	 if ( bufsz > MAX_SIZE ) break;
	 bufsz *= 2;
	 buf = erealloc ( buf, bufsz );
	}
   } 

   *totlen = len;
   efree(&headers);
   buf[len] = '\0';
   return buf;
  }
 }
 else return NULL;
}


char * mk_http_req(const char * hostname, char * path, char * httpuser, char * httppass)
{
  char * str = emalloc ( strlen(hostname) + strlen(path) + 1024 );
  struct preferences prefs;
  char proxy_auth[1024];
  char auth[1024];

  load_preferences(&prefs);

  if ( prefs.proxy_username && prefs.proxy_password )
	{
	char buf[1024];
	const char * base64;
	snprintf ( buf, sizeof(buf), "%s:%s", prefs.proxy_username, prefs.proxy_password);
	base64 = base64_encode(buf);
	snprintf(proxy_auth, sizeof(proxy_auth), "Proxy-Authorization: Basic %s\r\n", base64);
	}
  else proxy_auth[0] = '\0';

 if ( httpuser && httppass )
 {
  char buf[1024];
  const char * base64;
  snprintf ( buf, sizeof(buf), "%s:%s", httpuser, httppass);
  base64 = base64_encode(buf);
  snprintf(auth, sizeof(auth), "Authorization: Basic %s\r\n", base64);
 }
 else auth[0] = '\0';


  sprintf(str, "GET %s HTTP/1.1\r\n\
Connection: Close\r\n\
Host: %s\r\n\
Pragma: no-cache\r\n\
User-Agent: Nessus-Fetch/%s\r\n\
%s%sAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n\
Accept-Language: en\r\n\
Accept-Charset: iso-8859-1,*,utf-8\r\n\r\n",
                path, hostname, nessuslib_version(), proxy_auth[0] ? proxy_auth:"", auth[0] ? auth:"");

  return str;
}

/*---------------------------------------------------------------------------*/
static struct arglist * mkhostinfo(char * hostname)
{
 struct arglist * ret = emalloc( sizeof(*ret) );
 struct arglist * hn  = emalloc( sizeof(*hn ) );
 struct in_addr ia;
 struct in_addr * iap;
 char * proxy = NULL;

 struct preferences prefs;

 load_preferences(&prefs);

 arg_add_value ( ret, "HOSTNAME", ARG_ARGLIST, -1, hn);
 arg_add_value ( hn , "NAME", ARG_STRING, -1, estrdup(hostname));

 if ( prefs.proxy != NULL )
 {
  proxy = prefs.proxy;
  if ( strncmp(proxy, "https://", strlen("https://")) == 0 ) proxy += strlen("https://");
 }
	
 ia = nn_resolve( proxy ? proxy : hostname);
 if ( ia.s_addr == INADDR_NONE )
 {
  fprintf(stderr, "Could not resolve %s\n", hostname);
  exit(1);
 }

 iap = emalloc ( sizeof(struct in_addr));
 iap->s_addr = ia.s_addr;
 arg_add_value(hn, "IP", ARG_PTR, -1, iap);
 return ret;
}


/*--------------------- Register a user -------------------------------------*/
static void update_plugins(int argc, char ** argv)
{
 char * ptr;
 char path[1024];
 char * my_argv[] = { "nessus-update-plugins", NULL };
 pid_t pid;
 int e;

 printf("Now fetching the newest plugin set from %s...\n", PLUGINS_OPENVAS_ORG);

 ptr = find_in_path("nessus-update-plugins", 0);
 if ( ptr == NULL )
 {
  strncpy(path, argv[0], sizeof(path) - strlen("nessus-update-plugins") );
  path[sizeof(path) - strlen("nessus-update-plugins") ] = '\0';
  if ( path[0] == '/' ) 
	{
	 ptr = strstr(path, "/bin/");
	 if ( ptr != NULL )
         {
	  ptr[0] = '\0';
	  strncat(path, "/sbin/nessus-update-plugins", sizeof(path) - strlen(path) - 1);
	  path[sizeof(path) - 1] = '\0';
	  ptr = &(path[0]);
         }
	}
  else ptr = NULL;
 }
 else 
  {
  snprintf(path, sizeof(path), "%s/nessus-update-plugins", ptr);
  ptr = &(path[0]);
  }

 if ( ptr == NULL )
 {
  fprintf(stderr, "nessus-update-plugins could not be found in your $PATH\n");
  exit(1);
 }
 pid = fork();
 if ( pid == 0 )
 {
  if ( execv(ptr, my_argv) < 0 ) 
   fprintf(stderr, "Could not execute %s - %s\n", ptr, strerror(errno));
  exit(0);
 }
 else if ( pid < 0 ) {
	fprintf(stderr, "fork() failed (%s)\n", strerror(errno));
	exit(1);
	}
 
 do {
	errno = 0;
	e = waitpid(pid, NULL, 0);
    } while ( e < 0 && errno == EINTR );

 
 printf("Your Nessus installation is now up-to-date.\nMake sure to call regularly use the command 'nessus-update-plugins' to stay up-to-date\n");
 printf("To automate the update process, please visit <http://www.nessus.org/documentation/index.php?doc=cron>\n");
 printf("\n");
 
 exit(0);
}


static int do_register( char * serial, int argc, char ** argv )
{
 char * req, * result;
 char str[1024];
 struct arglist * hostinfo;
 int soc, len, hlen;
 int code;
 struct preferences prefs;


 load_preferences(&prefs);
 
 hostinfo = mkhostinfo(PLUGINS_OPENVAS_ORG);
 if ( prefs.proxy != NULL )
  snprintf(str, sizeof(str), "https://%s/register.php?serial=%s", PLUGINS_OPENVAS_ORG, serial);
 else
  snprintf(str, sizeof(str), "/register.php?serial=%s", serial);

 req = mk_http_req(plug_get_hostname(hostinfo), str, NULL, NULL);
 if ( prefs.proxy && prefs.proxy_port )
  soc = proxy_connect_method(PLUGINS_OPENVAS_ORG, HTTPS_PORT, &prefs, hostinfo);
 else
  soc = open_stream_connection(hostinfo, HTTPS_PORT, NESSUS_ENCAPS_TLSv1,  SOCKET_TIMEOUT);

 if ( soc < 0 ) 
 {
  fprintf(stderr, "could not connect to %s - %s\n", plug_get_hostname(hostinfo), strerror(errno));
  exit(1);
 } 
 stream_set_buffer(soc, 65535);

 write_stream_connection(soc, req, strlen(req));
   
 result = http_recv( soc, &len, &hlen, &code);
 if ( result == NULL )
 {
  fprintf(stderr, "Unknown error while decoding HTTP response (http error code = %d)\n", code);
  exit(1);
 }

 result += hlen;
 if ( strncmp(result, "SUCCESS", strlen("SUCCESS")) == 0 )
 {
  /* parse the result here */
  char * t, * e;
  char * username, * password;
  t = strchr(result, '\n');
  if ( t == NULL) goto error;
  t ++;
  e = strchr(t, '\n');
  if ( e == NULL ) goto error;
  e[0] = '\0';
  username = estrdup(t);
  t = e + 1;
  e = strchr(t, '\n');
  if ( e == NULL ) goto error;
  e[0] = '\0';
  password = estrdup(t);
   
  prefs.login = username;
  prefs.password = password;
  save_preferences(&prefs);
  printf("Your activation code has been registered properly - thank you.\n");
  update_plugins(argc, argv);
  exit(0);
 }
 else if ( strncmp(result, "EEXIST", strlen("EEXIST")) == 0 )
  fprintf(stderr, "The provided activation code (%s) has already been used.\n", serial);
 else 
 if ( strncmp(result, "ERROR", strlen("ERROR")) == 0 )
  fprintf(stderr, "The provided activation code (%s) was refused by the remote server\n", serial);
 else printf("%s\n", result);

  exit(1);
error:
  fprintf(stderr, "An unknown error occured while submitting the activation code\n");
  exit(1);
}


int proxy_connect_method(char * hostname, int port, struct preferences * prefs, struct arglist * hostinfo)
{
 char buf[1024];
 const char * base64;
 char proxy_auth[256];
 static SSL_CTX        *ssl_ctx = NULL;
 static SSL_METHOD     *ssl_mt = NULL;
 SSL           *ssl = NULL;
 int n;
 int fd, soc;


	if ( prefs->proxy_username != NULL && prefs->proxy_password != NULL )
	{
	snprintf ( buf, sizeof(buf), "%s:%s", prefs->proxy_username, prefs->proxy_password);
	base64 = base64_encode(buf);
	snprintf(proxy_auth, sizeof(proxy_auth), "Proxy-Authorization: Basic %s\r\n", base64);
	}
	else proxy_auth[0] = '\0';

  	soc = open_stream_connection ( hostinfo, atoi(prefs->proxy_port), NESSUS_ENCAPS_IP, SOCKET_TIMEOUT );
       fd = nessus_get_socket_from_connection(soc); 
	snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\nUser-Agent: Mozilla/4.73 (Win95;I)\r\n%s\r\n", hostname, port, proxy_auth);
	write_stream_connection ( soc, buf, strlen(buf) );
	n = read_stream_connection(soc, buf, sizeof(buf) - 1);
	if ( n < 0 || strstr(buf, " 200 " ) == NULL || strstr(buf, "\r\n\r\n") == NULL )
		{
		fprintf(stderr, "The remote proxy does not support CONNECT statements - %s\n", buf);
		exit(1);
		}
	
	
	ssl_mt = TLSv1_client_method();
	if ( ssl_mt == NULL )
		{
		 fprintf(stderr, "TLSv1_client_method() failed\n");
		 exit(1);
		}
	

	ssl_ctx = SSL_CTX_new(ssl_mt);
	if ( ssl_ctx == NULL )
		{
	 	 fprintf(stderr, "SSL_CTX_new() failed\n");
		 exit(1);
		}

	   if (SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL) < 0)
       		{
		 fprintf(stderr, "SSL_CTX_set_options() failed\n");
		 exit(1);
		} 

	if ( ( ssl = SSL_new(ssl_ctx) )  == NULL )
		{
		 fprintf(stderr, "SSL_new() failed\n");
		 exit(1);
		}

	
 	SSL_set_fd(ssl, fd);
	SSL_set_connect_state(ssl);
  
        unblock_socket(fd);
      if (ssl_connect_timeout(ssl, SOCKET_TIMEOUT) <= 0)
        {
          fprintf(stderr, "SSL_connect failed\n");
          exit (1);
        }
	block_socket(fd);

  return nessus_register_connection(fd, ssl);
}

/*-------------------------------------------------------------------------*/
void fetch_file(int encaps, int port, char * hostname, char * path, char * filename, char * httpuser, char * httppass, char ** content)
{
 int fd;
 int soc;
 struct arglist * hostinfo;
 char * req, *result;
 int len, hlen;
 int n;
 int code;
 struct preferences prefs;
 int proxy = 0;

 if ( content != NULL ) 
	*content = NULL;

 load_preferences(&prefs);

 if ( prefs.proxy != NULL && prefs.proxy_port != NULL )
	proxy = 1;

 if ( filename != NULL )
 {
  fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0600);
  if ( fd < 0 ) 
  {
  fprintf(stderr, "Could not locally open %s - %s\n", filename, strerror(errno));
  exit(1);
  }
 }

 hostinfo = mkhostinfo( hostname );

 if ( prefs.proxy != NULL && prefs.proxy_port != NULL )
 {
  proxy = 1;
  if ( encaps != NESSUS_ENCAPS_IP )
	{
 	 soc = proxy_connect_method(hostname, port, &prefs, hostinfo);		
	 proxy = 0;
	}
  else 
	soc = open_stream_connection ( hostinfo, atoi(prefs.proxy_port), NESSUS_ENCAPS_IP, SOCKET_TIMEOUT );
 }
 else {
 if ( encaps > 0 )
  soc = open_stream_connection ( hostinfo, ( prefs.proxy && prefs.proxy_port ) ? atoi(prefs.proxy_port) : port, encaps, SOCKET_TIMEOUT );
 else
  soc = open_stream_connection ( hostinfo, ( prefs.proxy && prefs.proxy_port ) ? atoi(prefs.proxy_port) : port, NESSUS_ENCAPS_TLSv1, SOCKET_TIMEOUT );
 }


 if ( soc < 0 )
 {
  fprintf(stderr, "Could not open connection to %s - %s\n", plug_get_hostname(hostinfo), strerror(errno));
  exit(1);
 }
 stream_set_buffer(soc, 65535);

 if ( proxy != 0 )
 {
  char path2[1024];
  snprintf(path2, sizeof(path2), "http://%s%s", hostname, path);
  req = mk_http_req(plug_get_hostname(hostinfo), path2, httpuser, httppass);
 }
 else
  req = mk_http_req(plug_get_hostname(hostinfo), path, httpuser, httppass);

 write_stream_connection(soc, req, strlen(req));
   
 result = http_recv( soc, &len, &hlen, &code);
 if ( result == NULL )
 {
  fprintf(stderr, "An unknown HTTP error occured (http error code: %d)\n", code);
  unlink(filename);
  exit(1);
 }
 close_stream_connection(soc);
 if ( content != NULL )
	*content = result + hlen;

 if ( filename == NULL )
   return;

 for ( n = 0 ; n != (len - hlen ) ; )
 {
  int e;
  errno = 0;
  e = write ( fd, result + hlen + n, len - hlen - n );
  if ( e <= 0 )
  {
   if ( errno == EINTR ) continue;
   fprintf(stderr, "Could not write to %s - %s\n", filename, strerror(errno));
   unlink(filename);
   exit(1);
  }
  else n += e;
 }

 close(fd);
}



void check_subscription()
{
 int direct_feed = 0;
 char path[1024];
 struct preferences prefs;
 char * result;


 load_preferences(&prefs);
 
 if ( prefs.login != NULL && prefs.password != NULL )
  {
  direct_feed = 1;
  snprintf(path, sizeof(path), "/get.php?u=%s&p=%s&f=check", prefs.login, prefs.password);


  fetch_file(NESSUS_ENCAPS_TLSv1, HTTPS_PORT, PLUGINS_OPENVAS_ORG, path, NULL, NULL, NULL, &result);
  if ( result == NULL )
	{
	fprintf(stderr, "An unknown network error occured while checking the plugins subscription\n");
	exit(1);
	}
  if (strstr(result, SUCCESS_MSG) != NULL )
  {
   fprintf(stderr, "nessus-fetch is properly configured to receive a direct plugin feed\n");
   exit(0);
  }
  else if ( strstr(result, ERROR_PREFIX ) != NULL )
  {
   char * t = result + strlen(ERROR_PREFIX);
   fprintf(stderr, "An error occured: %s\n", t);
   exit(1);
  }
 }
 else {
   fprintf(stderr, "nessus-fetch is not configured to receive a direct plugin feed\n");
   exit(1);
   }
 
}

void fetch_plugins_file(char * filename)
{
 int direct_feed = 0;
 char path[1024];
 struct preferences prefs;


 load_preferences(&prefs);
 
 if ( prefs.login != NULL && prefs.password != NULL )
  {
  int fd;
  char buf[1024];
  direct_feed = 1;
  snprintf(path, sizeof(path), "/get.php?u=%s&p=%s&f=%s", prefs.login, prefs.password, filename);
  fetch_file(NESSUS_ENCAPS_TLSv1, HTTPS_PORT, PLUGINS_OPENVAS_ORG, path, filename, NULL, NULL, NULL);
  fd = open(filename, O_RDONLY);
  if ( fd < 0 ) {
	fprintf(stderr, "Could not open %s - %s\n", filename, strerror(errno));
	exit(1);
	}
  bzero(buf, sizeof ( buf ));
  read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if ( strncmp(buf, ERROR_PREFIX, strlen(ERROR_PREFIX)) == 0 )
	{
	fprintf(stderr, "An error occured while updating the plugins : %s\n", buf + strlen(ERROR_PREFIX));
	unlink(filename);
	exit(1);
	}
  }
 else
  {
  snprintf(path, sizeof(path), "/nasl/%s", filename);
  fetch_file(NESSUS_ENCAPS_IP, HTTP_PORT, WWW_OPENVAS_ORG, path, filename, NULL, NULL, NULL);
  }
}

/*---------------------------------------------------------------------------*/
static void usage()
{
   fprintf(stderr, "Usage: nessus-fetch --plugins\n");
   fprintf(stderr, "Usage: nessus-fetch --plugins-md5\n");
   fprintf(stderr, "Usage: nessus-fetch --register <serial>\n");
   fprintf(stderr, "Usage: nessus-fetch --check\n");
   fprintf(stderr, "Usage: nessus-fetch --url <url> <localfile> [<http_login> <http_password>]\n");
   exit(1);
}

int main(int argc, char ** argv)
{

 nessus_SSL_init(NULL);
 if ( argc == 3 && strcmp(argv[1], "--register") == 0 )
 {
  char * serial;

  if ( getuid() != 0 )
  {
   fprintf(stderr, "You need to be root to use the --register option\n");
   exit(1);
  }
  serial = argv[2];
  do_register(serial, argc, argv);  
  exit(1);
 }
 else if ( argc == 2 && strcmp(argv[1], "--plugins") == 0 )
 {
  fetch_plugins_file("all-2.0.tar.gz");
  fetch_plugins_file("all-2.0.sig");
 }
 else if ( argc == 2 && strcmp(argv[1], "--plugins-md5") == 0 )
 {
  fetch_plugins_file("all-2.0.tar.gz.md5");
 }
 else if ( argc == 2 && strcmp(argv[1], "--check") == 0 )
 {
  if ( getuid() != 0 )
  {
   fprintf(stderr, "You need to be root to use the --check option\n");
   exit(1);
  }
  check_subscription();
 }
 else if ( ( argc == 4 || argc == 6 ) && strcmp(argv[1], "--url") == 0 )
 {
  char * url = estrdup(argv[2]);
  char * hostname;
  char * filename = argv[3];
  char * t;
  int encaps;
  int port;
  char * login;
  char * password;

  if ( strncmp(url, "http://", strlen("http://") ) == 0 ) 
	{
	url += strlen("http://");
	encaps = NESSUS_ENCAPS_IP;
	port = HTTP_PORT;
	}
  else if ( strncmp(url, "https://", strlen("https://") ) == 0 ) 
	{
	url += strlen("https://");
 	encaps = 0;
	port = HTTPS_PORT;
	}
  else {
	fprintf(stderr, "Only http:// and https:// handlers are supported\n");
	exit(1);
	}

  if ( argc == 6 )
  {
   login = argv[4];
   password = argv[5];
  }
  else login = password = NULL;
  
  t = strchr(url, '/');
  if ( t == NULL ) exit(1);
  t[0] = '\0';
  hostname = estrdup ( url );
  t[0] = '/';
  url = t;
  fetch_file(encaps, port, hostname, url, filename, login, password, NULL);
 }
 else usage();
 
 return 0;
}
