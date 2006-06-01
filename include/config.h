/* OpenVAS
* $Id$
* Description: header that provides general configuration settings.
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


 
/*
 * GENERAL CONFIGURATION
 */

 
/* 
 * Socket type
 *
 * OpenVAS can handle two types of socket : AF_INET and AF_UNIX
 *
 * The AF_INET type allow the server and the client to be on
 * different computers, but may create security problems (until
 * someone volunteers to made the encryption)
 *
 * The AF_UNIX type is more secure, but the server and the
 * client have to be on the same computer (this is what is used
 * by default if you don't define 'USE_AF_INET'), and must
 * be launched by the same user (read : same uid)
 */
 
/* #undef USE_AF_UNIX */
/* #undef AF_UNIX_PATH */

#ifndef USE_AF_UNIX
#define USE_AF_INET
#else
/* #undef OPENVAS_ON_SSL */
#endif

/* AF_UNIX socket path (if you want to use AF_UNIX sockets) */
#ifndef USE_AF_INET
#ifndef AF_UNIX_PATH
#define AF_UNIX_PATH "/var/run/openvas/openvas.sock"
#endif
#endif /* not def USE_AF_INET */


/*
 * define this if you want to see some useful debug
 * messages comming from OpenVAS
 */
/* #undef DEBUG */

/* more paricular debuging flags */
/* #undef DEBUGMORE */
/* #undef ENABLE_PID_STAMP_DEBUGGING */

/*
 * OPENVASD SPECIFIC CONFIGURATION
 */


/* miscellaneous */
#define OPENVASD_LANGUAGE "english"
#define OPENVASD_LOGS     OPENVASD_LOGDIR
#define OPENVASD_LOGINS   OPENVASD_STATEDIR "/users"
#define OPENVASD_JOBS	OPENVASD_STATEDIR  "/jobs"
#define OPENVASD_CERTS	OPENVASD_STATEDIR "/certs"

#define OPENVASD_CA	OPENVASD_SHAREDSTATEDIR "/CA"




/* derived entries */
#define OPENVASD_CONF     OPENVASD_CONFDIR  "/openvas/openvasd.conf"

#define OPENVASD_MESSAGES OPENVASD_LOGS "/openvasd.messages"
#define OPENVASD_DEBUGMSG OPENVASD_LOGS "/openvasd.dump"


#define OPENVASD_DATAPOOL OPENVASD_STATEDIR "-datapool"
#define OPENVASD_RULES    OPENVASD_DATADIR  "/openvasd.rules"
#define OPENVASD_USERS    OPENVASD_DATADIR  "/openvasd.users"



/* Definitions for client/server ecryption, activated on the C compiler
   command line as given by the command `openvas-config --cflags` */
#ifdef ENABLE_CRYPTO_LAYER

/* seconds the server waits for the client after authentication */
#define OPENVASD_NEGOT_TIMEOUT 600 

/* the files, keys are stored in */
#define OPENVASD_USERKEYS /* logindir */ "~/auth/openvasd.user-keys"
#define OPENVASD_USERPWDS OPENVASD_DATADIR "/openvasd.user-pwds"
#define OPENVASD_KEYFILE  OPENVASD_DATADIR "/openvasd.private-keys"

/* The default server key file and key length */
#define OPENVASD_KEYLENGTH    1024
#define OPENVASD_MAXPWDFAIL   5
#define OPENVASD_USERNAME     "openvasd"

/* The default rpc cipher openvasd will be connect to (if any) */
#define OPENVASD_RPCIPHER     "twofish/ripemd160"
#define OPENVASD_RPCAUTH_METH  3 /* auth scheme, either 1 or 3 */

/* The timeout secs when waiting for a log pipe to be established */
#define OPENVASD_LOGPIPE     OPENVASD_DATADIR  "/openvasd.logpipe"
#define OPENVASD_LOGPIPE_TMO 2

#endif /* ENABLE_CRYPTO_LAYER */

/* Obsolete: the port 3001 on which openvasd will be listening */
/* #undef DEFAULT_PORT */

/* The default port assigned to openvas by the iana is 1241, see
   http://www.isi.edu/in-notes/iana/assignments/port-numbers */
#define NESIANA_PORT 1241

/* The max number of client connections/sec */
#define OPENVASD_CONNECT_RATE 4

/* Block this many secs if the OPENVASD_CONNECT_RATE was exceeded */
#define OPENVASD_CONNECT_BLOCKER 2

/*
 * How much time before closing
 * the connection if nothing comes
 * from the client ? (in secs)
 */
#define CLIENT_TIMEOUT 300

/*
 * How much time before killing
 * a plugin ? (in secs)
 * (if you have a slow computer or a slow
 * network connection, set it to 320 or more)
 */
 
#define PLUGIN_TIMEOUT 320


/* 
 * Should we use applications for the remote harg stuff ?
 */
#ifdef ENABLE_RHLST
/* #undef ENABLE_RHLST_APPS */
#endif
/*
 * Shall the server log EVERYTHING ?
 */
 
/* #undef LOGMORE */

/*
 * Shall the server log the whole attack ?
 */
 
/* #undef LOG_WHOLE_ATTACK */

/*
 * Host specs.
 * 
 * Set this if you are running OpenBSD < 2.1 or all FreeBSD or
 * all netBSD, or BSDi < 3.0
 *
 * If you have run this script as root, then it should be correctly
 * set up
 *
 */
/* #undef BSD_BYTE_ORDERING */


/*
 * OPENVAS CLIENT SPECIFIC CONFIGURATION
 */
 
/*
 * Build the client with GTK?
 */
#define USE_GTK 1

/*
 * How long before closing the 
 * connection to the server if
 * it stays mute ?
 */
#define SERVER_TIMEOUT 800
 

/*
 * STOP ! Don't edit anything after this line !
 */
#ifndef _CYGWIN_
/* #undef _CYGWIN_ */
#endif

#define STDC_HEADERS 1
/* #undef HAVE_GMP_H */
/* #undef HAVE_GMP2_GMP_H */
#define HAVE_UNISTD_H 1
#define HAVE_ASSERT_H 1
/* #undef HAVE_FNMATCH */
#define HAVE_LSTAT 1
#define HAVE_MMAP 1
#define HAVE_ATEXIT 1
#define HAVE_BZERO 1
#define HAVE_BCOPY 1
#define HAVE_RAND 1
#define HAVE_POLL 1
/* #undef HAVE_RINT */
#define HAVE_SELECT 1
#define HAVE_SETSID 1
#define HAVE_WAITPID 1
#define HAVE_WAIT3 1
#define HAVE_WAIT4 1
#define HAVE_POLL_H 1
#define HAVE_GETTIMEOFDAY 1
/* #undef GETTIMEOFDAY_ONE_ARGUMENT */
#define HAVE_TIMEVAL 1
/* #undef HAVE_GETHRTIME */
#define HAVE_GETRUSAGE 1
#define HAVE_LONG_FILE_NAMES 1
#define HAVE_GETOPT_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_SYS_POLL_H 1
/* #undef HAVE_SYS_SOCKIO_H */
/* #undef HAVE_SYS_SOCKETIO_H */
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_NETDB_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_NET_IF_H 1
/* #undef HAVE_NETINET_TCPIP_H */
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_IN_SYSTM_H 1
/* #undef HAVE_NETINET_IP_UDP_H */
#define HAVE_NETINET_UDP_H 1
/* #undef HAVE_NETINET_PROTOCOLS_H */
#define HAVE_NETINET_IP_H 1
#define HAVE_NETINET_IP_ICMP_H 1
/* #undef HAVE_NETINET_IP_TCP_H */
/* #undef HAVE_NETINET_PROTOCOLS_H */
#define HAVE_DL_LIB 1
/* #undef HAVE_SHL_LOAD */
/* #undef HAVE_NSCREATEOBJECTFILEIMAGEFROMFILE */
#define HAVE_VSNPRINTF 1
#define HAVE_MKSTEMP 1
#define HAVE_SETJMP_H 1
#define HAVE_STRUCT_IP 1
#define HAVE_STRUCT_ICMP 1
#define HAVE_STRUCT_TCPHDR 1
#define HAVE_TCPHDR_TH_OFF 1
/* #undef HAVE_TCPHDR_TH_X2_OFF */
#define HAVE_STRUCT_UDPHDR 1
#define HAVE_BSD_STRUCT_UDPHDR 1
/* #undef HAVE_ICMP_ICMP_LIFETIME */
#define HAVE_SYS_WAIT_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_LIMITS_H 1
#define HAVE_VALUES_H 1
/* #undef HAVE_STAT_H */
#define TIME_WITH_SYS_TIME 1
/* #undef HAVE_SYS_TIME_H */
#define HAVE_SYS_IOCTL_H 1
#define HAVE_DIRENT_H 1
/* #undef HAVE_SYS_NDIR_H */
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_NDIR_H */
/* #undef HAVE_DL_H */
#define HAVE_STRCHR 1
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE 1
#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H 1
/* #undef HAVE_PTHREAD_H */
/* #undef HAVE_PTHREAD_CANCEL */
#define HAVE_DLFCN_H 1
#define HAVE_FCNTL_H 1
#define HAVE_RPC_RPC_H 1
/* #undef WORDS_BIGENDIAN */
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 4
#define HAVE_MEMORY_H 1
/* #undef HAVE_ADDR2ASCII */
/* #undef HAVE_INET_NETA */
#define HAVE_SYS_UN_H 1
#define HAVE_CTYPE_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_ERRNO_H 1
#define HAVE_PWD_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STDIO_H 1
/* #undef HAVE_SYS_FILIO_H */
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_XDR_MON 1
/* #undef HAVE_SOCKADDR_SA_LEN */
#define HAVE_SGTTY_H 1
#define HAVE_TERMIO_H 1
#define HAVE_TERMIOS_H 1
/* #undef HAVE_LIBUTIL_H */
/* #undef HAVE_DB1_DB_H */
/* #undef HAVE_DB_H */
/* #undef HAVE_SETPROCTITLE */
#define HAVE__EXIT 1

#define HAVE_PTY_H 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_SIGNAL_H 1
#define HAVE_PWD_H 1
#define HAVE_SETJMP_H 1
#define LINUX 1
/* #undef FREEBSD */
/* #undef OPENBSD */
/* #undef SOLARIS */
/* #undef SUNOS */
/* #undef BSDI */
/* #undef IRIX */
/* #undef NETBSD */


#define HAVE_INET_ATON 1
/* #undef STUPID_SOLARIS_CHECKSUM_BUG */
/* #undef HAVE_STRUCT_IP_CSUM */
/* #undef HAVE_GETHOSTBYNAME_R */
/* #undef HAVE_SOLARIS_GETHOSTBYNAME_R */
/* #undef HAVE_SOLARIS_GETHOSTBYADDR_R */
#define HAVE_SIGNAL_SA_RESTORER 1
#define USE_SYSLOG 1
/* #undef USE_ZLIB_COMPRESSION */


#define GTK_VERSION 26
/* #undef BROKEN_PTHREAD_CLEANUP_PUSH */

#define HAVE_REGEX_SUPPORT 1
/*
 * Experimental features 
 */
#define ENABLE_SAVE_TESTS 1
#define ENABLE_SAVE_KB 1
/* 
 * Local Variables:
 * mode: c
 * Emd:
 */
